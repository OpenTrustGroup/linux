// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2024 GoldenRiver Inc.

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/of_platform.h>

#include "nebula_rproc_remote.h"
#include "rpmsg.h"
#include "rpmsg_virtio.h"
#include "remoteproc_virtio.h"

#define VIRTIO_RPMSG_F_NS    0
#define RPMSG_VDEV_DFEATURES (1 << VIRTIO_RPMSG_F_NS)

/* Resource table entries */
#define NUM_VRINGS  0x02
#define VRING_ALIGN 0x1000
#define RING_TX	    0
#define RING_RX	    1
#define VRING_SIZE  256

struct rpmsg_device_descriptor {
	struct fw_rsc_vdev vdev;
	struct fw_rsc_vdev_vring vrings[NUM_VRINGS];
} __packed;

static const struct rpmsg_device_descriptor rpmsg_desc = {
	.vdev		= {
		.type		= RSC_VDEV,
		.id		= VIRTIO_ID_RPMSG,
		.dfeatures	= RPMSG_VDEV_DFEATURES,
		.config_len	= 0,
		.num_of_vrings	= NUM_VRINGS,
	},
	.vrings	= {
		[RING_TX]	= {
			.da		= FW_RSC_U32_ADDR_ANY,
			.align		= VRING_ALIGN,
			.num		= VRING_SIZE,
		},
		[RING_RX]	= {
			.da		= FW_RSC_U32_ADDR_ANY,
			.align		= VRING_ALIGN,
			.num		= VRING_SIZE,
		},
	},
};

#define MSG_COUNT 10
#define MSG_SIZE  64

struct rpmsg_device_priv {
	struct rpmsg_virtio_device rvdev;
	struct rpmsg_endpoint echo_ept;
	struct rpmsg_endpoint sink_ept;
};

static int sink_endpoint_cb(struct rpmsg_endpoint *ept, void *data, size_t len,
			    uint32_t src, void *priv)
{
	return RPMSG_SUCCESS;
}

static void sink_endpoint_unbind(struct rpmsg_endpoint *ept)
{
	struct rpmsg_device *rdev = ept->rdev;
	struct rpmsg_virtio_device *rvdev =
		container_of(rdev, struct rpmsg_virtio_device, rdev);
	struct rpmsg_device_priv *priv =
		container_of(rvdev, struct rpmsg_device_priv, rvdev);

	rpmsg_destroy_ept(&priv->sink_ept);
}

static int echo_endpoint_cb(struct rpmsg_endpoint *ept, void *data, size_t len,
			    uint32_t src, void *priv)
{
	/* Send data back to host */
	if (rpmsg_send(ept, data, len) < 0) {
		pr_err("rpmsg_send failed\r\n");
	}
	return RPMSG_SUCCESS;
}

static void echo_endpoint_unbind(struct rpmsg_endpoint *ept)
{
}

static void rproc_remote_ns_bind_cb(struct rpmsg_device *rdev, const char *name,
				    uint32_t dest)
{
	int ret;
	struct rpmsg_virtio_device *rvdev =
		container_of(rdev, struct rpmsg_virtio_device, rdev);
	struct rpmsg_device_priv *priv =
		container_of(rvdev, struct rpmsg_device_priv, rvdev);

	// frontend is expected to announce a service called "sink"
	const char expected[] = "sink";
	if (strncmp(expected, name, sizeof(expected)) == 0) {
		char msg[MSG_SIZE];
		int i;

		ret = rpmsg_create_ept(&priv->sink_ept, rdev, name,
				       RPMSG_ADDR_ANY, dest, sink_endpoint_cb,
				       sink_endpoint_unbind);
		if (ret != RPMSG_SUCCESS) {
			pr_err("failed to create ept, ret = %d\n", ret);
			return;
		}

		for (i = 0; i < MSG_COUNT; i++) {
			memset(msg, 0, sizeof(msg));
			snprintf(msg, MSG_SIZE, "hello from remote %d!", i);
			ret = rpmsg_trysend(&priv->sink_ept, msg, sizeof(msg));
			if (ret < 0) {
				pr_err("failed to send msg, ret = %d\n", ret);
				return;
			}
		}
	}
}

int rpmsg_device_create(struct virtio_device *vdev, struct metal_io_region *shm_io)
{
	int ret;
	int rpmsg_ret;
	struct rpmsg_device_priv *priv;

	priv = kzalloc(sizeof(struct rpmsg_device_priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	rpmsg_ret = rpmsg_init_vdev(&priv->rvdev, vdev, rproc_remote_ns_bind_cb,
				    shm_io, NULL);
	if (rpmsg_ret != RPMSG_SUCCESS) {
		pr_err("failed to init rpmsg device: %d\n", rpmsg_ret);
		ret = -EINVAL;
		goto err_free_priv;
	}

	// annonce a service called "echo" to frontend
	rpmsg_ret = rpmsg_create_ept(&priv->echo_ept, &priv->rvdev.rdev, "echo",
				     RPMSG_ADDR_ANY, RPMSG_ADDR_ANY,
				     echo_endpoint_cb, echo_endpoint_unbind);
	if (rpmsg_ret) {
		pr_err("failed to create rpmsg ept: %d\n", rpmsg_ret);
		ret = -EINVAL;
		goto err_deinit_rpmsg_vdev;
	}

	return 0;

err_deinit_rpmsg_vdev:
	rpmsg_deinit_vdev(&priv->rvdev);

err_free_priv:
	return ret;
}

void rpmsg_device_destroy(struct virtio_device *vdev)
{
	struct rpmsg_virtio_device *rvdev = vdev->priv;
	struct rpmsg_device_priv *priv =
		container_of(rvdev, struct rpmsg_device_priv, rvdev);

	rpmsg_deinit_vdev(rvdev);

	kfree(priv);
}

static void rpmsg_device_reset(struct virtio_device *vdev)
{
	pr_debug("rpmsg vdev reset\n");
}

static struct nebula_rproc_vdev_ops rpmsg_vdev_ops = {
	.on_create = rpmsg_device_create,
	.on_destroy = rpmsg_device_destroy,
	.on_reset = rpmsg_device_reset,
};

static int __init nebula_rpmsg_sample_init(void)
{
	nebula_rproc_register_device(&rpmsg_desc, sizeof(rpmsg_desc),
				     &rpmsg_vdev_ops);
	return 0;
}

module_init(nebula_rpmsg_sample_init);
MODULE_LICENSE("Dual BSD/GPL");