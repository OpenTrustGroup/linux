// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2024 GoldenRiver Inc.

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/of_platform.h>
#include <linux/spinlock.h>

#include "nebula_rproc_remote.h"
#include "rpmsg.h"
#include "rpmsg_virtio.h"
#include "remoteproc_virtio.h"

#define MAX_DEVICES             3
#define VIRTIO_RPMSG_F_NS       0
#define RPMSG_VDEV_DFEATURES    (1 << VIRTIO_RPMSG_F_NS)

// Resource table entries
#define NUM_VRINGS      0x02
#define VRING_ALIGN     0x1000
#define RING_TX         0
#define RING_RX         1
#define VRING_SIZE      256
#define MSG_COUNT       10
#define MSG_SIZE        64

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

struct rpmsg_devices_info {
	char* echo_name;
	char* sink_name;
	int host_vmid;
};

struct rpmsg_device_priv {
	struct rpmsg_virtio_device rvdev;
	struct rpmsg_endpoint echo_ept;
	struct rpmsg_endpoint sink_ept;
};

static struct rpmsg_devices_info rpmsg_test_devices[] = {
	{"echo-alps",  "sink-alps",   0},
	{"echo-tbox",  "sink-tbox",   1},
	{"echo-yocto", "sink-yocto", -1}
};

static int sink_endpoint_cb(struct rpmsg_endpoint *ept, void *data, size_t len,
			    uint32_t src, void *priv)
{
	return RPMSG_SUCCESS;
}

static void sink_endpoint_unbind(struct rpmsg_endpoint *ept)
{
}

static int echo_endpoint_cb(struct rpmsg_endpoint *ept, void *data, size_t len,
			    uint32_t src, void *t_priv)
{
	return rpmsg_send(ept, data, len);
}

static void echo_endpoint_unbind(struct rpmsg_endpoint *ept)
{
}

static void rproc_remote_ns_bind_cb(struct rpmsg_device *rdev, const char *name,
				    uint32_t dest)
{
	int ret, dev_cnt;
	struct rpmsg_virtio_device *rvdev =
			container_of(rdev, struct rpmsg_virtio_device, rdev);
	struct rpmsg_device_priv *priv =
			container_of(rvdev, struct rpmsg_device_priv, rvdev);

	/* frontend(host) is expected to announce a service called "sink". */
	for (dev_cnt = 0; dev_cnt < ARRAY_SIZE(rpmsg_test_devices); dev_cnt++) {
		char* expected = rpmsg_test_devices[dev_cnt].sink_name;
		if (strncmp(expected, name, strlen(expected)) == 0) {
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
				if (ret < 0) {
					pr_err("failed to snprintf hello rproc\n");
					return;
				}

				ret = rpmsg_trysend(&priv->sink_ept, msg, sizeof(msg));
				if (ret < 0) {
					pr_err("failed to send msg, ret = %d\n", ret);
					return;
				}
			}
		}
	}
}

int rpmsg_device_create(struct virtio_device *vdev, struct metal_io_region *shm_io,
					int vmid, void *user_priv)
{
	int rpmsg_ret;
	struct rpmsg_device_priv *priv;

	priv = kzalloc(sizeof(struct rpmsg_device_priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	rpmsg_ret = rpmsg_init_vdev(&priv->rvdev, vdev, rproc_remote_ns_bind_cb,
					shm_io, NULL);
	if (rpmsg_ret != RPMSG_SUCCESS) {
		pr_err("failed to init rpmsg device: %d\n", rpmsg_ret);
		kfree(priv);
		return -EINVAL;
	}

	/* announce a service called "echo" to frontend */
	rpmsg_ret = rpmsg_create_ept(&priv->echo_ept, &priv->rvdev.rdev,
					rpmsg_test_devices[vmid].echo_name,
					RPMSG_ADDR_ANY, RPMSG_ADDR_ANY,
					echo_endpoint_cb, echo_endpoint_unbind);
	if (rpmsg_ret) {
		pr_err("failed to create rpmsg ept: %d\n", rpmsg_ret);
		rpmsg_deinit_vdev(&priv->rvdev);
		kfree(priv);
		return -EINVAL;
	}

	return 0;
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
	int i;

	for (i = 0; i < ARRAY_SIZE(rpmsg_test_devices); i++) {
		nebula_rproc_register_device_for_host(&rpmsg_desc, sizeof(rpmsg_desc),
					&rpmsg_vdev_ops, rpmsg_test_devices[i].host_vmid, NULL);
	}

	return 0;
}

static void __exit nebula_rpmsg_sample_exit(void)
{
}

module_init(nebula_rpmsg_sample_init);
module_exit(nebula_rpmsg_sample_exit);
MODULE_LICENSE("Dual BSD/GPL");
