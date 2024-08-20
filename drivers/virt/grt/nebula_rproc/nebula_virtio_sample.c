// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2024 GoldenRiver Inc.

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/of_platform.h>
#include <linux/delay.h>
#include <linux/sched/clock.h>

#include "nebula_rproc_remote.h"
#include "remoteproc_virtio.h"
#include "virtqueue.h"
#include "virtio.h"

/* Resource table entries */
#define VIRTIO_ID_SAMPLE 80UL
#define NUM_VRINGS	 0x02
#define VRING_ALIGN	 0x1000
#define RING_TX		 0
#define RING_RX		 1
#define VRING_SIZE	 256

struct sample_device_descriptor {
	struct fw_rsc_vdev vdev;
	struct fw_rsc_vdev_vring vrings[NUM_VRINGS];
} __packed;

static const struct sample_device_descriptor sample_vdev_desc = {
	.vdev		= {
		.type		= RSC_VDEV,
		.id		= VIRTIO_ID_SAMPLE,
		.dfeatures	= 0,
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

struct sample_vdev_priv {
	struct virtqueue *svq;
	struct virtqueue *rvq;
};

static void *get_tx_buffer(struct sample_vdev_priv *priv, uint16_t *avail_idx,
			   uint32_t *len)
{
	void *buf;
	while (1) {
		buf = virtqueue_get_available_buffer(priv->svq, avail_idx, len);
		if (buf)
			break;

		msleep(1);
	}

	return buf;
}

static void sample_virtio_tx_callback(struct virtqueue *vq)
{
}

static void sample_virtio_rx_callback(struct virtqueue *vq)
{
	struct virtio_device *vdev = vq->vq_dev;
	struct sample_vdev_priv *priv = vdev->priv;
	void *rx_buf;
	uint32_t rx_buf_size;
	uint16_t rx_idx;
	int ret;

	rx_buf = virtqueue_get_available_buffer(priv->rvq, &rx_idx,
						&rx_buf_size);
	while (rx_buf) {
		uint32_t tx_buf_size;
		uint16_t tx_idx;
		uint64_t timestamp;

		ret = virtqueue_add_consumed_buffer(priv->rvq, rx_idx, rx_buf_size);
		BUG_ON(ret != VQUEUE_SUCCESS);

		void *tx_buf = get_tx_buffer(priv, &tx_idx, &tx_buf_size);

		timestamp = __arch_counter_get_cntvct();
		memcpy(tx_buf, &timestamp, sizeof(timestamp));

		ret = virtqueue_add_consumed_buffer(priv->svq, tx_idx,
						    sizeof(timestamp));
		BUG_ON(ret != VQUEUE_SUCCESS);

		rx_buf = virtqueue_get_available_buffer(priv->rvq, &rx_idx,
							&rx_buf_size);
		if (!rx_buf) {
			/* tell peer we return some rx buffer */
			virtqueue_kick(priv->rvq);
		}
	}

	virtqueue_kick(priv->svq);
}

static int wait_driver_ready(struct virtio_device *vdev)
{
	uint8_t status;
	int ret;

	while (1) {
		ret = virtio_get_status(vdev, &status);
		if (ret)
			return ret;

		/* Busy wait until the remote is ready */
		if (status & VIRTIO_CONFIG_STATUS_NEEDS_RESET) {
			ret = virtio_set_status(vdev, 0);
			if (ret)
				return ret;
		} else if (status & VIRTIO_CONFIG_STATUS_DRIVER_OK) {
			return 0;
		}

		schedule();
	}
}

int sample_device_create(struct virtio_device *vdev,
			 struct metal_io_region *shm_io)
{
	const char *vq_names[NUM_VRINGS];
	vq_callback callback[NUM_VRINGS];
	int vq_err, ret;
	unsigned int i;

	struct sample_vdev_priv *priv =
		kzalloc(sizeof(struct sample_vdev_priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	vq_names[0] = "tx_vq";
	vq_names[1] = "rx_vq";
	callback[0] = sample_virtio_tx_callback;
	callback[1] = sample_virtio_rx_callback;

	/* Create virtqueues for remote device */
	vq_err = virtio_create_virtqueues(vdev, 0, NUM_VRINGS, vq_names,
					  callback, NULL);
	if (vq_err != VQUEUE_SUCCESS) {
		pr_err("failed to create virtqueue, err=%d\n", vq_err);
		return -EIO;
	}

	priv->rvq = vdev->vrings_info[1].vq;
	priv->svq = vdev->vrings_info[0].vq;

	ret = wait_driver_ready(vdev);
	if (ret)
		return ret;

	/*
	 * Suppress "tx-complete" interrupts
	 * since send method use busy loop when buffer pool exhaust
	 */
	virtqueue_disable_cb(priv->svq);

	for (i = 0; i < NUM_VRINGS; i++) {
		struct virtqueue *vq = vdev->vrings_info[i].vq;

		/* the shm_io is used by phys_to_virt()/virt_to_phys() */
		virtqueue_set_shmem_io(vq, shm_io);
	}

	vdev->priv = priv;

	return 0;
}

void sample_device_destroy(struct virtio_device *vdev)
{
}

static void sample_device_reset(struct virtio_device *vdev)
{
}

static struct nebula_rproc_vdev_ops sample_vdev_ops = {
	.on_create = sample_device_create,
	.on_destroy = sample_device_destroy,
	.on_reset = sample_device_reset,
};

static int __init nebula_virtio_sample_init(void)
{
	nebula_rproc_register_device(
		&sample_vdev_desc, sizeof(sample_vdev_desc), &sample_vdev_ops);
	return 0;
}

module_init(nebula_virtio_sample_init);
MODULE_LICENSE("Dual BSD/GPL");
