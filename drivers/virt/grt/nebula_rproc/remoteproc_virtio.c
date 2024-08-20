/*
 * Remoteproc Virtio Framework Implementation
 *
 * Copyright(c) 2018 Xilinx Ltd.
 * Copyright(c) 2011 Texas Instruments, Inc.
 * Copyright(c) 2011 Google, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/mod_devicetable.h>

#include "remoteproc.h"
#include "remoteproc_virtio.h"
#include "virtqueue.h"

static void rproc_virtio_delete_virtqueues(struct virtio_device *vdev)
{
	struct virtio_vring_info *vring_info;
	unsigned int i;

	if (!vdev->vrings_info)
		return;

	for (i = 0; i < vdev->vrings_num; i++) {
		vring_info = &vdev->vrings_info[i];
		if (vring_info->vq)
			virtqueue_free(vring_info->vq);
	}
}

static int rproc_virtio_create_virtqueue(struct virtio_device *vdev,
					 unsigned int flags,
					 unsigned int idx,
					 const char *name,
					 vq_callback callback)
{
	struct virtio_vring_info *vring_info;
	struct vring_alloc_info *vring_alloc;
	int ret;
	(void)flags;

	/* Get the vring information */
	vring_info = &vdev->vrings_info[idx];
	vring_alloc = &vring_info->info;

	/* Fail if the virtqueue has already been created */
	if (vring_info->vq)
		return ERROR_VQUEUE_INVLD_PARAM;

	/* Alloc the virtqueue and init it */
	vring_info->vq = virtqueue_allocate(vring_alloc->num_descs);
	if (!vring_info->vq)
		return ERROR_NO_MEM;

	ret = virtqueue_create(vdev, idx, name, vring_alloc, callback,
			       vdev->func->notify, vring_info->vq);
	if (ret)
		return ret;

	return 0;
}

static int rproc_virtio_create_virtqueues(struct virtio_device *vdev,
					  unsigned int flags,
					  unsigned int nvqs,
					  const char *names[],
					  vq_callback callbacks[],
					  void *callback_args[])
{
	unsigned int i;
	int ret;
	(void)callback_args;

	/* Check virtqueue numbers and the vrings_info */
	if (nvqs > vdev->vrings_num || !vdev || !vdev->vrings_info)
		return ERROR_VQUEUE_INVLD_PARAM;

	/* set the notification id for vrings */
	for (i = 0; i < nvqs; i++) {
		ret = rproc_virtio_create_virtqueue(vdev, flags, i, names[i], callbacks[i]);
		if (ret)
			goto err;
	}
	return 0;

err:
	rproc_virtio_delete_virtqueues(vdev);
	return ret;
}

static void rproc_virtio_virtqueue_notify(struct virtqueue *vq)
{
	struct remoteproc_virtio *rpvdev;
	struct virtio_vring_info *vring_info;
	struct virtio_device *vdev;
	unsigned int vq_id = vq->vq_queue_index;

	vdev = vq->vq_dev;
	rpvdev = container_of(vdev, struct remoteproc_virtio, vdev);
	BUG_ON(vq_id >= vdev->vrings_num);
	vring_info = &vdev->vrings_info[vq_id];
	rpvdev->notify(rpvdev->priv, vring_info->notifyid);
}

static unsigned char rproc_virtio_get_status(struct virtio_device *vdev)
{
	struct remoteproc_virtio *rpvdev;
	struct fw_rsc_vdev *vdev_rsc;
	char status;

	rpvdev = container_of(vdev, struct remoteproc_virtio, vdev);
	vdev_rsc = rpvdev->vdev_rsc;
	status = vdev_rsc->status;
	return status;
}

static uint32_t rproc_virtio_get_dfeatures(struct virtio_device *vdev)
{
	struct remoteproc_virtio *rpvdev;
	struct fw_rsc_vdev *vdev_rsc;
	uint32_t features;

	rpvdev = container_of(vdev, struct remoteproc_virtio, vdev);
	vdev_rsc = rpvdev->vdev_rsc;
	features = vdev_rsc->dfeatures;

	return features;
}

static uint32_t rproc_virtio_get_features(struct virtio_device *vdev)
{
	struct remoteproc_virtio *rpvdev;
	struct fw_rsc_vdev *vdev_rsc;
	uint32_t gfeatures;
	uint32_t dfeatures;

	rpvdev = container_of(vdev, struct remoteproc_virtio, vdev);
	vdev_rsc = rpvdev->vdev_rsc;
	gfeatures = vdev_rsc->gfeatures;
	dfeatures = rproc_virtio_get_dfeatures(vdev);

	return dfeatures & gfeatures;
}

static void rproc_virtio_read_config(struct virtio_device *vdev,
				     uint32_t offset, void *dst, int length)
{
	struct remoteproc_virtio *rpvdev;
	struct fw_rsc_vdev *vdev_rsc;
	char *config;

	rpvdev = container_of(vdev, struct remoteproc_virtio, vdev);
	vdev_rsc = rpvdev->vdev_rsc;
	config = (char *)(&vdev_rsc->vring[vdev->vrings_num]);

	if (offset + length <= vdev_rsc->config_len) {
		memcpy(dst, config + offset, length);
	}
}

static const struct virtio_dispatch remoteproc_virtio_dispatch_funcs = {
	.create_virtqueues = rproc_virtio_create_virtqueues,
	.delete_virtqueues = rproc_virtio_delete_virtqueues,
	.get_status = rproc_virtio_get_status,
	.get_features = rproc_virtio_get_features,
	.read_config = rproc_virtio_read_config,
	.notify = rproc_virtio_virtqueue_notify,
};

struct virtio_device *
rproc_virtio_create_vdev(unsigned int role, unsigned int notifyid,
			 void *rsc, struct metal_io_region *rsc_io,
			 void *priv,
			 rpvdev_notify_func notify,
			 virtio_dev_reset_cb rst_cb)
{
	struct remoteproc_virtio *rpvdev;
	struct virtio_vring_info *vrings_info;
	struct fw_rsc_vdev *vdev_rsc = rsc;
	struct virtio_device *vdev;
	unsigned int num_vrings = vdev_rsc->num_of_vrings;

	rpvdev = kzalloc(sizeof(*rpvdev), GFP_KERNEL);
	if (!rpvdev)
		return NULL;

	vrings_info = kzalloc(sizeof(*vrings_info) * num_vrings, GFP_KERNEL);
	if (!vrings_info)
		goto err;

	/* Initialize the remoteproc virtio */
	rpvdev->notify = notify;
	rpvdev->priv = priv;
	/* Assuming the shared memory has been mapped and registered if
	 * necessary
	 */
	rpvdev->vdev_rsc = vdev_rsc;
	rpvdev->vdev_rsc_io = rsc_io;

	/* Initialize the virtio device */
	vdev = &rpvdev->vdev;
	vdev->vrings_info = vrings_info;
	vdev->notifyid = notifyid;
	vdev->id.device = vdev_rsc->id;
	vdev->role = role;
	vdev->reset_cb = rst_cb;
	vdev->vrings_num = num_vrings;
	vdev->func = &remoteproc_virtio_dispatch_funcs;

	return &rpvdev->vdev;
err:
	kfree(rpvdev);
	return NULL;
}

void rproc_virtio_remove_vdev(struct virtio_device *vdev)
{
	struct remoteproc_virtio *rpvdev;

	if (!vdev)
		return;
	rpvdev = container_of(vdev, struct remoteproc_virtio, vdev);
	if (vdev->vrings_info)
		kfree(vdev->vrings_info);
	kfree(rpvdev);
}

int rproc_virtio_init_vring(struct virtio_device *vdev, unsigned int index,
			    unsigned int notifyid, void *va,
			    struct metal_io_region *io,
			    unsigned int num_descs, unsigned int align)
{
	struct virtio_vring_info *vring_info;
	unsigned int num_vrings;

	num_vrings = vdev->vrings_num;
	if ((index >= num_vrings) || (num_descs > RPROC_MAX_VRING_DESC))
		return -RPROC_EINVAL;
	vring_info = &vdev->vrings_info[index];
	vring_info->io = io;
	vring_info->notifyid = notifyid;
	vring_info->info.vaddr = va;
	vring_info->info.num_descs = num_descs;
	vring_info->info.align = align;

	return 0;
}

int rproc_virtio_notified(struct virtio_device *vdev, uint32_t notifyid)
{
	unsigned int num_vrings, i;
	struct virtio_vring_info *vring_info;
	struct virtqueue *vq;

	if (!vdev)
		return -RPROC_EINVAL;
	/* We do nothing for vdev notification in this implementation */
	if (vdev->notifyid == notifyid)
		return 0;
	num_vrings = vdev->vrings_num;
	for (i = 0; i < num_vrings; i++) {
		vring_info = &vdev->vrings_info[i];
		if (vring_info->notifyid == notifyid ||
		    notifyid == RSC_NOTIFY_ID_ANY) {
			vq = vring_info->vq;
			virtqueue_notification(vq);
		}
	}
	return 0;
}

void rproc_virtio_wait_remote_ready(struct virtio_device *vdev)
{
	uint8_t status;

	while (1) {
		status = rproc_virtio_get_status(vdev);
		if (status & VIRTIO_CONFIG_STATUS_DRIVER_OK)
			return;
		schedule();
	}
}
