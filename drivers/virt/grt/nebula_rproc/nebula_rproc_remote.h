// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2024 GoldenRiver Inc.

#include "remoteproc.h"
#include "remoteproc_virtio.h"

struct nebula_rproc_vdev_ops {
	int (*on_create)(struct virtio_device *vdev, struct metal_io_region *shm_io,
				 int vmid, void *user_priv);
	void (*on_destroy)(struct virtio_device *vdev);
	void (*on_reset)(struct virtio_device *vdev);
};

int nebula_rproc_register_device_for_host(const void *rsc,
				 size_t rsc_size, struct nebula_rproc_vdev_ops *vdev_ops,
				 int vmid, void *user_priv);

int nebula_rproc_register_device(const void *rsc, size_t rsc_size,
				 struct nebula_rproc_vdev_ops *vdev_ops, void *user_priv);
