// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2024 GoldenRiver Inc.

#include "rpmsg.h"
#include "remoteproc.h"
#include "remoteproc_virtio.h"

struct nebula_rproc_vdev_ops {
	int (*on_create)(struct virtio_device *vdev, struct metal_io_region *shm_io);
	void (*on_destroy)(struct virtio_device *vdev);
	void (*on_reset)(struct virtio_device *vdev);
};

void nebula_rproc_register_device(const void *rsc, size_t rsc_size,
				  struct nebula_rproc_vdev_ops *vdev_ops);