// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2024 GoldenRiver Inc.

#include "rpmsg.h"

struct nebula_rpmsg_backend_ops {
	// this will be invoked when a rpmsg frontend annouce a new service.
	void (*on_bind)(struct rpmsg_device *rdev, const char *name,
			uint32_t dest, void *priv);

	// this will be invoked when a rpmsg frontend is attaching to us.
	int (*on_create)(struct rpmsg_device *rvdev, void *priv);
};

struct nebula_rpmsg_backend {
	struct nebula_rpmsg_backend_ops *ops;
	void *priv;
};

void nebula_rpmsg_backend_register(struct nebula_rpmsg_backend *backend);
void nebula_rpmsg_backend_unregister(struct nebula_rpmsg_backend *backend);
void *nebula_rpmsg_backend_get_priv(void);