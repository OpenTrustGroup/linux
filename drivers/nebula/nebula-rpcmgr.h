/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright 2021 GoldenRiver Technologies Co., Ltd.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#ifndef __LINUX_NEBULA_RPCMGR_H
#define __LINUX_NEBULA_RPCMGR_H

#include <linux/kref.h>
#include <linux/mutex.h>
#include <linux/types.h>

#include "nebula-rpc-transport.h"
#include "nebula-map.h"
#include "nebula-status.h"

#define MAX_NUM_RPC_WORKER 1

typedef nbl_status (*rpc_cb)(uint32_t cmd, const void *in, size_t in_size,
			     void **out, size_t *out_size);

struct nbl_rpcmgr {
	struct mutex lock;
	struct kref refcount;
	struct rpc_transport *transport;
	struct nbl_map *cmds;
	struct nbl_map *incomplete_messages;
	struct task_struct *worker[MAX_NUM_RPC_WORKER];
};

extern struct nbl_rpcmgr *nbl_rpcmgr_init(struct rpc_transport *transport);
extern struct nbl_rpcmgr *nbl_rpcmgr_addref(struct nbl_rpcmgr *mgr);
extern void nbl_rpcmgr_delref(struct nbl_rpcmgr *mgr);

extern int nbl_rpcmgr_add_cb(struct nbl_rpcmgr *mgr, uint32_t cmd, rpc_cb cb);
extern int nbl_rpcmgr_del_cb(struct nbl_rpcmgr *mgr, uint32_t cmd);

#endif /* __LINUX_NEBULA_RPCMGR_H */
