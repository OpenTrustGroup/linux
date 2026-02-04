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

#ifndef __LINUX_NEBULA_RPC_H
#define __LINUX_NEBULA_RPC_H

#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>

#include "nebula-status.h"
#include "nebula-rpcmgr.h"

static inline nbl_status serialize(const void *in, size_t in_size, void **out,
				   size_t *out_size)
{
	void *reply;
	reply = kmalloc(in_size, GFP_KERNEL);
	if (!reply)
		return -ENOMEM;

	memcpy(reply, in, in_size);
	*out = reply;
	*out_size = in_size;
	return 0;
}

static inline nbl_status serialize_status(int status, void **out,
					  size_t *out_size)
{
	return serialize(&status, sizeof(status), out, out_size);
}

int nbl_rpc_add_cb(uint32_t cmd, rpc_cb cb);

int nbl_rpc_send(uint32_t ordinal, const void *payload, size_t payload_len);

#endif /* __LINUX_NEBULA_RPC_H */
