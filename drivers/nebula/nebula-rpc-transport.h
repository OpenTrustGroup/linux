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

#ifndef __LINUX_NEBULA_RPC_TRANSPORT_H
#define __LINUX_NEBULA_RPC_TRANSPORT_H

#include <linux/types.h>
#include <linux/uio.h>

struct rpc_transport {
	int (*recv)(struct rpc_transport *transport, void *buf, size_t len);
	int (*send)(struct rpc_transport *transport, const void *buf,
		    size_t len);
	void *priv;
};

#endif /* __LINUX_NEBULA_RPC_TRANSPORT_H */
