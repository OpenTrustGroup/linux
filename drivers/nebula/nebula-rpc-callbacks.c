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

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "nebula-rpc-callbacks.h"

static struct _ops {
	uint32_t cmd;
	rpc_cb cb;
} _ops[] = {};

int nebula_rpc_callbacks_init(void)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(_ops); ++i) {
		BUG_ON(!RPC_IS_KERNEL(_ops[i].cmd));
		BUG_ON(!_ops[i].cb);
		BUG_ON(nbl_rpc_add_cb(_ops[i].cmd, _ops[i].cb));
	}
	return 0;
}
late_initcall(nebula_rpc_callbacks_init);
