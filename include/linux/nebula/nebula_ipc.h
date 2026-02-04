/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * Copyright 2021 GoldenRiver Technologies Co., Ltd. All rights reserved.
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

#ifndef __LINUX_NEBULA_IPC_H
#define __LINUX_NEBULA_IPC_H

#if defined(CONFIG_NEBULA_IPC) || defined(CONFIG_NEBULA_IPC_MODULE)

#include <linux/nebula/trusty_ipc.h>

int nbl_ipc_connect(const char *srv_name);
int nbl_ipc_close(int srv_id);
ssize_t nbl_ipc_read(int srv_id, void *buf, size_t count);
ssize_t nbl_ipc_write(int srv_id, const void *buf, size_t count,
		      struct tipc_shmem *shmv, uint shmv_cnt);

#endif /* CONFIG_NEBULA_IPC */

#endif /* __LINUX_NEBULA_IPC_H */
