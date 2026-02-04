/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright 2020 GoldenRiver Technologies Co., Ltd. All rights reserved.
 * Copyright (C) 2015 Google, Inc.
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

#ifndef _VTEE_LOG_H_
#define _VTEE_LOG_H_

bool is_vtee_nebula_log_ready(void);
void vtee_nebula_log_fifo_write(void *buf, size_t sz);
int vtee_nebula_log_init(void);
void vtee_nebula_log_exit(void);

#endif
