/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * Copyright 2020 GoldenRiver Technologies Co., Ltd. All rights reserved.
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

#ifndef __LINUX_NEBULA_TUI_H
#define __LINUX_NEBULA_TUI_H

#include <linux/types.h>

void nbl_tui_notify_pwrkey(void);

/* MUST sync with secure tpd driver */
enum tpd_devid_t {
	TPD_TIPC = 1,
	TPD_RESERVED_MAX = 0xf,
	TPD_TLSC6X,
	TPD_FT6336U,
};

struct nbl_tui_tpd_ops {
	int (*enter)(void);
	int (*exit)(void);
	enum tpd_devid_t (*devid)(void);
};
void nbl_tui_register_tpd_ops(struct nbl_tui_tpd_ops ops);
/* Deregister tpd driver from Linux */
int nbl_tui_tpd_enter(void);

/* Reregister tpd driver to Linux */
int nbl_tui_tpd_exit(void);

/* Get predefined device id for secure driver */
enum tpd_devid_t nbl_tui_tpd_devid(void);

int nbl_tui_input_connect(void);
void nbl_tui_input_disconnect(void);
void nbl_tui_input_set_abs_max(uint16_t x_max, uint16_t y_max);
void nbl_tui_input_report_abs(uint16_t x, uint16_t y, uint8_t down);

#endif
