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

#include <linux/module.h>
#include <linux/nebula/nbl-tui.h>

static int tpd_enter_generic(void)
{
	return 0;
}

static int tpd_exit_generic(void)
{
	return 0;
}

static enum tpd_devid_t tpd_devid_generic(void)
{
	return TPD_TIPC;
}

static struct nbl_tui_tpd_ops g_tpd_ops = {
	.enter = tpd_enter_generic,
	.exit = tpd_exit_generic,
	.devid = tpd_devid_generic,
};

static int tui_generic_init(void)
{
	nbl_tui_register_tpd_ops(g_tpd_ops);
	return 0;
}

module_init(tui_generic_init);
