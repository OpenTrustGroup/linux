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

#include <linux/err.h>
#include <linux/debugfs.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/uio.h>
#include <linux/types.h>
#include <linux/delay.h>
#include <linux/random.h>
#include <linux/kthread.h>

#include <linux/nebula/nbl-tui.h>

#include "hal/tui-hal_mt.h"
#include "nebula-unittest.h"

static bool ssmr_basic_test(void)
{
	phys_addr_t phys;
	size_t size;
	bool allow_64 = true;
	unsigned int feature = SSMR_FEAT_TUI;

	BEGIN_TEST;

	ASSERT_EQ(0, ssmr_offline(&phys, &size, allow_64, feature), "");
	ASSERT_NE(0, phys, "");
	ASSERT_NE(0, size, "");
	ASSERT_EQ(0, ssmr_online(feature), "");

	END_TEST;
}

static bool disp_basic_test(void)
{
	BEGIN_TEST;

	ASSERT_EQ(0, display_enter_tui(), "");
	ASSERT_EQ(0, display_exit_tui(), "");

	END_TEST;
}

static bool i2c_basic_test(void)
{
	/* TODO: find a better way instead of hardcode bus num. */
	int i2c_bus = 0;

	BEGIN_TEST;

	ASSERT_EQ(0, i2c_tui_enable_clock(i2c_bus), "");
	ASSERT_EQ(0, i2c_tui_disable_clock(i2c_bus), "");

	END_TEST;
}

static bool tpd_basic_test(void)
{
	BEGIN_TEST;

	ASSERT_EQ(0, nbl_tui_tpd_enter(), "");
	ASSERT_EQ(0, nbl_tui_tpd_exit(), "");
	ASSERT_NE(0, nbl_tui_tpd_devid(), "");

	END_TEST;
}

UNITTEST_START_TESTCASE(tui)
UNITTEST(ssmr_basic_test)
UNITTEST(disp_basic_test)
UNITTEST(i2c_basic_test)
UNITTEST(tpd_basic_test)
UNITTEST_END_TESTCASE(tui, "TUI unittests");
