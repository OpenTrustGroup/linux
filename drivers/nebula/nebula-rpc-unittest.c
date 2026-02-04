/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright 2021 GoldenRiver Technologies Co., Ltd.
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
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/completion.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/uio.h>

#include "nebula-rpc.h"
#include "nebula-rpc-proto.h"
#include "nebula-unittest.h"

static struct completion sWaitForRpc;
static const char kDummyData[] = "dummy";
static unsigned long kTimeoutMillis = 1000;

static bool rpc_send_callback_test(uint32_t cmd, const void *in,
				    size_t in_size, void **out,
				    size_t *out_size)
{
	BEGIN_TEST;

	ASSERT_EQ(NBL_KRPC_UNITTEST, cmd, "");
	ASSERT_EQ(sizeof(kDummyData), in_size, "");
	ASSERT_BYTES_EQ(kDummyData, in, in_size, "");
	complete_all(&sWaitForRpc);

	END_TEST;
}

static nbl_status rpc_send_callback(uint32_t cmd, const void *in,
				    size_t in_size, void **out,
				    size_t *out_size)
{
	bool test_ok = rpc_send_callback_test(cmd, in, in_size, out, out_size);
	if (test_ok == false) {
		return kNblErrGeneric;
	}
	return kNblOk;
}

static bool rpc_send_test(void)
{
	int ret;

	BEGIN_TEST;

	init_completion(&sWaitForRpc);
	nbl_rpc_add_cb(NBL_KRPC_UNITTEST, rpc_send_callback);

	ASSERT_EQ(0,
		  nbl_rpc_send(NBL_KRPC_UNITTEST, kDummyData,
			       sizeof(kDummyData)),
		  "");

	ret = wait_for_completion_interruptible_timeout(
		&sWaitForRpc, msecs_to_jiffies(kTimeoutMillis));
	EXPECT_GE(ret, 1, "");

	END_TEST;
}

UNITTEST_START_TESTCASE(rpc)
UNITTEST(rpc_send_test)
UNITTEST_END_TESTCASE(rpc, "RPC Kernel API unittests");
