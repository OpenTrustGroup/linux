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

#include <linux/err.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/uio.h>

#include <linux/nebula/nebula_ipc.h>

#include "nebula-unittest.h"

#define MAX_NAME_LEN 256

#define TIPC_MEMREF_PERM_RO (0x0 << 0)
#define TIPC_MEMREF_PERM_RW (0x1 << 0)

#define MEMREF_UT_CMD_FILL  1
#define MEMREF_UT_CMD_CHECK 2

struct memref_test_cmd {
	uint16_t cmd;
	uint16_t flags;
	uint32_t arg;
	uint32_t hsize;
	uint32_t offset;
	uint32_t dsize;
	uint32_t delay;
	uint32_t status;
};

static bool echo_test(void)
{
	int ret;
	int err;
	int srv_id;
	const char srv_name[] = "com.android.ipc-unittest.srv.echo";
	char *bytes;
	char *in_bytes, *out_bytes;
	int num_bytes;
	const int kMaxNumBytes = 4080;

	BEGIN_TEST;

	bytes = kzalloc(2 * PAGE_SIZE, GFP_KERNEL);
	ASSERT_NONNULL(bytes, "");

	in_bytes = bytes;
	out_bytes = bytes + PAGE_SIZE;

	srv_id = nbl_ipc_connect(srv_name);
	ASSERT_GT(srv_id, 0, "");

	memset(out_bytes, 0xff, PAGE_SIZE);

	for (num_bytes = 0; num_bytes <= kMaxNumBytes; ++num_bytes) {
		ret = nbl_ipc_write(srv_id, out_bytes, num_bytes, NULL, 0);
		ASSERT_EQ(num_bytes, ret, "");

		memset(in_bytes, 0, PAGE_SIZE);
		ret = nbl_ipc_read(srv_id, in_bytes, num_bytes);
		ASSERT_EQ(num_bytes, ret, "");

		ASSERT_BYTES_EQ(out_bytes, in_bytes, num_bytes, "");
	}

	err = nbl_ipc_close(srv_id);
	ASSERT_EQ(0, err, "");
	kfree(bytes);

	END_TEST;
}

static bool memref_test(void)
{
	int ret;
	int err;
	int srv_id;
	const char srv_name[] = "com.android.trusty.memref-unittest.leaf";
	const char kValue = 0xff;
	const int kMemorySize = PAGE_SIZE;
	char *memory;
	struct memref_test_cmd cmd;
	struct tipc_shmem shmv;

	BEGIN_TEST;

	memory = alloc_pages_exact(kMemorySize, GFP_KERNEL);
	ASSERT_NONNULL(memory, "");

	srv_id = nbl_ipc_connect(srv_name);
	ASSERT_GT(srv_id, 0, "");

	memset(&cmd, 0, sizeof(cmd));
	cmd.cmd = MEMREF_UT_CMD_FILL;
	cmd.arg = kValue;
	cmd.dsize = kMemorySize;
	cmd.hsize = kMemorySize;

	memset(&shmv, 0, sizeof(shmv));
	shmv.flags = TIPC_MEMREF_PERM_RW;
	shmv.base[1] = (__u64)memory;
	shmv.size[1] = kMemorySize;

	ret = nbl_ipc_write(srv_id, &cmd, sizeof(cmd), &shmv, 1);
	ASSERT_EQ(sizeof(cmd), ret, "");

	memset(&cmd, 0, sizeof(cmd));
	ret = nbl_ipc_read(srv_id, &cmd, sizeof(cmd));
	ASSERT_EQ(sizeof(cmd), ret, "");

	ASSERT_EQ(kValue, memory[0], "");
	ASSERT_BYTES_EQ(memory, memory + 1, kMemorySize - 1, "");

	err = nbl_ipc_close(srv_id);
	ASSERT_EQ(0, err, "");
	free_pages_exact(memory, kMemorySize);

	END_TEST;
}

UNITTEST_START_TESTCASE(ipc)
UNITTEST(echo_test)
UNITTEST(memref_test)
UNITTEST_END_TESTCASE(ipc, "IPC Kernel API unittests");
