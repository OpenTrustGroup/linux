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

#include "nebula-unittest.h"
#include "nebula-map.h"

static bool map_basic_test(void)
{
	struct nbl_map *map;
	const uint64_t kNumKeys = 4096;
	uint64_t key;

	BEGIN_TEST;

	map = nbl_map_init();
	ASSERT_FALSE(IS_ERR(map), "");

	for (key = 0; key < kNumKeys; ++key) {
		ASSERT_NULL(nbl_map_find(map, key), "");
		ASSERT_EQ(0, nbl_map_emplace(map, key, (void *)key), "");
		ASSERT_EQ(-EEXIST, nbl_map_emplace(map, key, (void *)key), "");
		ASSERT_EQ(key, (uint64_t)nbl_map_find(map, key), "");
	}

	for (key = 0; key < kNumKeys; ++key) {
		ASSERT_EQ(key, (uint64_t)nbl_map_find(map, key), "");
		ASSERT_EQ(key, (uint64_t)nbl_map_erase(map, key), "");
		ASSERT_EQ(-ENOENT, (long)nbl_map_erase(map, key), "");
		ASSERT_NULL(nbl_map_find(map, key), "");
	}

	nbl_map_delref(map);

	END_TEST;
}

UNITTEST_START_TESTCASE(map)
UNITTEST(map_basic_test)
UNITTEST_END_TESTCASE(map, "Hashmap unittests");
