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

#ifndef __LINUX_NEBULA_MAP_H
#define __LINUX_NEBULA_MAP_H

#include <linux/hashtable.h>
#include <linux/kref.h>

#define MAP_HASH_BITS 12

struct nbl_map {
	struct kref refcount;
	DECLARE_HASHTABLE(hash, MAP_HASH_BITS);
	size_t num_entry;
};

struct nbl_map_entry {
	uint64_t key;
	void *data;
	struct hlist_node node;
};

extern struct nbl_map *nbl_map_init(void);
extern struct nbl_map *nbl_map_addref(struct nbl_map *map);
extern void nbl_map_delref(struct nbl_map *map);

extern void *nbl_map_find(struct nbl_map *map, uint64_t key);
extern int nbl_map_emplace(struct nbl_map *map, uint64_t key, void *data);
extern void *nbl_map_erase(struct nbl_map *map, uint64_t key);

extern size_t nbl_map_size(struct nbl_map *map);

#endif /* __LINUX_NEBULA_MAP_H */
