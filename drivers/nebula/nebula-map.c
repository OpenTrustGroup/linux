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
#include <linux/slab.h>

#include "nebula-map.h"

struct nbl_map *nbl_map_init(void)
{
	struct nbl_map *map;

	map = kzalloc(sizeof(*map), GFP_KERNEL);
	if (!map)
		return ERR_PTR(-ENOMEM);

	kref_init(&map->refcount);
	hash_init(map->hash);
	return map;
}
EXPORT_SYMBOL(nbl_map_init);

static void _free_nbl_map(struct kref *kref)
{
	struct nbl_map_entry *entry;
	struct hlist_node *tmp;
	unsigned int bkt;
	struct nbl_map *map = container_of(kref, struct nbl_map, refcount);

	hash_for_each_safe (map->hash, bkt, tmp, entry, node) {
		hash_del(&entry->node);
		kfree(entry);
	}
	kfree(map);
}

struct nbl_map *nbl_map_addref(struct nbl_map *map)
{
	kref_get(&map->refcount);
	return map;
}
EXPORT_SYMBOL(nbl_map_addref);

void nbl_map_delref(struct nbl_map *map)
{
	kref_put(&map->refcount, _free_nbl_map);
}
EXPORT_SYMBOL(nbl_map_delref);

static struct nbl_map_entry *_nbl_map_find_entry(struct nbl_map *map,
						 uint64_t key)
{
	struct nbl_map_entry *entry = NULL;

	hash_for_each_possible (map->hash, entry, node, key) {
		if (entry->key == key)
			break;
	}

	return entry;
}

void *nbl_map_find(struct nbl_map *map, uint64_t key)
{
	struct nbl_map_entry *entry = _nbl_map_find_entry(map, key);

	return entry ? entry->data : NULL;
}
EXPORT_SYMBOL(nbl_map_find);

int nbl_map_emplace(struct nbl_map *map, uint64_t key, void *data)
{
	struct nbl_map_entry *entry = _nbl_map_find_entry(map, key);

	if (entry)
		return -EEXIST;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;

	entry->key = key;
	entry->data = data;
	hash_add(map->hash, &entry->node, key);
	map->num_entry++;

	return 0;
}
EXPORT_SYMBOL(nbl_map_emplace);

void *nbl_map_erase(struct nbl_map *map, uint64_t key)
{
	struct nbl_map_entry *entry;
	struct hlist_node *tmp;
	void *data = ERR_PTR(-ENOENT);

	hash_for_each_possible_safe (map->hash, entry, tmp, node, key) {
		if (entry->key == key) {
			data = entry->data;
			hash_del(&entry->node);
			kfree(entry);
			map->num_entry--;
			break;
		}
	}

	return data;
}
EXPORT_SYMBOL(nbl_map_erase);

size_t nbl_map_size(struct nbl_map *map)
{
	return map->num_entry;
}
EXPORT_SYMBOL(nbl_map_size);
