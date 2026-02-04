/*
 * Copyright 2018 GoldenRiver Technologies Co., Ltd. All rights reserved.
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

#ifndef _HAL_ION_H_
#define _HAL_ION_H_

struct ion_heap;
struct ion_buffer;

void *trusty_ion_get_plat_priv(struct ion_buffer *buffer);

struct trusty_ion_platform_ops {
	int (*register_ion_heap)(struct ion_heap *heap);

	void *(*alloc_plat_priv)(void);
	void (*free_plat_priv)(void *priv);
};

extern struct trusty_ion_platform_ops g_ion_platform_ops;

#endif
