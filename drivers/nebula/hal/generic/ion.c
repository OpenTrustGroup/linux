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

#include <linux/scatterlist.h>
#include <linux/mm.h>
#include <linux/slab.h>

#include "trusty-ion.h"

static int generic_register_ion_heap(struct ion_heap *heap)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
	static struct ion_device *ion_device = NULL;

	if (!ion_device) {
		ion_device = ion_device_create(NULL);
		if (IS_ERR(ion_device)) {
			pr_err("%s: unable to create ion device\n", __func__);
			return PTR_ERR(ion_device);
		}
	}

	ion_device_add_heap(ion_device, heap);
#else
	ion_device_add_heap(heap);
#endif
	return 0;
}

static void *generic_alloc_plat_priv(void) {
	return NULL;
}

static void generic_free_plat_priv(void *priv) {
}

struct trusty_ion_platform_ops g_ion_platform_ops = {
	.register_ion_heap = generic_register_ion_heap,
	.alloc_plat_priv = generic_alloc_plat_priv,
	.free_plat_priv = generic_free_plat_priv,
};
