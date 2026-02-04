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

#ifdef CONFIG_MTK_IOMMU

#ifdef CONFIG_MTK_PSEUDO_M4U
#include <mach/pseudo_m4u.h>
#else
#include <m4u_v2_ext.h>
#endif

#else
#include <m4u.h>
#endif

#include "trusty-ion.h"

struct buffer_info {
	int module_id;
	ion_phys_addr_t mva;
	unsigned long len;
	struct sg_table *table;
};

/* Due to m4u data structure member variables' name are not
 * the same in different kernel version, we need to create
 * an internal data structure to unify the source code
 */
struct m4u_port_info_t {
	int emoduleid;
	unsigned long va;
	unsigned int buf_size;
	int security;
	int cache_coherent;
	unsigned int flags;
	unsigned int iova_start;
	unsigned int iova_end;
	unsigned int mva;
};

static int mtk_ion_heap_phys(struct ion_heap *heap, struct ion_buffer *buffer,
			    ion_phys_addr_t *addr, size_t *len) {
	struct m4u_port_info_t port_info;
	struct sg_table *table = buffer->sg_table;
	uint64_t vaddr;
	int ret;

	struct buffer_info *buffer_info = trusty_ion_get_plat_priv(buffer);
	if (!buffer_info) {
		pr_err("%s: unable to get buffer info\n", __func__);
		return -EINVAL;
	}
	if (buffer_info->mva) {
		*addr = buffer_info->mva;
		*len = buffer_info->len;
		return 0;
	}

	vaddr = (uint64_t)phys_to_virt(PFN_PHYS(page_to_pfn(sg_page(table->sgl))));

	memset((void *)&port_info, 0, sizeof(struct m4u_port_info_t));
	port_info.emoduleid = -1;
	port_info.buf_size = buffer->size;
	port_info.va = vaddr;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
	ret = m4u_alloc_mva_sg((struct port_mva_info_t *)&port_info, buffer->sg_table);
#else
	ret = m4u_alloc_mva_sg((port_mva_info_t *)&port_info, buffer->sg_table);
#endif
	if (ret) {
		pr_err("%s: failed to alloc mva for sg: %d\n", __func__, ret);
		return ret;
	}

	*(unsigned int *)addr = port_info.mva;
	*len = port_info.buf_size;

	buffer_info->module_id = -1;
	buffer_info->mva = *addr;
	buffer_info->len = *len;
	buffer_info->table = table;
	pr_info("%s: allocated mva entry: %llx %llx\n", __func__, buffer_info->mva, buffer_info->len);
	return 0;
}

static int mtk_register_ion_heap(struct ion_heap *heap) {
	heap->ops->phys = mtk_ion_heap_phys;

	ion_device_add_heap(g_ion_device, heap);
	return 0;
}

void *mtk_alloc_plat_priv() {
	void *priv = kzalloc(sizeof(struct buffer_info), GFP_KERNEL);
	return priv;
}

void mtk_free_plat_priv(void *priv) {
	struct buffer_info *info = (struct buffer_info *)priv;
	if (info->mva) {
		m4u_dealloc_mva_sg(info->module_id, info->table, info->len, info->mva);
		pr_info("%s: removed mva entry: table:%p, moduleId:%d, mva:0x%llx, len:0x%llx\n",
				__func__, info->table, info->module_id, info->mva, info->len);
	}
	kfree(info);
}

struct trusty_ion_platform_ops g_ion_platform_ops = {
	.register_ion_heap = mtk_register_ion_heap,
	.alloc_plat_priv = mtk_alloc_plat_priv,
	.free_plat_priv = mtk_free_plat_priv,
};
