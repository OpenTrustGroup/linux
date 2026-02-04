/* SPDX-License-Identifier: GPL-2.0-only */
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

#include <linux/dma-buf.h>
#include <linux/genalloc.h>
#include <linux/printk.h>
#include <linux/scatterlist.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/nebula/smcall.h>
#include <linux/nebula/trusty.h>
#include <linux/nebula/trusty_ipc.h>
#include <linux/types.h>
#include <linux/of.h>
#include <linux/of_fdt.h>
#include <linux/of_reserved_mem.h>

#include "trusty-ion.h"

struct trusty_ion_priv {
	uint32_t magic;
	uint32_t handle;
	void *plat_priv;
};

#define TRUSTY_ION_MAGIC 0x54494f4e /* 'TION' */

#define ION_HEAP_ID_SECCAM 0
#define ION_HEAP_ID_CARVEOUT ION_HEAP_TYPE_CARVEOUT

static struct ion_platform_heap platform_heap_list[] = {
	{
		.id = ION_HEAP_ID_SECCAM,
		.type = ION_HEAP_TYPE_CARVEOUT,
		.name = "trusty_ion",
		.size = 0,
	},
	{
		.id = ION_HEAP_ID_CARVEOUT,
		.type = ION_HEAP_TYPE_CARVEOUT,
		.name = "carveout",
		.size = 0,
	},
};

#ifndef ION_CARVEOUT_ALLOCATE_FAIL
#define ION_CARVEOUT_ALLOCATE_FAIL -1
#endif

struct carveout_heap {
	struct ion_heap heap;
	struct gen_pool *pool;
	phys_addr_t base;
};

static struct sg_table *__alloc_sg_table(phys_addr_t paddr, unsigned long len) {
	struct sg_table *table;
	int ret;

	table = kmalloc(sizeof(*table), GFP_KERNEL);
	if (!table)
		return NULL;

	ret = sg_alloc_table(table, 1, GFP_KERNEL);
	if (ret)
		goto err_free;

	sg_set_page(table->sgl, pfn_to_page(PFN_DOWN(paddr)), len, 0);

	return table;
err_free:
	kfree(table);
	return NULL;
}

static void __free_sg_table(struct sg_table *table) {
	sg_free_table(table);
	kfree(table);
}

static phys_addr_t __carveout_allocate(struct ion_heap *heap,
				       unsigned long size)
{
	struct carveout_heap *carveout_heap =
		container_of(heap, struct carveout_heap, heap);
	unsigned long offset = gen_pool_alloc(carveout_heap->pool, size);

	if (!offset)
		return ION_CARVEOUT_ALLOCATE_FAIL;

	return offset;
}

static void __carveout_free(struct ion_heap *heap, phys_addr_t addr,
			    unsigned long size)
{
	struct carveout_heap *carveout_heap =
		container_of(heap, struct carveout_heap, heap);

	if (addr == ION_CARVEOUT_ALLOCATE_FAIL)
		return;
	gen_pool_free(carveout_heap->pool, addr, size);
}

static int __carveout_heap_allocate(struct ion_heap *heap,
				    struct ion_buffer *buffer,
				    unsigned long size, unsigned long flags)
{
	struct sg_table *table;
	phys_addr_t paddr;
	int ret;
	struct trusty_ion_priv *priv = buffer->priv_virt;

	paddr = __carveout_allocate(heap, size);
	if (paddr == ION_CARVEOUT_ALLOCATE_FAIL) {
		return -ENOMEM;
	}

	table = __alloc_sg_table(paddr, size);
	if (!table) {
		ret = -ENOMEM;
		goto err_carveout_free;
	}
	buffer->sg_table = table;

	priv->plat_priv = g_ion_platform_ops.alloc_plat_priv();
	return 0;

err_carveout_free:
	__carveout_free(heap, paddr, size);
	return ret;
}

static void __carveout_heap_free(struct ion_buffer *buffer)
{
	struct ion_heap *heap = buffer->heap;
	struct trusty_ion_priv *priv = buffer->priv_virt;
	struct sg_table *table = buffer->sg_table;
	struct page *page = sg_page(table->sgl);
	phys_addr_t paddr = PFN_PHYS(page_to_pfn(page));

	g_ion_platform_ops.free_plat_priv(priv->plat_priv);

	ion_heap_buffer_zero(buffer);

	__carveout_free(heap, paddr, buffer->size);

	__free_sg_table(table);
}

static uint32_t ion_handle_id = 200;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0) || defined(CONFIG_NEBULA_HAL_MEDIATEK)
static int trusty_ion_heap_phys(struct ion_heap *heap,
				struct ion_buffer *buffer,
				ion_phys_addr_t *addr, size_t *len)
{
	struct sg_table *table = buffer->sg_table;
	struct page *page = sg_page(table->sgl);
	ion_phys_addr_t paddr = PFN_PHYS(page_to_pfn(page));

	*addr = paddr;
	*len = buffer->size;
	return 0;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0)
static struct sg_table *trusty_ion_map_dma(struct ion_heap *heap,
						  struct ion_buffer *buffer)
{
	return buffer->sg_table;
}

static void trusty_ion_heap_unmap_dma(struct ion_heap *heap,
				      struct ion_buffer *buffer)
{
}
#endif

static int trusty_ion_map_user(struct ion_heap *heap, struct ion_buffer *buffer,
			       struct vm_area_struct *vma)
{
#if !defined(CONFIG_NEBULA_SECCAM_ION_WRITEABLE)
	vma->vm_flags &= ~VM_WRITE;
	vma->vm_page_prot = vm_get_page_prot(vma->vm_flags);
#endif
	return ion_heap_map_user(heap, buffer, vma);
}

static int register_ion_buffer(struct ion_buffer *buffer, size_t len)
{
	int ret;
	struct scatterlist *sg;
	uint64_t paddr;
	struct trusty_ion_priv *priv = buffer->priv_virt;

	sg = buffer->sg_table->sgl;
	paddr = page_to_phys(sg_page(sg));
	ret = nebula_tipc_register_ion_buffer(priv->handle, paddr, len);
	if (ret != 0)
		pr_err("failed to register ion buffer: %d\n", ret);

	return ret;
}

static int trusty_ion_allocate(struct ion_heap *heap, struct ion_buffer *buffer,
			       unsigned long len,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0) || defined(CONFIG_NEBULA_HAL_MEDIATEK)
			       unsigned long align,
#endif
			       unsigned long flags)
{
	struct trusty_ion_priv *priv;
	int ret;

	priv = kzalloc(sizeof(struct trusty_ion_priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	priv->magic = TRUSTY_ION_MAGIC;
	priv->handle = ion_handle_id++;
	buffer->priv_virt = priv;

	ret = __carveout_heap_allocate(heap, buffer, len, flags);
	if (ret)
		goto err_free_priv;

	ret = register_ion_buffer(buffer, len);
	if (ret)
		goto err_free_ion_buffer;

	return 0;

err_free_ion_buffer:
	__carveout_heap_free(buffer);
err_free_priv:
	kfree(priv);

	return ret;
}

static void trusty_ion_free(struct ion_buffer *buffer)
{
	struct trusty_ion_priv *priv = buffer->priv_virt;

	nebula_tipc_deregister_ion_buffer(priv->handle);

	__carveout_heap_free(buffer);

	kfree(priv);
}

void *trusty_ion_get_plat_priv(struct ion_buffer *buffer) {
	struct trusty_ion_priv *priv = buffer->priv_virt;
	return priv->plat_priv;
}

long tipc_query_ion_handle(unsigned long arg)
{
	struct dma_buf *dmabuf;
	struct ion_buffer *buffer;
	struct tipc_query_ion_handle_req req;
	struct trusty_ion_priv *priv;

	/* copy in request */
	if (copy_from_user(&req, (const void __user *)arg, sizeof(req)))
		return -EFAULT;

	dmabuf = dma_buf_get(req.ion_fd);
	if (IS_ERR(dmabuf)) {
		pr_err("%s: unable to get dma buffer from fd %d\n", __func__, req.ion_fd);
		return -EINVAL;
	}

	buffer = dmabuf->priv;
	dma_buf_put(dmabuf);

	priv = buffer->priv_virt;
	if (!priv)
		return -EINVAL;

	if (priv->magic != TRUSTY_ION_MAGIC)
		return -EINVAL;

	req.out_handle = priv->handle;
	if (copy_to_user((void __user *)arg, &req, sizeof(req)))
		return -EFAULT;

	return 0;
}

static struct ion_heap_ops trusty_ion_heap_ops = {
	.allocate = trusty_ion_allocate,
	.free = trusty_ion_free,
	.map_user = trusty_ion_map_user,
	.map_kernel = ion_heap_map_kernel,
	.unmap_kernel = ion_heap_unmap_kernel,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0) || defined(CONFIG_NEBULA_HAL_MEDIATEK)
	.phys = trusty_ion_heap_phys,
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0)
	.map_dma = trusty_ion_map_dma,
	.unmap_dma = trusty_ion_heap_unmap_dma,
#endif
};

static void __carveout_chunk_show(struct gen_pool *pool,
				  struct gen_pool_chunk *chunk, void *data)
{
	int order, nlongs, nbits, i;
	struct seq_file *s = (struct seq_file *)data;

	order = pool->min_alloc_order;
	nbits = (chunk->end_addr - chunk->start_addr) >> order;
	nlongs = BITS_TO_LONGS(nbits);

	seq_printf(s, "phys_addr=0x%x bits=", (unsigned int)chunk->phys_addr);

	for (i = 0; i < nlongs; i++)
		seq_printf(s, "0x%x ", (unsigned int)chunk->bits[i]);

	seq_puts(s, "\n");
}

static int __carveout_heap_debug_show(struct ion_heap *heap, struct seq_file *s,
				      void *unused)
{
	struct carveout_heap *carveout_heap =
		container_of(heap, struct carveout_heap, heap);
	size_t size_avail, total_size;

	total_size = gen_pool_size(carveout_heap->pool);
	size_avail = gen_pool_avail(carveout_heap->pool);

	seq_printf(s, "total_size=0x%zu, free=0x%zu, base=0x%llu\n", total_size,
		   size_avail, carveout_heap->base);

	gen_pool_for_each_chunk(carveout_heap->pool, __carveout_chunk_show, s);

	return 0;
}

static struct ion_heap *
__carveout_heap_create(struct ion_platform_heap *heap_data)
{
	struct carveout_heap *carveout_heap;
	int ret;

	struct page *page;
	size_t size;

	page = pfn_to_page(PFN_DOWN(heap_data->base));
	size = heap_data->size;

	ret = ion_heap_pages_zero(page, size, pgprot_writecombine(PAGE_KERNEL));
	if (ret)
		return ERR_PTR(ret);

	carveout_heap = kzalloc(sizeof(*carveout_heap), GFP_KERNEL);
	if (!carveout_heap)
		return ERR_PTR(-ENOMEM);

	carveout_heap->pool = gen_pool_create(PAGE_SHIFT, -1);
	if (!carveout_heap->pool) {
		kfree(carveout_heap);
		return ERR_PTR(-ENOMEM);
	}
	carveout_heap->base = heap_data->base;
	gen_pool_add(carveout_heap->pool, carveout_heap->base, heap_data->size,
		     -1);
	carveout_heap->heap.ops = &trusty_ion_heap_ops;
	carveout_heap->heap.type = ION_HEAP_TYPE_CARVEOUT;
	carveout_heap->heap.flags = ION_HEAP_FLAG_DEFER_FREE;
	carveout_heap->heap.debug_show = __carveout_heap_debug_show;
	return &carveout_heap->heap;
}

static void __carveout_heap_destroy(struct ion_heap *heap)
{
	struct carveout_heap *carveout_heap =
		container_of(heap, struct carveout_heap, heap);

	gen_pool_destroy(carveout_heap->pool);
	kfree(carveout_heap);
	carveout_heap = NULL;
}

static int nbl_ion_create(struct ion_platform_heap *heap_data)
{
	int ret = 0;
	struct ion_heap *heap = NULL;

	switch (heap_data->id) {
	case ION_HEAP_ID_SECCAM:
		heap = __carveout_heap_create(heap_data);
		break;
	case ION_HEAP_ID_CARVEOUT:
		heap = ion_carveout_heap_create(heap_data);
		break;
	default:
		pr_err("%s: unknown nbl ion heap id=%u\n", __func__,
		       heap_data->id);
		return -EINVAL;
	}

	if (!heap) {
		pr_err("%s: unable to create nbl ion heap, id=%u\n", __func__,
		       heap_data->id);
		return -ENOMEM;
	}

	heap->name = heap_data->name;
	heap->id = heap_data->id;

	pr_info("%s: created nbl ion heap %s @ %lx, size: 0x%zx\n", __func__,
		heap->name, (ulong)heap_data->base, heap_data->size);

	ret = g_ion_platform_ops.register_ion_heap(heap);
	if (ret < 0) {
		/* Due to kernel version >= 4.14 do not have destroy function for
		 * carveout heap type, we need to implement it by self */
		__carveout_heap_destroy(heap);
	}
	return ret;
}

static int update_ion_region(unsigned int id, phys_addr_t base, size_t size)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(platform_heap_list); i++) {
		if (id == platform_heap_list[i].id) {
			platform_heap_list[i].base = base;
			platform_heap_list[i].size = size;
			return 0;
		}
	}

	pr_err("%s: ion heap id (%u) not found", __func__, id);
	return -EINVAL;
}

static int __init reserve_nbl_seccam_ion(struct reserved_mem *rmem)
{
	pr_info("%s: detected seccam ion reserved memory, base: 0x%pa, size: 0x%pa\n",
		 __func__, &rmem->base, &rmem->size);

	return update_ion_region(ION_HEAP_ID_SECCAM, rmem->base, rmem->size);
}
RESERVEDMEM_OF_DECLARE(seccam_ion, "nbl,seccam-ion-reserve-memory",
		       reserve_nbl_seccam_ion);

static int __init reserve_nbl_carveout_ion(struct reserved_mem *rmem)
{
	pr_info("%s: detected carveout ion reserved memory, base: 0x%pa, size: 0x%pa\n",
		__func__, &rmem->base, &rmem->size);

	return update_ion_region(ION_HEAP_ID_CARVEOUT, rmem->base, rmem->size);
}
RESERVEDMEM_OF_DECLARE(carveout_ion, "ion_carveout", reserve_nbl_carveout_ion);

static int __init nbl_ion_init(void)
{
	int i, ret;

	for (i = 0; i < ARRAY_SIZE(platform_heap_list); i++) {
		if (platform_heap_list[i].size > 0) {
			ret = nbl_ion_create(&platform_heap_list[i]);
			if (ret < 0) {
				pr_err("%s: failed to init nbl ion memory, id=%u",
				       __func__, platform_heap_list[i].id);
				return ret;
			}
		}
	}

	return 0;
}

module_init(nbl_ion_init);
