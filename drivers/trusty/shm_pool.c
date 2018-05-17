/*
 * Copyright (c) 2015, Linaro Limited
 * Copyright (c) 2017, EPAM Systems
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
#include <linux/device.h>
#include <linux/dma-buf.h>
#include <linux/genalloc.h>
#include <linux/slab.h>
#include <linux/tee_drv.h>
#include "shm_pool.h"

static int pool_op_alloc(struct tee_shm_pool_mgr *poolm,
			 struct tee_shm *shm, size_t size)
{
	void *buf;
	struct page *page;

	buf = alloc_pages_exact(size, GFP_KERNEL | __GFP_ZERO);
	if (!buf)
		return -ENOMEM;

	page = virt_to_page(buf);

	shm->kaddr = buf;
	shm->paddr = page_to_phys(page);
	shm->size = size;

	return 0;
}

static void pool_op_free(struct tee_shm_pool_mgr *poolm,
			 struct tee_shm *shm)
{
	free_pages_exact(shm->kaddr, shm->size);
	shm->kaddr = NULL;
}

static void pool_op_destroy_poolmgr(struct tee_shm_pool_mgr *poolm)
{
	kfree(poolm);
}

static const struct tee_shm_pool_mgr_ops pool_ops = {
	.alloc = pool_op_alloc,
	.free = pool_op_free,
	.destroy_poolmgr = pool_op_destroy_poolmgr,
};

/**
 * trusty_shm_pool_alloc_pages() - create page-based allocator pool
 *
 * This pool is used when TEE does not supports static SHM. In this case
 * command buffers and such are allocated from kernel's own memory.
 */
struct tee_shm_pool_mgr *trusty_shm_pool_alloc_pages(void)
{
	struct tee_shm_pool_mgr *mgr = kzalloc(sizeof(*mgr), GFP_KERNEL);

	if (!mgr)
		return ERR_PTR(-ENOMEM);

	mgr->ops = &pool_ops;

	return mgr;
}
