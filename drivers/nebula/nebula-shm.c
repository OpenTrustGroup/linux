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

#define pr_fmt(fmt) "nebula-shm: " fmt

#include <linux/genalloc.h>
#include <linux/rculist.h>
#include <linux/slab.h>
#include <linux/nebula/nebula_shm.h>

static struct gen_pool *gpool __maybe_unused;

struct nbl_shm_ops {
	void *(*alloc)(size_t size, gfp_t gfp_mask); /* alloc_pages_exact */
	void (*free)(void *vaddr, size_t size); /* free_pages_exact */
	/* arch/arm64/include/asm/memory.h */
	void *(*phys_to_virt)(phys_addr_t x);
	phys_addr_t (*virt_to_phys)(const volatile void *x);
};

static void *_default_alloc(size_t sz, gfp_t gfp)
{
	return alloc_pages_exact(sz, gfp);
}

static void _default_free(void *va, size_t sz)
{
	free_pages_exact(va, sz);
}

static void *_default_phys_to_virt(phys_addr_t paddr)
{
	return phys_to_virt(paddr);
}

static phys_addr_t _default_virt_to_phys(const volatile void *vaddr)
{
	return virt_to_phys(vaddr);
}

static struct nbl_shm_ops _shm_ops = {
	.alloc = _default_alloc,
	.free = _default_free,
	.virt_to_phys = _default_virt_to_phys,
	.phys_to_virt = _default_phys_to_virt,
};

static void *_gpool_alloc(size_t size, gfp_t gfp)
{
	unsigned long vaddr;

	BUG_ON(!gpool);
	BUG_ON(!size);

	vaddr = gen_pool_alloc(gpool, size);
	if (!vaddr) {
		pr_err("alloc failed, request 0x%zx avail 0x%zx\n", size,
		       gen_pool_avail(gpool));
		return NULL;
	}

	if (gfp & __GFP_ZERO)
		memset((void *)vaddr, 0, size);

	/* WARN if other gfp set ? */

	pr_debug("0x%zx alloced, avail 0x%zx\n", size, gen_pool_avail(gpool));

	return (void *)vaddr;
}

static void _gpool_free(void *vaddr, size_t size)
{
	BUG_ON(!gpool);
	BUG_ON(!vaddr);
	BUG_ON(!size);

	gen_pool_free(gpool, (uintptr_t)vaddr, size);

	pr_debug("0x%zx freed, avail 0x%zx\n", size, gen_pool_avail(gpool));
}

static void *_gpool_phys_to_virt(phys_addr_t paddr)
{
	struct gen_pool_chunk *chunk;
	size_t chunk_size = 0;
	unsigned long vaddr = 0;

	BUG_ON(!gpool);

	rcu_read_lock();
	list_for_each_entry_rcu (chunk, &gpool->chunks, next_chunk) {
		chunk_size = chunk->end_addr - chunk->start_addr + 1;
		/* check addr is within chunk boundary */
		if (paddr >= chunk->phys_addr &&
		    paddr <= (chunk->phys_addr + chunk_size)) {
			vaddr = chunk->start_addr + (paddr - chunk->phys_addr);
			break;
		}
	}
	rcu_read_unlock();

	return (void *)vaddr;
}

static phys_addr_t _gpool_virt_to_phys(const volatile void *vaddr)
{
	BUG_ON(!gpool);

	return gen_pool_virt_to_phys(gpool, (uintptr_t)vaddr);
}

static struct nbl_shm_ops _gpool_ops __maybe_unused = {
	.alloc = _gpool_alloc,
	.free = _gpool_free,
	.virt_to_phys = _gpool_virt_to_phys,
	.phys_to_virt = _gpool_phys_to_virt,
};

///////////////////////////////////////////////////////////////////////////////

void *nbl_shm_alloc(size_t size, gfp_t gfp)
{
	return _shm_ops.alloc(size, gfp);
}
EXPORT_SYMBOL(nbl_shm_alloc);

void nbl_shm_free(void *vaddr, size_t size)
{
	_shm_ops.free(vaddr, size);
}
EXPORT_SYMBOL(nbl_shm_free);

void *nbl_shm_phys_to_virt(unsigned long paddr)
{
	return _shm_ops.phys_to_virt(paddr);
}
EXPORT_SYMBOL(nbl_shm_phys_to_virt);

phys_addr_t nbl_shm_virt_to_phys(void *vaddr)
{
	return _shm_ops.virt_to_phys(vaddr);
}
EXPORT_SYMBOL(nbl_shm_virt_to_phys);
