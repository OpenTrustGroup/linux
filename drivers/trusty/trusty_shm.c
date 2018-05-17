/*
 * Copyright (c) 2018, Open Trust Group
 * Copyright (c) 2015, Linaro Limited
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

#include <linux/io.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/tee_drv.h>
#include <linux/trusty/trusty.h>
#include <linux/trusty/smcall.h>
#include "shm_pool.h"

struct trusty_shm_state {
	struct tee_shm_pool_mgr *pool_mgr;
	void *shm_va;
	struct device *dev;
};

struct trusty_shm_state *shm_state;

void *trusty_alloc_shm(size_t size, phys_addr_t *out_pa)
{
	struct tee_shm_pool_mgr *pool_mgr;
	struct tee_shm s;
	int rc;

	BUG_ON(!size);
	BUG_ON(!shm_state);
	BUG_ON(!shm_state->pool_mgr);

	s.kaddr = NULL;
	s.paddr = (phys_addr_t)0;
	s.size = 0;

	pool_mgr = shm_state->pool_mgr;
	rc = pool_mgr->ops->alloc(pool_mgr, &s, size);
	if (rc < 0) {
		dev_err(shm_state->dev, "alloc shm failed, rc(%d)\n", rc);
		return NULL;
	}

	if (out_pa)
		*out_pa = s.paddr;

	return s.kaddr;
}
EXPORT_SYMBOL_GPL(trusty_alloc_shm);

void trusty_free_shm(void *virt, size_t size)
{
	struct tee_shm s;

	BUG_ON(!virt);
	BUG_ON(!shm_state);
	BUG_ON(!shm_state->pool_mgr);

	s.kaddr = virt;
	s.size = size;

	shm_state->pool_mgr->ops->free(shm_state->pool_mgr, &s);
}
EXPORT_SYMBOL_GPL(trusty_free_shm);

static struct tee_shm_pool_mgr *
trusty_prepare_shm_pool(void **shm_va, struct device *dev)
{
	long shm_pa;
	long shm_size;
	long shm_use_cache;
	unsigned long vaddr;
	phys_addr_t paddr;
	size_t size;
	phys_addr_t begin;
	phys_addr_t end;
	void *va = 0;
	void *rc = NULL;
	int tee_support_static_shm = 0;

	shm_pa = trusty_fast_call32(dev, SMC_FC_GET_STATIC_SHM_CONFIG,
			TRUSTY_SHM_PA, 0, 0);
	if (shm_pa < 0)
		goto ignore_static_shm_config;

	shm_size = trusty_fast_call32(dev, SMC_FC_GET_STATIC_SHM_CONFIG,
			TRUSTY_SHM_SIZE, 0, 0);
	if (shm_size < 0)
		goto ignore_static_shm_config;

	shm_use_cache = trusty_fast_call32(dev, SMC_FC_GET_STATIC_SHM_CONFIG,
			TRUSTY_SHM_USE_CACHE, 0, 0);
	if (shm_use_cache < 0)
		goto ignore_static_shm_config;

	if (!shm_use_cache) {
		dev_err(dev, "only normal cached shared memory supported\n");
		return ERR_PTR(-EINVAL);
	}

	tee_support_static_shm = 1;

	begin = roundup(shm_pa, PAGE_SIZE);
	end = rounddown(shm_pa + shm_size, PAGE_SIZE);
	paddr = begin;
	size = end - begin;

	va = memremap(paddr, size, MEMREMAP_WB);
	if (!va) {
		dev_err(dev, "shared memory ioremap failed\n");
		return ERR_PTR(-EINVAL);
	}
	vaddr = (unsigned long)va;

ignore_static_shm_config:
	/*
	 * If TEE does not support static SHM, we will use dynamic shm pool
	 * for private shm
	 */
	if (!tee_support_static_shm) {
		dev_info(dev, "create dynamic shm pool mgr\n");
		rc = trusty_shm_pool_alloc_pages();
		if (IS_ERR(rc))
			goto err_memunmap;
	} else {
		dev_info(dev, "create static shm pool mgr: pa 0x%llx size 0x%lx\n",
				paddr, size);
		rc = tee_shm_pool_mgr_alloc_res_mem(vaddr, paddr, size,
						    3 /* 8 bytes aligned */);
		if (IS_ERR(rc))
			goto err_memunmap;
	}

	*shm_va = va;
	return rc;

err_memunmap:
	if (va)
		memunmap(va);
	return rc;
}

int trusty_init_shm_pool(struct device *dev)
{
	struct tee_shm_pool_mgr *pool_mgr;
	void *shm_va;
	int rc = 0;

	shm_state = kzalloc(sizeof(*shm_state), GFP_KERNEL);
	if (!shm_state)
		return -ENOMEM;

	pool_mgr = trusty_prepare_shm_pool(&shm_va, dev);
	if (IS_ERR(pool_mgr)) {
		rc = PTR_ERR(pool_mgr);
		goto err_shm_pool;
	}

	shm_state->pool_mgr = pool_mgr;
	shm_state->shm_va = shm_va;
	shm_state->dev = dev;

	return 0;

err_shm_pool:
	kfree(shm_state);
	return rc;
}

void trusty_destroy_shm_pool(struct device *dev)
{
	tee_shm_pool_mgr_destroy(shm_state->pool_mgr);
	if (shm_state->shm_va)
		memunmap(shm_state->shm_va);
	kfree(shm_state);
}

