/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * Copyright (C) 2013 Google, Inc.
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
#ifndef __LINUX_NEBULA_TRUSTY_H
#define __LINUX_NEBULA_TRUSTY_H

#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/nebula/sm_err.h>
#include <linux/device.h>
#include <linux/pagemap.h>

#define TRUSTY_PROBE_DEFER (0x44425054)

#if defined(CONFIG_NEBULA) || defined(CONFIG_NEBULA_MODULE)
void trusty_probe_late(void);
void trusty_notifier_call(void);
s32 nebula_std_call32(struct device *dev, u32 smcnr, u32 a0, u32 a1, u32 a2);
s32 nebula_fast_call32(struct device *dev, u32 smcnr, u32 a0, u32 a1, u32 a2);
#ifdef CONFIG_64BIT
s64 nebula_fast_call64(struct device *dev, u64 smcnr, u64 a0, u64 a1, u64 a2);
#endif
u64 nebula_dev_secure_id(struct device *dev);
#else
static inline s32 nebula_std_call32(struct device *dev, u32 smcnr,
				    u32 a0, u32 a1, u32 a2)
{
	return SM_ERR_UNDEFINED_SMC;
}
static inline s32 nebula_fast_call32(struct device *dev, u32 smcnr,
				     u32 a0, u32 a1, u32 a2)
{
	return SM_ERR_UNDEFINED_SMC;
}
#ifdef CONFIG_64BIT
static inline s64 nebula_fast_call64(struct device *dev,
				     u64 smcnr, u64 a0, u64 a1, u64 a2)
{
	return SM_ERR_UNDEFINED_SMC;
}
#endif
#endif

struct notifier_block;
enum {
	TRUSTY_CALL_PREPARE,
	TRUSTY_CALL_RETURNED,
	TRUSTY_NOTIFY_LOG = 0x10000,
};
int nebula_call_notifier_register(struct device *dev,
				  struct notifier_block *n);
int nebula_call_notifier_unregister(struct device *dev,
				    struct notifier_block *n);
void nebula_notify_log(struct device *dev);
const char *nebula_version_str_get(struct device *dev);
u32 nebula_get_api_version(struct device *dev);

struct ns_mem_page_info {
	uint64_t attr;
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0)
int nebula_encode_page_info(struct ns_mem_page_info *inf,
			    struct page *page, pgprot_t pgprot);
#else
int nebula_encode_page_info(struct ns_mem_page_info *inf, struct page *page,
			    pgprot_t pgprot, bool writable);
#endif

int nebula_call32_mem_buf(struct device *dev, u32 smcnr,
			  struct page *page,  u32 size,
			  pgprot_t pgprot
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
			  , bool writable
#endif
			  );

struct trusty_nop {
	struct list_head node;
	u32 args[3];
};

static inline void trusty_nop_init(struct trusty_nop *nop,
				   u32 arg0, u32 arg1, u32 arg2) {
	INIT_LIST_HEAD(&nop->node);
	nop->args[0] = arg0;
	nop->args[1] = arg1;
	nop->args[2] = arg2;
}

void nebula_enqueue_nop(struct device *dev, struct trusty_nop *nop);
void nebula_dequeue_nop(struct device *dev, struct trusty_nop *nop);

#endif
