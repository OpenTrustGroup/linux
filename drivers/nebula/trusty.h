/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2024 GoldenriverTek, Inc.
 */
#ifndef _TRUSTY_H
#define _TRUSTY_H

#include <linux/types.h>

#include "trusty-smc.h"

struct trusty_state;

struct trusty_work {
	struct trusty_state *ts;
	struct work_struct work;
};

struct trusty_state {
	struct mutex smc_lock;
	struct atomic_notifier_head notifier;
	struct completion cpu_idle_completion;
	char *version_str;
	u32 api_version;
	struct device *dev;
	struct workqueue_struct *nop_wq;
	struct trusty_work __percpu *nop_works;
	struct list_head nop_queue;
	spinlock_t nop_lock; /* protects nop_queue */
	u64 smc_secure_id;
};

#ifdef CONFIG_ARM64
#define SMC_ARG0	   "x0"
#define SMC_ARG1	   "x1"
#define SMC_ARG2	   "x2"
#define SMC_ARG3	   "x3"
#define SMC_ARCH_EXTENSION ""
#define SMC_REGISTERS_TRASHED                                                  \
	"x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", \
		"x15", "x16", "x17"
#else
#define SMC_ARG0	      "r0"
#define SMC_ARG1	      "r1"
#define SMC_ARG2	      "r2"
#define SMC_ARG3	      "r3"
#define SMC_ARCH_EXTENSION    ".arch_extension sec\n"
#define SMC_REGISTERS_TRASHED "ip"
#endif

void nebula_locked_nop_work_func(struct work_struct *work);
void nebula_nop_work_func(struct work_struct *work);
int nebula_init_api_version(struct trusty_state *s, struct device *dev);
void nebula_init_version(struct trusty_state *s, struct device *dev,
			 const struct device_attribute *attr);

#endif /* _TRUSTY_H */
