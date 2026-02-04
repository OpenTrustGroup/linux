/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2019 GoldenRiver Technologies, Inc.
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
#include <linux/cpu_pm.h>

#include <linux/arm-smccc.h>
#include <linux/nebula/smcall.h>

#define NO_TIMER 0

#ifdef CONFIG_CPU_PM
static int trusty_cpu_pm_notifier(struct notifier_block *self,
                                  unsigned long cmd, void *v)
{
	struct arm_smccc_res res;
	unsigned long a7 = SMC_TEE_SECURE_ID << 16;

	switch (cmd) {
	case CPU_PM_ENTER: {
		long time_left_ns;

		arm_smccc_smc(SMC_FC64_GET_TIMER, 0, 0, 0, 0, 0, 0, a7, &res);
		time_left_ns = res.a0;

		//-1 : SMC_FC64_GET_TIMER not implement
		if(time_left_ns == NO_TIMER || time_left_ns == -1) {
			break;
		}
		return NOTIFY_OK;
	}
	case CPU_PM_EXIT:
		break;
	default:
		return NOTIFY_DONE;
	}
	return NOTIFY_OK;
}

static struct notifier_block trusty_cpu_pm_notifier_block = {
	.notifier_call = trusty_cpu_pm_notifier,
};

static void __init __trusty_pm_init(void)
{
	cpu_pm_register_notifier(&trusty_cpu_pm_notifier_block);
}

#else
static inline void __trusty_pm_init(void) { }
#endif /* CONFIG_CPU_PM */

int __init trusty_pm_init(void)
{
	__trusty_pm_init();

	return 0;
}
