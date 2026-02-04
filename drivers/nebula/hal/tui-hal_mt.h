/*
 * Copyright 2019 GoldenRiver Technologies Co., Ltd. All rights reserved.
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

#ifndef __TUI_HAL_MT__H__
#define __TUI_HAL_MT__H__

#include <linux/version.h>

#if defined(CONFIG_MTK_PLATFORM)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)
#include <trusted_mem/ssmr/memory_ssmr.h>
#else
#include <memory-ssvp/memory_ssmr.h>
#endif
#else
#define SSMR_FEAT_TUI (0)
#endif /* !CONFIG_MTK_PLATFORM */

extern int i2c_tui_enable_clock(int id);
extern int i2c_tui_disable_clock(int id);
extern int tui_region_offline(phys_addr_t *pa, unsigned long *size);
extern int tui_region_online(void);
extern int display_enter_tui(void);
extern int display_exit_tui(void);
extern int ssmr_offline(phys_addr_t *pa, unsigned long *size, bool is_64bit,
			unsigned int feat);
extern int ssmr_online(unsigned int feat);

// mtk_mcdi_governor.h
extern bool is_mcdi_working(void);
extern void set_mcdi_enable_status(bool enabled);

int disp_smmu_map(phys_addr_t pa_start, unsigned int size, unsigned long *mva);
int disp_smmu_unmap(phys_addr_t mva);

#endif /* __TUI_HAL_MT__H__ */
