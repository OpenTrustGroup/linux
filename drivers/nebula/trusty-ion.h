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

#ifndef _TRUSTY_ION_H_
#define _TRUSTY_ION_H_

#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0) && defined(CONFIG_NEBULA_HAL_MEDIATEK)
#include <mtk_ion/ion_priv.h>
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0) && !defined(CONFIG_NEBULA_HAL_MEDIATEK)
#include <ion/ion_private.h>
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0) && !defined(CONFIG_NEBULA_HAL_MEDIATEK)
#include <ion/ion.h>
struct ion_heap *ion_carveout_heap_create(struct ion_platform_heap *heap_data);
#else
#include <ion/ion_priv.h>
#endif

#include "hal/ion.h"

struct tipc_query_ion_handle_req {
	uint32_t ion_fd;
	uint32_t out_handle;
};

long tipc_query_ion_handle(unsigned long req);

#endif
