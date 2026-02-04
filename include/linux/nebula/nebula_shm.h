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

#ifndef __LINUX_NEBULA_SHM_H
#define __LINUX_NEBULA_SHM_H

void *nbl_shm_alloc(size_t size, gfp_t gfp);
void nbl_shm_free(void *virt, size_t size);
phys_addr_t nbl_shm_virt_to_phys(void *vaddr);
void *nbl_shm_phys_to_virt(unsigned long addr);

#endif
