/*
 * Copyright (C) 2018 Open Trust Group
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
#ifndef __LINUX_TRUSTY_SHM_H
#define __LINUX_TRUSTY_SHM_H

void *trusty_alloc_shm(size_t size, phys_addr_t *out_pa);
void trusty_free_shm(void *virt, size_t size);
int trusty_init_shm_pool(struct device *dev);
void trusty_destroy_shm_pool(struct device *dev);

#endif
