/*
 * Copyright 2024 GoldenRiver Technologies Co., Ltd. All rights reserved.
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

#ifndef _NBL_VCPU_EXIT_H_
#define _NBL_VCPU_EXIT_H_

#include "trace.h"

typedef struct {
    uint32_t reason[NBL_TRACE_VCPU_CNT][NBL_TRACE_VM_CNT];
} wfe_exit_buf_t;

extern int start_record_wfe_exit(void);
extern int stop_record_wfe_exit(void);
extern wfe_exit_buf_t* get_wfe_exit_buf(void);

#endif