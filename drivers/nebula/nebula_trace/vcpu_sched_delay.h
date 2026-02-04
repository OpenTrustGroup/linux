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

#ifndef _NBL_VCPU_SCHED_DELAY_H_
#define _NBL_VCPU_SCHED_DELAY_H_

#include "trace.h"

typedef struct {
    uint64_t enter_timestamp;
    uint64_t current_delay_time;
    uint64_t max_delay_time;
    uint64_t min_delay_time;
    uint64_t total_delay_time;
    uint64_t thread_id;
    uint64_t run_times;
    uint64_t bRun;
} vcpu_sched_delay_hdr_t;

typedef struct {
    vcpu_sched_delay_hdr_t delay[NBL_TRACE_VM_CNT][NBL_TRACE_VCPU_CNT];
    bool enable;
} vcpu_sched_delay_buf_t;

extern int start_record_vcpu_sched_delay(void);
extern int stop_record_vcpu_sched_delay(void);
vcpu_sched_delay_buf_t* get_vcpu_sched_delay_buf(void);


#endif