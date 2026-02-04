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

#define MAX_BUF_SIZE 128

typedef struct {
	uint8_t src_cpu;
	uint8_t target_cpu;
	uint64_t timestamp;
} send_timestamp_t;

typedef struct {
	uint8_t cpu;
	uint64_t timestamp;
} received_timestamp_t;

typedef struct {
	send_timestamp_t send_ipi[MAX_BUF_SIZE];
	received_timestamp_t receive_ipi[MAX_BUF_SIZE];
	uint32_t snd_point;
	uint32_t rsv_point;
	bool enable;
} cpu_ipi_delay_buf_t;

extern int start_record_cpu_ipi_delay(void);
extern int stop_record_cpu_ipi_delay(void);
cpu_ipi_delay_buf_t *get_cpu_ipi_delay_buf(void);

#endif