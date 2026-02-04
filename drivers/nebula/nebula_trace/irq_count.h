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

#ifndef _NBL_IRQ_COUNT_H_
#define _NBL_IRQ_COUNT_H_

#define NBL_TRACE_MAX_IRQS    1024

typedef struct {
    uint32_t irq_count[NBL_TRACE_MAX_IRQS];
} irq_count_buf_t;

extern irq_count_buf_t* get_irq_count_buf(void);


#endif