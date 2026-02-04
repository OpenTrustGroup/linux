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

#ifndef _NBL_IRQ_DELAY_H_
#define _NBL_IRQ_DELAY_H_

#define IRQ_DELAY_MAX_RECS       10240

// ring buffer irq layout:
// ---------------------------------------------------------------
// | trace_irq_delay_ringbuf_hdr | rec[0] | rec[1] | ...... | rec[n] |
// ---------------------------------------------------------------
//                           | <-             size            -> |
// | <-      hdr_size     -> |
//                           | <-           write_pos         -> |
typedef struct {
    uint64_t write_pos;
    uint64_t read_pos;
    size_t hdr_size;
    size_t size;
    size_t rec_size;
    uint32_t rec_cnt;
    bool enable;
    uint8_t reserved[3];
} irq_delay_ringbuf_hdr_t;

typedef struct {
    uint64_t flag : 1;
    uint64_t vector : 13;
    // 50 bits timestamp is big enough, for 13MHz tick, it can record
    // for more than 5 years.
    uint64_t timestamp : 50;
} irq_rec_t;

// trace vcpu irq entey/inject timestamp
typedef struct {
    irq_delay_ringbuf_hdr_t rb_hdr;
    irq_rec_t rec[IRQ_DELAY_MAX_RECS];
} irq_delay_buf_t;

extern int start_record_irq_delay(void);
extern int stop_record_irq_delay(void);
irq_delay_buf_t* get_irq_delay_buf(void);

#endif