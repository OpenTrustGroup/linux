/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _TRUSTY_LOG_H_
#define _TRUSTY_LOG_H_

/*
 * Ring buffer that supports one secure producer thread and one
 * linux side consumer thread.
 */
struct log_rb {
	volatile uint32_t alloc;
	volatile uint32_t put;
	uint32_t sz;
	volatile char data[];
} __packed;

#define TRUSTY_LOG_API_VERSION	1

#endif
