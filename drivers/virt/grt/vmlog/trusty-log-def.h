/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _TRUSTY_LOG_DEF_H_
#define _TRUSTY_LOG_DEF_H_

#include "user-log-dev.h"

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

#define TRUSTY_LOG_SIZE (PAGE_SIZE * 32)
#define TRUSTY_LINE_BUFFER_SIZE 256

struct trusty_log_state {
	struct device *dev;
	struct device *trusty_dev;

	/*
	 * This lock is here to ensure only one consumer will read
	 * from the log ring buffer at a time.
	 */
	spinlock_t fast_lock;  // for handling logs in IRQ context
	struct mutex lock;
	struct log_rb *log;
	uint32_t get;

	struct page *log_pages;

	struct notifier_block call_notifier;
	struct notifier_block panic_notifier;
	char line_buffer[TRUSTY_LINE_BUFFER_SIZE];

	struct notifier_block vm_state_notifier;
	char log_prefix[TRUSTY_LINE_BUFFER_SIZE];
	uint32_t vmid;
	atomic_t enabled;
	ktime_t timer_disable_deadline;
	struct timer_list timer;
	struct user_log_state *usr_log_state;

	struct workqueue_struct	*dump_log_wq;
	struct work_struct	dump_log_worker;
};

#endif
