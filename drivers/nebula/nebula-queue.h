/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright 2021 GoldenRiver Technologies Co., Ltd.
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

#ifndef __LINUX_NEBULA_QUEUE_H
#define __LINUX_NEBULA_QUEUE_H

#include <linux/kref.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/poll.h>
#include <linux/wait.h>

struct nbl_queue {
	struct mutex lock;
	struct kref refcount;
	wait_queue_head_t pop_waitq;
	struct list_head used_elem_list;
	struct list_head free_elem_list;
	size_t used_elem_cnt;
	size_t free_elem_cnt;
};

struct nbl_queue_elem {
	struct list_head node;
	void *data;
};

extern struct nbl_queue *nbl_queue_init(void);
extern struct nbl_queue *nbl_queue_addref(struct nbl_queue *q);
extern void nbl_queue_delref(struct nbl_queue *q);

extern bool nbl_queue_empty(struct nbl_queue *q);
extern size_t nbl_queue_size(struct nbl_queue *q);

extern int nbl_queue_push(struct nbl_queue *q, void *data);
extern void *nbl_queue_pop(struct nbl_queue *q, bool wait);

extern unsigned int nbl_queue_poll_wait(struct nbl_queue *q, struct file *filp,
					poll_table *wait);

#endif /* __LINUX_NEBULA_QUEUE_H */
