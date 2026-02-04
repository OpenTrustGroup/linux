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

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/err.h>
#include <linux/kthread.h>
#include <linux/slab.h>
#include <linux/sched.h>

#include "nebula-queue.h"

// #define DEBUG

static bool is_kthread(struct task_struct *k)
{
	return k->flags & PF_KTHREAD;
}

struct nbl_queue *nbl_queue_init(void)
{
	struct nbl_queue *q;

	q = kzalloc(sizeof(*q), GFP_KERNEL);
	if (!q)
		return ERR_PTR(-ENOMEM);

	mutex_init(&q->lock);
	kref_init(&q->refcount);
	init_waitqueue_head(&q->pop_waitq);
	INIT_LIST_HEAD(&q->used_elem_list);
	INIT_LIST_HEAD(&q->free_elem_list);

#ifdef DEBUG
	pr_info("%s obj %p\n", __func__, q);
#endif

	return q;
}
EXPORT_SYMBOL(nbl_queue_init);

unsigned int nbl_queue_poll_wait(struct nbl_queue *q, struct file *filp,
				 poll_table *wait)
{
	unsigned int mask = 0;

	mutex_lock(&q->lock);

	poll_wait(filp, &q->pop_waitq, wait);

	/* Writes always succeed for now */
	mask |= POLLOUT | POLLWRNORM;

	if (!list_empty(&q->used_elem_list))
		mask |= POLLIN | POLLRDNORM;

	mutex_unlock(&q->lock);
	return mask;
}
EXPORT_SYMBOL(nbl_queue_poll_wait);

bool nbl_queue_empty(struct nbl_queue *q)
{
	return list_empty(&q->used_elem_list);
}
EXPORT_SYMBOL(nbl_queue_empty);

size_t nbl_queue_size(struct nbl_queue *q)
{
	return q->used_elem_cnt;
}
EXPORT_SYMBOL(nbl_queue_size);

static void _free_nbl_queue(struct kref *kref)
{
	struct nbl_queue_elem *elem, *tmp;
	struct nbl_queue *q = container_of(kref, struct nbl_queue, refcount);

#ifdef DEBUG
	pr_info("%s obj %p\n", __func__, q);
#endif

	list_for_each_entry_safe (elem, tmp, &q->used_elem_list, node) {
#ifdef DEBUG
		pr_info("%s used elem %p --\n", __func__, elem);
#endif
		list_del(&elem->node);
		kfree(elem);
	}

	list_for_each_entry_safe (elem, tmp, &q->free_elem_list, node) {
#ifdef DEBUG
		pr_info("%s free elem %p --\n", __func__, elem);
#endif
		list_del(&elem->node);
		kfree(elem);
	}

	kfree(q);
}

struct nbl_queue *nbl_queue_addref(struct nbl_queue *q)
{
	kref_get(&q->refcount);
	return q;
}
EXPORT_SYMBOL(nbl_queue_addref);

void nbl_queue_delref(struct nbl_queue *q)
{
	kref_put(&q->refcount, _free_nbl_queue);
}
EXPORT_SYMBOL(nbl_queue_delref);

static struct nbl_queue_elem *_get_elem_locked(struct nbl_queue *q)
{
	struct nbl_queue_elem *elem;

	if (q->free_elem_cnt) {
		elem = list_first_entry(&q->free_elem_list,
					struct nbl_queue_elem, node);
		list_del(&elem->node);
		q->free_elem_cnt--;
	} else {
		elem = kzalloc(sizeof(*elem), GFP_KERNEL);
		if (!elem)
			return ERR_PTR(-ENOMEM);

#ifdef DEBUG
		pr_info("%s elem %p ++\n", __func__, elem);
#endif
	}
	return elem;
}

static void _put_elem_locked(struct nbl_queue *q, struct nbl_queue_elem *e)
{
	list_add_tail(&e->node, &q->free_elem_list);
	q->free_elem_cnt++;
}

int nbl_queue_push(struct nbl_queue *q, void *data)
{
	int ret;
	struct nbl_queue_elem *elem;

	mutex_lock(&q->lock);

	elem = _get_elem_locked(q);
	if (IS_ERR(elem)) {
		ret = PTR_ERR(elem);
		goto out;
	}

	elem->data = data;

	list_add_tail(&elem->node, &q->used_elem_list);
	q->used_elem_cnt++;
	wake_up_interruptible(&q->pop_waitq);
	ret = 0;

out:
	mutex_unlock(&q->lock);
	return ret;
}
EXPORT_SYMBOL(nbl_queue_push);

static bool _got_elem_locked(struct nbl_queue *q)
{
	if (is_kthread(current) && kthread_should_stop())
		return true;

	if (!list_empty(&q->used_elem_list))
		return true;

	return false;
}

void *nbl_queue_pop(struct nbl_queue *q, bool wait)
{
	struct nbl_queue_elem *elem;
	void *data = NULL;

	mutex_lock(&q->lock);

	while (list_empty(&q->used_elem_list)) {
		if (is_kthread(current) && kthread_should_stop()) {
			data = ERR_PTR(-ESHUTDOWN);
			goto out;
		}

		mutex_unlock(&q->lock);

		if (!wait)
			return ERR_PTR(-EAGAIN);

		if (wait_event_interruptible(q->pop_waitq, _got_elem_locked(q)))
			return ERR_PTR(-ERESTARTSYS);

		mutex_lock(&q->lock);
	}

	elem = list_first_entry(&q->used_elem_list, struct nbl_queue_elem,
				node);
	list_del(&elem->node);

	data = elem->data;
	q->used_elem_cnt--;
	_put_elem_locked(q, elem);

out:
	mutex_unlock(&q->lock);
	return data;
}
EXPORT_SYMBOL(nbl_queue_pop);
