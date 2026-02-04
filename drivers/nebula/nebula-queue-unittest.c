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
#include <linux/debugfs.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/uio.h>
#include <linux/types.h>
#include <linux/delay.h>
#include <linux/random.h>
#include <linux/kthread.h>

#include "nebula-unittest.h"
#include "nebula-queue.h"

#define KNUMTHREADS 10

static bool queue_basic_test(void)
{
	long i;
	struct nbl_queue *queue;
	const long kNumElements = 1000;

	BEGIN_TEST;

	queue = nbl_queue_init();
	ASSERT_FALSE(IS_ERR(queue), "");

	ASSERT_TRUE(nbl_queue_empty(queue), "");
	ASSERT_EQ(0, nbl_queue_size(queue), "");

	for (i = 0; i < kNumElements; ++i) {
		ASSERT_EQ(0, nbl_queue_push(queue, (void *)i), "");
		ASSERT_EQ(i + 1, nbl_queue_size(queue), "");
	}

	for (i = 0; i < kNumElements; ++i) {
		ASSERT_EQ(i, (long)nbl_queue_pop(queue, /*wait=*/true), "");
		ASSERT_EQ(kNumElements - i - 1, nbl_queue_size(queue), "");
	}

	ASSERT_TRUE(nbl_queue_empty(queue), "");
	ASSERT_EQ(0, nbl_queue_size(queue), "");

	nbl_queue_delref(queue);

	END_TEST;
}

struct _thread_data {
	struct task_struct *task;
	struct nbl_queue *queue;
	struct completion pop_done;
	int value;
	int error;
};

/* Simulate 10 ~ 20 ms workload */
void simulate_workload(void)
{
	int workload_ms;

	get_random_bytes(&workload_ms, sizeof(workload_ms));
	workload_ms = workload_ms % 10 + 10;
	msleep(workload_ms);
}

static int _thread_func(void *arg)
{
	struct _thread_data *data = arg;

	data->value = (long)nbl_queue_pop(data->queue, /*wait=*/true);

	simulate_workload();
	complete(&data->pop_done);

	data->error = (long)nbl_queue_pop(data->queue, /*wait=*/true);

	nbl_queue_delref(data->queue);
	return 0;
}

static bool queue_thread_test(void)
{
	long i, sum = 0, val = 0;
	struct nbl_queue *queue;
	struct _thread_data *data[KNUMTHREADS];

	BEGIN_TEST;

	queue = nbl_queue_init();
	ASSERT_FALSE(IS_ERR(queue), "");

	for (i = 0; i < KNUMTHREADS; ++i) {
		data[i] = kzalloc(sizeof(*data[i]), GFP_KERNEL);
		ASSERT_NONNULL(data[i], "");
		init_completion(&data[i]->pop_done);
		data[i]->queue = nbl_queue_addref(queue);
		data[i]->task =
			kthread_run(_thread_func, data[i], "qthr/%ld", i);
		ASSERT_FALSE(IS_ERR(data[i]->task), "");
	}

	for (i = 0; i < KNUMTHREADS; ++i) {
		val = i + 1;
		sum += val;
		ASSERT_EQ(0, nbl_queue_push(queue, (void *)val), "");
	}

	for (i = 0; i < KNUMTHREADS; ++i) {
		wait_for_completion(&data[i]->pop_done);
	}

	for (i = 0; i < KNUMTHREADS; ++i) {
		ASSERT_EQ(0, kthread_stop(data[i]->task), "");
		ASSERT_EQ(-ESHUTDOWN, data[i]->error, "");
		ASSERT_GT(data[i]->value, 0, "");
		sum -= data[i]->value;
		kfree(data[i]);
	}

	ASSERT_EQ(0, sum, "");

	nbl_queue_delref(queue);

	END_TEST;
}

struct _pc_data {
	struct nbl_queue *queue;
	int num_iterations;
	struct completion done;
};

struct _product {
	uint32_t params[4];
} __attribute__((packed));

static int _consumer_func(void *arg)
{
	struct _pc_data *data = arg;
	int num_iterations = data->num_iterations;
	struct iovec *iovec;
	struct _product *product;

	while (num_iterations--) {
		iovec = nbl_queue_pop(data->queue, /*wait=*/true);
		BUG_ON(IS_ERR(iovec));
		BUG_ON(iovec->iov_len != sizeof(*product));

		product = iovec->iov_base;
		BUG_ON(product->params[0] != num_iterations);
		BUG_ON(product->params[1] != num_iterations);
		BUG_ON(product->params[2] != num_iterations);
		BUG_ON(product->params[3] != num_iterations);

		kfree(iovec->iov_base);
		kfree(iovec);
	}
	complete(&data->done);
	return 0;
}

static int _producer_func(void *arg)
{
	struct _pc_data *data = arg;
	int num_iterations = data->num_iterations;
	struct iovec *iovec;
	struct _product *product;

	while (num_iterations--) {
		product = kmalloc(sizeof(*product), GFP_KERNEL);
		BUG_ON(!product);

		product->params[0] = num_iterations;
		product->params[1] = num_iterations;
		product->params[2] = num_iterations;
		product->params[3] = num_iterations;

		iovec = kzalloc(sizeof(*iovec), GFP_KERNEL);
		BUG_ON(!iovec);

		iovec->iov_base = product;
		iovec->iov_len = sizeof(*product);
		BUG_ON(nbl_queue_push(data->queue, iovec));
	}
	complete(&data->done);
	return 0;
}

static bool queue_producer_consumer_test(void)
{
	struct task_struct *producer, *consumer;
	struct _pc_data data;

	BEGIN_TEST;

	data.queue = nbl_queue_init();
	ASSERT_FALSE(IS_ERR(data.queue), "");

	init_completion(&data.done);
	data.num_iterations = 10000;

	consumer = kthread_run(_consumer_func, &data, "consumer");
	ASSERT_FALSE(IS_ERR(consumer), "");

	producer = kthread_run(_producer_func, &data, "producer");
	ASSERT_FALSE(IS_ERR(producer), "");

	// one for consumer, one for producer
	wait_for_completion(&data.done);
	wait_for_completion(&data.done);

	ASSERT_EQ(0, kthread_stop(consumer), "");
	ASSERT_EQ(0, kthread_stop(producer), "");

	nbl_queue_delref(data.queue);

	END_TEST;
}

UNITTEST_START_TESTCASE(queue)
UNITTEST(queue_basic_test)
UNITTEST(queue_thread_test)
UNITTEST(queue_producer_consumer_test)
UNITTEST_END_TESTCASE(queue, "Blocking queue unittests");
