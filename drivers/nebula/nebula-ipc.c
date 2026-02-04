/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright 2021 GoldenRiver Technologies Co., Ltd.
 * Copyright (C) 2015 Google, Inc.
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

#define pr_fmt(fmt) "nebula-ipc: " fmt

#include <linux/completion.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/idr.h>
#include <linux/kref.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/nebula/nebula_ipc.h>

#define REPLY_TIMEOUT_MS 5000
#define TXBUF_TIMEOUT_MS 15000

#define MIN_CONTEXT_ID 1024
#define MAX_CONTEXT_ID 0x7FFFFFFF

#define MAX_NAME_LEN 256

static DEFINE_MUTEX(srv_idr_lock);
static DEFINE_IDR(srv_idr);

enum tipc_chan_state {
	TIPC_DISCONNECTED = 0,
	TIPC_CONNECTING,
	TIPC_CONNECTED,
	TIPC_STALE,
	TIPC_UNKNOWN,
};

struct context {
	int state;
	struct mutex lock;
	struct kref refcount;
	struct tipc_chan *chan;
	struct completion reply_comp;
	wait_queue_head_t readq;
	struct list_head rx_msg_queue;
	int srv_id;
	char srv_name[MAX_NAME_LEN];
};

static struct context *find_context_by_id(int srv_id)
{
	struct context *ctx;

	mutex_lock(&srv_idr_lock);
	ctx = idr_find(&srv_idr, srv_id);
	mutex_unlock(&srv_idr_lock);
	return ctx;
}

static int alloc_srv_id(struct context *ctx)
{
	int ret;

	mutex_lock(&srv_idr_lock);
	ret = idr_alloc_cyclic(&srv_idr, ctx, MIN_CONTEXT_ID, MAX_CONTEXT_ID,
			       GFP_KERNEL);
	mutex_unlock(&srv_idr_lock);
	if (ret > 0) {
		ctx->srv_id = ret;
	}
	return ret;
}

static void free_srv_id(int srv_id)
{
	mutex_lock(&srv_idr_lock);
	idr_remove(&srv_idr, srv_id);
	mutex_unlock(&srv_idr_lock);
}

static void _free_context(struct kref *kref)
{
	struct context *ctx = container_of(kref, struct context, refcount);

	if (ctx->chan) {
		nebula_tipc_chan_shutdown(ctx->chan);
		nebula_tipc_chan_destroy(ctx->chan);
	}

	if (ctx->srv_id) {
		free_srv_id(ctx->srv_id);
	}

	kfree(ctx);
}

static void _free_msg_buf_list(struct tipc_chan *chan, struct list_head *list)
{
	struct tipc_msg_buf *mb = NULL;

	mb = list_first_entry_or_null(list, struct tipc_msg_buf, node);
	while (mb) {
		list_del(&mb->node);
		nebula_tipc_chan_put_rxbuf(chan, mb);
		mb = list_first_entry_or_null(list, struct tipc_msg_buf, node);
	}
}

static int wait_for_reply(struct context *ctx, int timeout)
{
	int ret;

	ret = wait_for_completion_interruptible_timeout(
		&ctx->reply_comp, msecs_to_jiffies(timeout));
	if (ret < 0)
		return ret;

	mutex_lock(&ctx->lock);
	if (!ret) {
		ctx->state = TIPC_STALE;
		ret = -ETIMEDOUT;
	} else {
		if (ctx->state == TIPC_CONNECTED)
			ret = 0;
		else if (ctx->state == TIPC_DISCONNECTED)
			if (!list_empty(&ctx->rx_msg_queue))
				ret = 0;
			else
				ret = -ENOTCONN;
		else
			ret = -EIO;
	}
	mutex_unlock(&ctx->lock);

	return ret;
}

struct tipc_msg_buf *handle_msg(void *data, struct tipc_msg_buf *rxbuf)
{
	struct context *ctx = data;
	struct tipc_msg_buf *newbuf = rxbuf;

	mutex_lock(&ctx->lock);
	if (ctx->state == TIPC_CONNECTED) {
		newbuf = nebula_tipc_chan_get_rxbuf(ctx->chan);
		if (newbuf) {
			list_add_tail(&rxbuf->node, &ctx->rx_msg_queue);
			wake_up_interruptible(&ctx->readq);
		} else {
			pr_err("%s: discard incoming message\n", __func__);
			newbuf = rxbuf;
		}
	}
	mutex_unlock(&ctx->lock);
	return newbuf;
}

static void ctx_connected(struct context *ctx)
{
	mutex_lock(&ctx->lock);
	ctx->state = TIPC_CONNECTED;
	complete(&ctx->reply_comp);
	mutex_unlock(&ctx->lock);
}

static void ctx_disconnected(struct context *ctx)
{
	mutex_lock(&ctx->lock);
	ctx->state = TIPC_DISCONNECTED;
	complete(&ctx->reply_comp);
	wake_up_interruptible_all(&ctx->readq);
	mutex_unlock(&ctx->lock);
}

static void ctx_shutdown(struct context *ctx)
{
	mutex_lock(&ctx->lock);
	ctx->state = TIPC_STALE;
	complete(&ctx->reply_comp);
	wake_up_interruptible_all(&ctx->readq);
	mutex_unlock(&ctx->lock);
}

static void handle_event(void *data, int event)
{
	struct context *ctx = data;

	switch (event) {
	case TIPC_CHANNEL_SHUTDOWN:
		ctx_shutdown(ctx);
		break;
	case TIPC_CHANNEL_DISCONNECTED:
		ctx_disconnected(ctx);
		break;
	case TIPC_CHANNEL_CONNECTED:
		ctx_connected(ctx);
		break;
	default:
		pr_err("%s: unhandled event %d\n", __func__, event);
		break;
	}
}

static struct tipc_chan_ops tipc_ops = {
	.handle_event = handle_event,
	.handle_msg = handle_msg,
};

static int _ipc_connect_sync(struct context *ctx)
{
	int ret;

	ret = nebula_tipc_chan_connect(ctx->chan, ctx->srv_name);
	if (ret)
		return ret;

	ret = wait_for_reply(ctx, REPLY_TIMEOUT_MS);
	if (ret < 0)
		return ret;

	return alloc_srv_id(ctx);
}

int nbl_ipc_connect(const char *srv_name)
{
	int ret;
	struct context *ctx;

	if (!srv_name)
		return -EINVAL;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	strlcpy(ctx->srv_name, srv_name, sizeof(ctx->srv_name));
	ctx->srv_name[sizeof(ctx->srv_name) - 1] = '\0';

	mutex_init(&ctx->lock);
	kref_init(&ctx->refcount);
	init_waitqueue_head(&ctx->readq);
	init_completion(&ctx->reply_comp);
	INIT_LIST_HEAD(&ctx->rx_msg_queue);

	ctx->state = TIPC_DISCONNECTED;

	ctx->chan = nebula_tipc_create_channel(NULL, &tipc_ops, ctx);
	if (IS_ERR(ctx->chan)) {
		ret = PTR_ERR(ctx->chan);
		ctx->chan = NULL;
		goto err_create_channel;
	}

	ret = _ipc_connect_sync(ctx);
	if (ret < 0)
		goto err_sync_connect;

	return ret;

err_sync_connect:
err_create_channel:
	kref_put(&ctx->refcount, _free_context);

	return ret;
}
EXPORT_SYMBOL(nbl_ipc_connect);

int nbl_ipc_close(int srv_id)
{
	struct context *ctx;

	ctx = find_context_by_id(srv_id);
	if (!ctx)
		return -EINVAL;

	ctx_shutdown(ctx);

	_free_msg_buf_list(ctx->chan, &ctx->rx_msg_queue);

	kref_put(&ctx->refcount, _free_context);

	return 0;
}
EXPORT_SYMBOL(nbl_ipc_close);

static inline bool _got_rx_locked(struct context *ctx)
{
	if (ctx->state != TIPC_CONNECTED)
		return true;

	if (!list_empty(&ctx->rx_msg_queue))
		return true;

	return false;
}

ssize_t nbl_ipc_read(int srv_id, void *buf, size_t count)
{
	ssize_t ret;
	size_t len;
	struct tipc_msg_buf *mb;
	struct context *ctx;

	ctx = find_context_by_id(srv_id);
	if (!ctx)
		return -EINVAL;

	mutex_lock(&ctx->lock);

	while (list_empty(&ctx->rx_msg_queue)) {
		if (ctx->state != TIPC_CONNECTED) {
			if (ctx->state == TIPC_CONNECTING)
				ret = -ENOTCONN;
			else if (ctx->state == TIPC_DISCONNECTED)
				ret = -ENOTCONN;
			else if (ctx->state == TIPC_STALE)
				ret = -ESHUTDOWN;
			else
				ret = -EBADFD;
			goto out;
		}

		mutex_unlock(&ctx->lock);

		if (wait_event_interruptible(ctx->readq, _got_rx_locked(ctx)))
			return -ERESTARTSYS;

		mutex_lock(&ctx->lock);
	}

	mb = list_first_entry(&ctx->rx_msg_queue, struct tipc_msg_buf, node);

	len = mb_avail_data(mb);
	if (len > count) {
		ret = -EMSGSIZE;
		goto out;
	}

	memcpy(buf, mb_get_data(mb, len), len);

	ret = len;
	list_del(&mb->node);
	nebula_tipc_chan_put_rxbuf(ctx->chan, mb);

out:
	mutex_unlock(&ctx->lock);
	return ret;
}
EXPORT_SYMBOL(nbl_ipc_read);

ssize_t nbl_ipc_write(int srv_id, const void *buf, size_t count,
		      struct tipc_shmem *shmv, uint shmv_cnt)
{
	int ret;
	size_t len;
	struct tipc_msg_buf *txbuf;
	struct context *ctx;

	ctx = find_context_by_id(srv_id);
	if (!ctx)
		return -EINVAL;

	txbuf = nebula_tipc_chan_get_txbuf_timeout(ctx->chan, TXBUF_TIMEOUT_MS);
	if (IS_ERR(txbuf))
		return PTR_ERR(txbuf);

	len = mb_avail_space(txbuf);
	if (count > mb_avail_space(txbuf)) {
		ret = -EMSGSIZE;
		goto err_out;
	}

	memcpy(mb_put_data(txbuf, count), buf, count);

	ret = nebula_tipc_chan_queue_msg(ctx->chan, txbuf, shmv, shmv_cnt);
	if (ret < 0)
		goto err_out;

	return count;

err_out:
	nebula_tipc_chan_put_txbuf(ctx->chan, txbuf);
	return ret;
}
EXPORT_SYMBOL(nbl_ipc_write);
