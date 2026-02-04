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

#include <linux/version.h>
#include <crypto/hash.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
#include <crypto/sha.h>
#else
#include <crypto/sha2.h>
#endif
#include <linux/random.h>
#include <linux/scatterlist.h>

#include <linux/err.h>
#include <linux/kthread.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/uio.h>

#include "nebula-rpcmgr.h"
#include "nebula-queue.h"
#include "nebula-rpc-proto.h"
#include "nebula-rpc-transport.h"
#include "nebula-status.h"

#include "nebula-unittest.h"

#define _ECHO_CMD NBL_KRPC_CALL(0x1)
#define _BULK_CMD NBL_KRPC_CALL(0x2)

static const size_t kMegaBytes = 1u << 20;

struct context {
	struct nbl_queue *queue;
	struct completion reply_comp;
	void *reply;
	size_t reply_size;
	struct rpc_transport transport;
	struct nbl_rpcmgr *mgr;
};

static int get_sha256_digest(const void *buf, size_t len, void *digest)
{
	int ret;
	struct crypto_shash *alg;
	struct shash_desc *desc;
	const char *driver = "sha256";

	alg = crypto_alloc_shash(driver, CRYPTO_ALG_TYPE_SHASH, 0);
	if (IS_ERR(alg)) {
		pr_err("Failed to alloc shash %s: %ld\n", driver, PTR_ERR(alg));
		return PTR_ERR(alg);
	}

	desc = kzalloc(sizeof(*desc) + crypto_shash_descsize(alg), GFP_KERNEL);
	if (!desc) {
		pr_err("Failed to alloc memory\n");
		ret = -ENOMEM;
		goto err_alloc;
	}

	desc->tfm = alg;

	ret = crypto_shash_digest(desc, buf, len, digest);
	if (ret) {
		pr_err("Failed to digest: %d\n", ret);
		goto err_digest;
	}

err_digest:
	kfree(desc);
err_alloc:
	crypto_free_shash(alg);

	return ret;
}

static int _mock_rpc_recv(struct rpc_transport *transport, void *buf,
			  size_t len)
{
	struct iovec *iov;
	struct context *ctx = transport->priv;
	struct nbl_queue *queue = ctx->queue;

	iov = nbl_queue_pop(queue, /*wait=*/true);
	if (IS_ERR(iov))
		return PTR_ERR(iov);

	len = min(len, iov->iov_len);
	memcpy(buf, iov->iov_base, len);
	return len;
}

static int _mock_rpc_send(struct rpc_transport *transport, const void *buf,
			  size_t len)
{
	struct context *ctx = transport->priv;
	const struct rpc_message_t *msg = buf;
	const void *payload;
	size_t payload_size, new_reply_size;

	payload = msg->payload;
	payload_size = len - sizeof(*msg);

	if (payload_size) {
		/* Append payload to reply */
		new_reply_size = ctx->reply_size + payload_size;
		ctx->reply = krealloc(ctx->reply, new_reply_size, GFP_KERNEL);
		memcpy(ctx->reply + ctx->reply_size, payload, payload_size);
		ctx->reply_size = new_reply_size;
	}

	if (msg->header.flags & RPC_FLAG_STOP_BIT)
		complete(&ctx->reply_comp);

	return len;
}

static void _context_create(struct context *ctx)
{
	init_completion(&ctx->reply_comp);
	ctx->transport.send = _mock_rpc_send;
	ctx->transport.recv = _mock_rpc_recv;
	ctx->transport.priv = ctx;
	ctx->reply = NULL;
	ctx->reply_size = 0;
	ctx->queue = nbl_queue_init();
	ctx->mgr = nbl_rpcmgr_init(&ctx->transport);
}

static void _context_destroy(struct context *ctx)
{
	if (ctx->mgr)
		nbl_rpcmgr_delref(ctx->mgr);
	if (ctx->queue)
		nbl_queue_delref(ctx->queue);
	if (ctx->reply)
		kfree(ctx->reply);
}

static bool rpcmgr_init_test(void)
{
	struct rpc_transport _empty = {};
	struct rpc_transport _recv_only = { .recv = _mock_rpc_recv };
	struct rpc_transport _send_only = { .send = _mock_rpc_send };

	BEGIN_TEST;

	ASSERT_EQ(-EINVAL, PTR_ERR(nbl_rpcmgr_init(NULL)), "");
	ASSERT_EQ(-EINVAL, PTR_ERR(nbl_rpcmgr_init(&_empty)), "");
	ASSERT_EQ(-EINVAL, PTR_ERR(nbl_rpcmgr_init(&_recv_only)), "");
	ASSERT_EQ(-EINVAL, PTR_ERR(nbl_rpcmgr_init(&_send_only)), "");

	END_TEST;
}

static int _dummy_rpc_recv(struct rpc_transport *transport, void *buf,
			   size_t len)
{
	wait_queue_head_t waitq;

	init_waitqueue_head(&waitq);
	if (wait_event_interruptible(waitq, kthread_should_stop()))
		return -ERESTARTSYS;
	return -ESHUTDOWN;
}

static int _dummy_rpc_send(struct rpc_transport *transport, const void *buf,
			   size_t len)
{
	return len;
}

static bool rpcmgr_add_del_cb_test(void)
{
	int i;
	const int kNumCallbacks = 1024;
	struct nbl_rpcmgr *mgr;
	struct rpc_transport transport = {
		.recv = _dummy_rpc_recv,
		.send = _dummy_rpc_send,
	};

	BEGIN_TEST;

	mgr = nbl_rpcmgr_init(&transport);
	ASSERT_FALSE(IS_ERR(mgr), "")

	for (i = 0; i < kNumCallbacks; ++i) {
		ASSERT_EQ(0, nbl_rpcmgr_add_cb(mgr, i, NULL), "");
		ASSERT_EQ(-EEXIST, nbl_rpcmgr_add_cb(mgr, i, NULL), "");
	}

	for (i = 0; i < kNumCallbacks; ++i) {
		ASSERT_EQ(0, nbl_rpcmgr_del_cb(mgr, i), "");
		ASSERT_EQ(-ENOENT, nbl_rpcmgr_del_cb(mgr, i), "");
	}

	nbl_rpcmgr_delref(mgr);

	END_TEST;
}

static nbl_status _echo_handler(uint32_t cmd, const void *in, size_t in_size,
				void **out, size_t *out_size)
{
	void *reply;

	reply = kmalloc(in_size, GFP_KERNEL);
	if (!reply)
		return kNblErrNoMemory;

	memcpy(reply, in, in_size);

	*out = reply;
	*out_size = in_size;

	return kNblOk;
}

static bool rpcmgr_echo_test(void)
{
	struct context ctx;
	struct iovec iov;
	size_t msgsz;
	struct rpc_message_t *msg;
	const size_t payload_size = 64;

	BEGIN_TEST;

	_context_create(&ctx);
	ASSERT_FALSE(IS_ERR(ctx.queue), "");
	ASSERT_FALSE(IS_ERR(ctx.mgr), "");

	ASSERT_EQ(0, nbl_rpcmgr_add_cb(ctx.mgr, _ECHO_CMD, _echo_handler), "");

	msgsz = sizeof(*msg) + payload_size;
	msg = kzalloc(msgsz, GFP_KERNEL);
	ASSERT_NONNULL(msg, "");

	msg->header.txid = 1;
	msg->header.ordinal = _ECHO_CMD;
	msg->header.flags |= RPC_FLAG_STOP_BIT;
	get_random_bytes(msg->payload, payload_size);

	iov.iov_base = msg;
	iov.iov_len = msgsz;

	ASSERT_EQ(0, nbl_queue_push(ctx.queue, &iov), "");

	wait_for_completion(&ctx.reply_comp);

	ASSERT_EQ(payload_size, ctx.reply_size, "");
	ASSERT_BYTES_EQ(msg->payload, ctx.reply, payload_size, "");

	kfree(msg);
	_context_destroy(&ctx);

	END_TEST;
}

static nbl_status _bulk_reply_handler(uint32_t cmd, const void *in,
				      size_t in_size, void **out,
				      size_t *out_size)
{
	struct reply {
		u8 digest[SHA256_DIGEST_SIZE];
		u8 data[];
	} * reply;
	size_t data_size = kMegaBytes;
	size_t reply_size;

	reply_size = sizeof(*reply) + data_size;
	reply = vmalloc(reply_size);
	if (!reply)
		return kNblErrNoMemory;

	get_random_bytes(reply->data, data_size);
	get_sha256_digest(reply->data, data_size, reply->digest);

	*out = reply;
	*out_size = reply_size;

	return kNblOk;
}

static bool rpcmgr_bulk_reply_test(void)
{
	struct context ctx;
	struct iovec iov;
	struct rpc_message_t msg;
	struct reply {
		u8 digest[SHA256_DIGEST_SIZE];
		u8 data[];
	} * reply;
	size_t data_size = kMegaBytes;
	size_t reply_size;
	u8 digest[SHA256_DIGEST_SIZE];

	BEGIN_TEST;

	_context_create(&ctx);
	ASSERT_FALSE(IS_ERR(ctx.queue), "");
	ASSERT_FALSE(IS_ERR(ctx.mgr), "");

	ASSERT_EQ(0, nbl_rpcmgr_add_cb(ctx.mgr, _BULK_CMD, _bulk_reply_handler),
		  "");

	msg.header.txid = 1;
	msg.header.ordinal = _BULK_CMD;
	msg.header.flags |= RPC_FLAG_STOP_BIT;
	iov.iov_base = &msg;
	iov.iov_len = sizeof(msg);

	ASSERT_EQ(0, nbl_queue_push(ctx.queue, &iov), "");

	wait_for_completion(&ctx.reply_comp);

	reply = ctx.reply;
	reply_size = sizeof(*reply) + data_size;

	ASSERT_EQ(reply_size, ctx.reply_size, "");

	get_sha256_digest(reply->data, data_size, digest);
	ASSERT_BYTES_EQ(digest, reply->digest, SHA256_DIGEST_SIZE, "");

	_context_destroy(&ctx);

	END_TEST;
}

UNITTEST_START_TESTCASE(rpcmgr)
UNITTEST(rpcmgr_init_test)
UNITTEST(rpcmgr_add_del_cb_test)
UNITTEST(rpcmgr_echo_test)
UNITTEST(rpcmgr_bulk_reply_test)
UNITTEST_END_TESTCASE(rpcmgr, "RCS manager unittests");
