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

#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/slab.h>

#include "nebula-rpc-proto.h"
#include "nebula-rpcmgr.h"
#include "nebula-status.h"

struct _saved_msg_list {
	struct list_head head;
	size_t total_payload_size;
};

struct _saved_msg_item_t {
	struct rpc_message_t *msg;
	size_t payload_size;
	struct list_head node;
};

static struct _saved_msg_list *_erase_saved_msg_list(struct nbl_rpcmgr *mgr,
						     uint32_t txid)
{
	struct _saved_msg_list *msg_list;

	mutex_lock(&mgr->lock);
	msg_list = nbl_map_erase(mgr->incomplete_messages, txid);
	mutex_unlock(&mgr->lock);
	return msg_list;
}

static struct _saved_msg_list *_find_saved_msg_list(struct nbl_rpcmgr *mgr,
						    uint32_t txid)
{
	struct _saved_msg_list *msg_list;

	mutex_lock(&mgr->lock);
	msg_list = nbl_map_find(mgr->incomplete_messages, txid);
	mutex_unlock(&mgr->lock);
	return msg_list;
}

static int _emplace_saved_msg_list(struct nbl_rpcmgr *mgr, uint32_t txid,
				   struct _saved_msg_list *msg_list)
{
	int ret;

	mutex_lock(&mgr->lock);
	ret = nbl_map_emplace(mgr->incomplete_messages, txid, msg_list);
	mutex_unlock(&mgr->lock);
	return ret;
}

static ssize_t _send_response(struct nbl_rpcmgr *mgr, uint32_t txid,
			      uint32_t ordinal, const void *buf, size_t len)
{
	ssize_t ret;
	struct rpc_message_t *outmsg = NULL;
	const char *payload;
	size_t payload_size, msgsz, bytes_remaining;

	outmsg = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!outmsg)
		return -ENOMEM;

	payload = buf;
	bytes_remaining = len;
	outmsg->header.txid = txid;
	outmsg->header.ordinal = ordinal;
	outmsg->header.flags |= RPC_FLAG_RESP_BIT;

	do {
		payload_size = min(bytes_remaining, MAX_RPC_PAYLOAD_SIZE);
		if (payload_size == bytes_remaining)
			outmsg->header.flags |= RPC_FLAG_STOP_BIT;

		memcpy(outmsg->payload, payload, payload_size);
		msgsz = RPC_MESSAGE_HEADER_SIZE + payload_size;

		ret = mgr->transport->send(mgr->transport, outmsg, msgsz);
		if (ret != msgsz) {
			pr_err("Failed to send packet: %zd\n", ret);
			goto err_out;
		}

		payload += payload_size;
		bytes_remaining -= payload_size;

	} while (bytes_remaining);

	ret = 0;

err_out:
	kfree(outmsg);
	return ret ? ret : len;
}

static ssize_t _send_err_response(struct nbl_rpcmgr *mgr, uint32_t txid,
				  uint32_t ordinal, int err)
{
	return _send_response(mgr, txid, ordinal, &err, sizeof(err));
}

static int _callback(struct nbl_rpcmgr *mgr, uint32_t ordinal, const void *in,
		     size_t in_size, void **out, size_t *out_size)
{
	rpc_cb cb;

	mutex_lock(&mgr->lock);
	cb = nbl_map_find(mgr->cmds, ordinal);
	mutex_unlock(&mgr->lock);

	if (!cb)
		return kNblErrNotSupported;

	return cb(ordinal, in, in_size, out, out_size);
}

static int _dispatch_msg(struct nbl_rpcmgr *mgr, struct rpc_message_t *msg,
			 size_t payload_size)
{
	int ret;
	void *out_payload = NULL;
	size_t out_payload_size = 0;

	ret = _callback(mgr, msg->header.ordinal, msg->payload, payload_size,
			&out_payload, &out_payload_size);

	/* txid == 0 means no response */
	if (msg->header.txid != 0) {
		// TODO: Wrap rpc_responder_t so that users can decide when to reply.
		if (ret)
			ret = _send_err_response(mgr, msg->header.txid,
						 msg->header.ordinal, ret);
		else
			ret = _send_response(mgr, msg->header.txid,
					     msg->header.ordinal, out_payload,
					     out_payload_size);
	}

	if (out_payload)
		kvfree(out_payload);

	return ret;
}

static int _assemble_msg(struct nbl_rpcmgr *mgr, uint32_t txid,
			 struct rpc_message_t **out_msg,
			 size_t *out_payload_size)
{
	struct _saved_msg_list *msg_list;
	struct _saved_msg_item_t *curr, *tmp;
	char *out, *out_payload;
	size_t header_size = sizeof(struct rpc_message_t);

	msg_list = _erase_saved_msg_list(mgr, txid);
	BUG_ON(!msg_list);

	out = kmalloc(header_size + msg_list->total_payload_size, GFP_KERNEL);
	if (!out)
		return -ENOMEM;

	out_payload = out + header_size;

	list_for_each_entry_safe (curr, tmp, &msg_list->head, node) {
		memcpy(out, curr->msg, header_size);
		memcpy(out_payload, curr->msg->payload, curr->payload_size);
		out_payload += curr->payload_size;
		list_del(&curr->node);
		kfree(curr->msg);
		kfree(curr);
	}

	*out_msg = (struct rpc_message_t *)out;
	*out_payload_size = msg_list->total_payload_size;

	kfree(msg_list);
	return 0;
}

static int _assemble_and_dispatch_msg(struct nbl_rpcmgr *mgr, uint32_t txid)
{
	int ret = 0;
	struct rpc_message_t *saved_msg = NULL;
	size_t saved_payload_size = 0;

	ret = _assemble_msg(mgr, txid, &saved_msg, &saved_payload_size);
	if (ret < 0)
		return ret;

	ret = _dispatch_msg(mgr, saved_msg, saved_payload_size);
	kfree(saved_msg);

	return ret;
}

static int _append_msg_to_list(struct _saved_msg_list *msg_list,
			       struct rpc_message_t *msg, size_t payload_size)
{
	struct _saved_msg_item_t *item;

	item = kmalloc(sizeof(*item), GFP_KERNEL);
	if (!item)
		return -ENOMEM;

	item->msg = msg;
	item->payload_size = payload_size;

	msg_list->total_payload_size += payload_size;
	list_add_tail(&item->node, &msg_list->head);

	/* |msg_item| will be freed when successfully assembled. */
	return 0;
}

static struct _saved_msg_list *_get_or_alloc_msg_list(struct nbl_rpcmgr *mgr,
						      uint32_t txid)
{
	struct _saved_msg_list *msg_list;

	msg_list = _find_saved_msg_list(mgr, txid);

	if (!msg_list) {
		msg_list = kmalloc(sizeof(*msg_list), GFP_KERNEL);
		if (!msg_list)
			return ERR_PTR(-ENOMEM);

		INIT_LIST_HEAD(&msg_list->head);
		msg_list->total_payload_size = 0;
		WARN_ON(_emplace_saved_msg_list(mgr, txid, msg_list));
	}

	/* |msg_list| will be freed when successfully assembled. */
	return msg_list;
}

static int _on_new_message(struct nbl_rpcmgr *mgr, struct rpc_message_t *msg,
			   size_t payload_size)
{
	int ret;
	struct _saved_msg_list *msg_list;
	uint32_t txid = msg->header.txid;
	uint32_t ordinal = msg->header.ordinal;
	bool last_msg = msg->header.flags & RPC_FLAG_STOP_BIT;

	msg_list = _get_or_alloc_msg_list(mgr, txid);
	if (IS_ERR_OR_NULL(msg_list)) {
		ret = PTR_ERR(msg_list);
		pr_err("Failed to get msg list: %d\n", ret);
		goto err_get_msg_list;
	}

	ret = _append_msg_to_list(msg_list, msg, payload_size);
	if (ret < 0) {
		pr_err("Failed to append msg: %d\n", ret);
		goto err_append_msg;
	}

	/* |msg| ownership transferred to _assemble_and_dispatch_msg(). */
	if (last_msg) {
		ret = _assemble_and_dispatch_msg(mgr, txid);
		if (ret < 0) {
			pr_err("Failed to handle msg txid %u ordinal %u err %d \n",
			       txid, ordinal, ret);
		}
	}
	return ret;

err_get_msg_list:
err_append_msg:
	kfree(msg);
	return ret;
}

static int _read_and_dispatch_message(struct nbl_rpcmgr *mgr)
{
	int ret;
	struct rpc_message_t *new_msg;
	size_t header_size = sizeof(struct rpc_message_t);
	size_t payload_size;

	new_msg = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!new_msg)
		return -ENOMEM;

	ret = mgr->transport->recv(mgr->transport, new_msg, PAGE_SIZE);
	if (ret < 0) {
		if (ret != -ESHUTDOWN)
			pr_err("Failed to recv packet: %d\n", ret);
		kfree(new_msg);
		return ret;
	}

	payload_size = ret - header_size;

	/* |new_msg| ownership transferred to _on_new_message(). */
	return _on_new_message(mgr, new_msg, payload_size);
}

static int _rpc_worker_func(void *data)
{
	int ret;
	struct nbl_rpcmgr *mgr = data;

	do {
		ret = _read_and_dispatch_message(mgr);
		if (ret < 0) {
			pr_err("Failed to read and dispatch message: %d\n",
			       ret);
		}
	} while (!kthread_should_stop());
	return 0;
}

static void _free_rpcmgr(struct kref *kref)
{
	int i;
	struct nbl_rpcmgr *mgr =
		container_of(kref, struct nbl_rpcmgr, refcount);

	for (i = 0; i < MAX_NUM_RPC_WORKER; ++i) {
		if (!IS_ERR_OR_NULL(mgr->worker[i]))
			kthread_stop(mgr->worker[i]);
	}

	if (!IS_ERR_OR_NULL(mgr->cmds))
		nbl_map_delref(mgr->cmds);

	if (!IS_ERR_OR_NULL(mgr->incomplete_messages))
		nbl_map_delref(mgr->incomplete_messages);

	kfree(mgr);
}

struct nbl_rpcmgr *nbl_rpcmgr_init(struct rpc_transport *transport)
{
	int ret, i;
	struct nbl_rpcmgr *mgr;

	if (!transport)
		return ERR_PTR(-EINVAL);

	if (!transport->recv || !transport->send)
		return ERR_PTR(-EINVAL);

	mgr = kzalloc(sizeof(*mgr), GFP_KERNEL);
	if (!mgr)
		return ERR_PTR(-ENOMEM);

	mutex_init(&mgr->lock);
	kref_init(&mgr->refcount);
	mgr->transport = transport;

	mgr->cmds = nbl_map_init();
	if (IS_ERR(mgr->cmds)) {
		ret = PTR_ERR(mgr->cmds);
		goto err_out;
	}

	mgr->incomplete_messages = nbl_map_init();
	if (IS_ERR(mgr->incomplete_messages)) {
		ret = PTR_ERR(mgr->incomplete_messages);
		goto err_out;
	}

	for (i = 0; i < MAX_NUM_RPC_WORKER; ++i) {
		mgr->worker[i] = kthread_run(_rpc_worker_func, mgr,
					     "rpc-cb-worker-%d", i);
		if (IS_ERR(mgr->worker[i])) {
			ret = PTR_ERR(mgr->worker[i]);
			goto err_out;
		}
	}

	return mgr;

err_out:
	kref_put(&mgr->refcount, _free_rpcmgr);
	return ERR_PTR(ret);
}

struct nbl_rpcmgr *nbl_rpcmgr_addref(struct nbl_rpcmgr *mgr)
{
	kref_get(&mgr->refcount);
	return mgr;
}

void nbl_rpcmgr_delref(struct nbl_rpcmgr *mgr)
{
	kref_put(&mgr->refcount, _free_rpcmgr);
}

int nbl_rpcmgr_add_cb(struct nbl_rpcmgr *mgr, uint32_t cmd, rpc_cb cb)
{
	int ret;
	struct nbl_map *map = mgr->cmds;

	mutex_lock(&mgr->lock);
	ret = nbl_map_emplace(map, cmd, cb);
	mutex_unlock(&mgr->lock);
	return ret;
}

int nbl_rpcmgr_del_cb(struct nbl_rpcmgr *mgr, uint32_t cmd)
{
	void *cb;
	struct nbl_map *map = mgr->cmds;

	mutex_lock(&mgr->lock);
	cb = nbl_map_erase(map, cmd);
	mutex_unlock(&mgr->lock);
	return IS_ERR(cb) ? PTR_ERR(cb) : 0;
}
