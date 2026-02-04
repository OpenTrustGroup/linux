/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright 2019 GoldenRiver Technologies Co., Ltd.
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

#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/delay.h>
#include <linux/fs.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/poll.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/uio.h>
#include <linux/version.h>
#include <linux/kthread.h>
#include <linux/nebula/nebula_ipc.h>

#include "nebula-rpc.h"
#include "nebula-rpc-transport.h"
#include "nebula-queue.h"
#include "nebula-rpcmgr.h"
#include "nebula-rpc-proto.h"

#ifndef CONFIG_OF
#error "nbl-rpc driver only supported on device tree kernels"
#endif

#define DEVICE_NAME "nbl-rpc"
#define DRIVER_NAME "nbl-rpc"

#define MAX_RPC_NAME_LEN 64

#define RPC_MINORBITS 9

#define RPC_MINORS    (1 << RPC_MINORBITS)
#define RPC_MINOR_MAX (RPC_MINORS - 1)

#define NUM_RPC_BUFFER 32

// #define DEBUG

static const char kSvcName[] = "com.goldenrivertek.nblrpc.server";

static unsigned int rpc_major = CONFIG_NEBULA_RPC_DEV_MAJOR;
static struct class *rpc_class;
static DEFINE_MUTEX(rpc_minor_lock);
static unsigned long rpc_ids[BITS_TO_LONGS(RPC_MINORBITS)];

struct rpc_ctx {
	struct platform_device *pdev;
	struct cdev cdev;
	int minor;
	struct nbl_rpcmgr *mgr;
	struct nbl_queue *krx_msg_queue;
	struct nbl_queue *urx_msg_queue;
	struct nbl_queue *tx_msg_queue;
	int svc_fd;
	struct task_struct *rx_thread;
	struct task_struct *tx_thread;
	struct rpc_transport transport;
	struct completion ack_comp;
	struct notifier_block tipc_state_notifier;
	struct work_struct connect_rpc;
	struct workqueue_struct	*connect_rpc_wq;
};

static struct rpc_ctx *default_ctx;

int nbl_rpc_add_cb(uint32_t cmd, rpc_cb cb)
{
	uint retry = 10;
	int ret;

	while (!default_ctx || !default_ctx->svc_fd) {
		if (retry == 0) {
			pr_err("%s: nebula IPC driver not ready, ignore cmd=0x%x\n",
				__func__, cmd);
			return -ENODEV;
		}
		mdelay(1000);
		retry--;
	}

	BUG_ON(!default_ctx);
	BUG_ON(!default_ctx->svc_fd);

	ret = nbl_rpcmgr_add_cb(default_ctx->mgr, cmd, cb);
	if (ret < 0) {
		pr_err("%s: failed to add rpc callback, cmd 0x%x ret %d\n",
			__func__, cmd, ret);
	}
	return ret;
}
EXPORT_SYMBOL(nbl_rpc_add_cb);

int nbl_rpc_send(uint32_t cmd, const void *payload, size_t payload_len)
{
	int ret;
	struct iovec *iovec;
	struct nbl_queue *rx_msg_queue;
	size_t msg_size = RPC_MESSAGE_HEADER_SIZE + payload_len;
	struct rpc_message_t *msg = kzalloc(msg_size, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	msg->header.ordinal = cmd;
	msg->header.flags = RPC_FLAG_STOP_BIT;
	memcpy(msg->payload, payload, payload_len);

	iovec = kzalloc(sizeof(*iovec), GFP_KERNEL);
	if (!iovec) {
		kfree(msg);
		return -ENOMEM;
	}

	iovec->iov_base = msg;
	iovec->iov_len = msg_size;

	BUG_ON(!default_ctx);
	rx_msg_queue = RPC_IS_KERNEL(msg->header.ordinal) ?
				     default_ctx->krx_msg_queue :
				     default_ctx->urx_msg_queue;
	ret = nbl_queue_push(rx_msg_queue, iovec);
	if (ret)
		dev_err(&default_ctx->pdev->dev, "Failed to queue_push %d\n", ret);
	return ret;
}

static int rpc_minor_get(struct rpc_ctx *dev)
{
	int ret;

	mutex_lock(&rpc_minor_lock);

	ret = find_first_zero_bit(rpc_ids, RPC_MINORS);

	if (ret >= RPC_MINORS) {
		dev_err(&dev->pdev->dev, "too many rpc devices\n");
		ret = -ENODEV;
	} else {
		dev->minor = ret;
		set_bit(ret, rpc_ids);
		ret = 0;
	}
	mutex_unlock(&rpc_minor_lock);
	return ret;
}

static void rpc_minor_free(struct rpc_ctx *dev)
{
	mutex_lock(&rpc_minor_lock);
	clear_bit(dev->minor, rpc_ids);
	mutex_unlock(&rpc_minor_lock);
}

static int rpc_open(struct inode *inode, struct file *filp)
{
	struct rpc_ctx *ctx = container_of(inode->i_cdev, struct rpc_ctx, cdev);

	filp->private_data = ctx;
	dev_info(&ctx->pdev->dev, "%s online\n", current->comm);
	return 0;
}

static unsigned int rpc_poll(struct file *filp, poll_table *wait)
{
	struct rpc_ctx *ctx = filp->private_data;

	return nbl_queue_poll_wait(ctx->urx_msg_queue, filp, wait);
}

static int rpc_release(struct inode *inode, struct file *filp)
{
	struct rpc_ctx *ctx = filp->private_data;

	dev_info(&ctx->pdev->dev, "%s offline\n", current->comm);
	filp->private_data = NULL;
	return 0;
}

static ssize_t rpc_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	ssize_t ret;
	struct file *filp = iocb->ki_filp;
	bool wait = !(filp->f_flags & O_NONBLOCK);
	struct rpc_ctx *ctx = filp->private_data;
	struct iovec *iovec;
	size_t len;
	struct rpc_message_t *_msgdbg __maybe_unused;

	iovec = nbl_queue_pop(ctx->urx_msg_queue, wait);
	if (IS_ERR(iovec))
		return PTR_ERR(iovec);

	// Enforce message to be rpc_message_t.
	BUG_ON(iovec->iov_len < RPC_MESSAGE_HEADER_SIZE);

	len = iovec->iov_len;
	if (len > iov_iter_count(iter)) {
		ret = -EMSGSIZE;
		goto err_out;
	}

#ifdef DEBUG
	_msgdbg = iovec->iov_base;
	pr_info("%s: urpc deque txid %u ordinal %u flags 0x%x size %zu\n",
		current->comm, _msgdbg->header.txid, _msgdbg->header.ordinal,
		_msgdbg->header.flags, len);
#endif

	if (copy_to_iter(iovec->iov_base, len, iter) != len) {
		ret = -EFAULT;
		goto err_out;
	}

	ret = len;

err_out:
	kfree(iovec->iov_base);
	kfree(iovec);
	return ret;
}

static ssize_t rpc_write_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	ssize_t ret;
	struct file *filp = iocb->ki_filp;
	struct rpc_ctx *ctx = filp->private_data;
	struct device *dev = &ctx->pdev->dev;
	size_t len;
	void *bufcopy;
	struct iovec *iovec;
	struct rpc_message_t *_msgdbg __maybe_unused;

	iovec = kzalloc(sizeof(*iovec), GFP_KERNEL);
	if (!iovec)
		return -ENOMEM;

	len = iov_iter_count(iter);
	if (len < RPC_MESSAGE_HEADER_SIZE || len > MAX_RPC_MESSAGE_SIZE) {
		ret = -EMSGSIZE;
		goto err_msg_size;
	}

	bufcopy = kmalloc(len, GFP_KERNEL);
	if (!bufcopy) {
		ret = -ENOMEM;
		goto err_alloc_buf;
	}

	if (copy_from_iter(bufcopy, len, iter) != len) {
		ret = -EFAULT;
		goto err_copy_buf;
	}

#ifdef DEBUG
	_msgdbg = bufcopy;
	pr_info("%s: urpc queue txid %u ordinal %u flags 0x%x size %zu\n",
		current->comm, _msgdbg->header.txid, _msgdbg->header.ordinal,
		_msgdbg->header.flags, len);
#endif

	iovec->iov_base = bufcopy;
	iovec->iov_len = len;

	ret = nbl_queue_push(ctx->tx_msg_queue, iovec);
	if (ret) {
		dev_err(dev, "Failed to queue_push %zd\n", ret);
		goto err_queue_push;
	}

	return len;

err_queue_push:
err_copy_buf:
	kfree(bufcopy);
err_alloc_buf:
err_msg_size:
	kfree(iovec);
	return ret;
}

static const struct file_operations rpc_fops = {
	.owner = THIS_MODULE,
	.open = rpc_open,
	.release = rpc_release,
	.poll = rpc_poll,
	.read_iter = rpc_read_iter,
	.write_iter = rpc_write_iter,
};

static const struct of_device_id rpc_of_match[] = {
	{ .compatible = "grt,vtee-rpc-generic" },
	{},
};
MODULE_DEVICE_TABLE(of, rpc_of_match);

static int _rpc_recv(struct rpc_transport *transport, void *buf, size_t len)
{
	struct iovec *iovec;
	struct rpc_ctx *ctx = transport->priv;
	struct rpc_message_t *_msgdbg __maybe_unused;

	iovec = nbl_queue_pop(ctx->krx_msg_queue, /*wait=*/true);
	if (IS_ERR(iovec))
		return PTR_ERR(iovec);

	// Enforce messages to be rpc_message_t.
	BUG_ON(iovec->iov_len < RPC_MESSAGE_HEADER_SIZE);

#ifdef DEBUG
	_msgdbg = iovec->iov_base;
	pr_info("%s: krpc deque txid %u ordinal %u flags 0x%x size %zu\n",
		current->comm, _msgdbg->header.txid, _msgdbg->header.ordinal,
		_msgdbg->header.flags, iovec->iov_len);
#endif

	len = min(len, iovec->iov_len);
	memcpy(buf, iovec->iov_base, len);

	kfree(iovec->iov_base);
	kfree(iovec);
	return len;
}

static int _rpc_send(struct rpc_transport *transport, const void *buf,
		     size_t len)
{
	ssize_t ret;
	struct rpc_ctx *ctx = transport->priv;
	struct device *dev = &ctx->pdev->dev;
	void *bufcopy;
	struct iovec *iovec;
	struct rpc_message_t *_msgdbg __maybe_unused;

	// Enforce message to be rpc_message_t.
	BUG_ON(len < RPC_MESSAGE_HEADER_SIZE);

	iovec = kzalloc(sizeof(*iovec), GFP_KERNEL);
	if (!iovec)
		return -ENOMEM;

	bufcopy = kmalloc(len, GFP_KERNEL);
	if (!bufcopy) {
		ret = -ENOMEM;
		goto err_alloc_buf;
	}

	memcpy(bufcopy, buf, len);
	iovec->iov_base = bufcopy;
	iovec->iov_len = len;

#ifdef DEBUG
	_msgdbg = bufcopy;
	pr_info("%s: krpc queue txid %u ordinal %u flags 0x%x size %zu\n",
		current->comm, _msgdbg->header.txid, _msgdbg->header.ordinal,
		_msgdbg->header.flags, len);
#endif

	ret = nbl_queue_push(ctx->tx_msg_queue, iovec);
	if (ret) {
		dev_err(dev, "Failed to queue_push %zd\n", ret);
		goto err_queue_push;
	}

	return len;

err_queue_push:
	kfree(bufcopy);
err_alloc_buf:
	kfree(iovec);
	return ret;
}

static int _rx_thread_func(void *arg)
{
	int ret;
	struct iovec *iovec;
	struct rpc_ctx *ctx = arg;
	struct device *dev = &ctx->pdev->dev;
	struct nbl_queue *rx_msg_queue;
	struct rpc_message_t *msg;

	dev_info(dev, "%s: running\n", current->comm);

	while (true) {
		msg = kzalloc(PAGE_SIZE, GFP_KERNEL);
		if (!msg) {
			ret = -ENOMEM;
			goto err_alloc_msg;
		}

	again:
		ret = nbl_ipc_read(ctx->svc_fd, msg, PAGE_SIZE);
		if (ret < 0) {
			dev_err(dev, "Failed to ipc_read %d\n", ret);
			goto err_ipc_read;
		}

		if (ret < sizeof(struct rpc_message_t)) {
			dev_err(dev, "Invalid message size %d\n", ret);
			goto again;
		}

#ifdef DEBUG
		pr_info("%s: ipc recv txid %u ordinal %u flags 0x%x size %d\n",
			current->comm, msg->header.txid, msg->header.ordinal,
			msg->header.flags, ret);
#endif

		// Now it's a special message sent from nbl_rpc_srv.
		if (msg->header.flags & RPC_FLAG_ACK_BIT) {
			// Wake-up tx-thread to proceed to next write.
			complete(&ctx->ack_comp);
			goto again;
		}

		iovec = kzalloc(sizeof(*iovec), GFP_KERNEL);
		if (!iovec) {
			ret = -ENOMEM;
			goto err_alloc_iovec;
		}

		iovec->iov_base = msg;
		iovec->iov_len = ret;

		rx_msg_queue = RPC_IS_KERNEL(msg->header.ordinal) ?
					     ctx->krx_msg_queue :
					     ctx->urx_msg_queue;

		ret = nbl_queue_push(rx_msg_queue, iovec);
		if (ret) {
			dev_err(dev, "Failed to queue_push %d\n", ret);
			goto err_queue_push;
		}
	}

err_queue_push:
	kfree(iovec);
err_alloc_iovec:
err_ipc_read:
	kfree(msg);
err_alloc_msg:
	dev_err(dev, "%s: exiting (%d)\n", current->comm, ret);
	return ret;
}

static int _tx_thread_func(void *arg)
{
	int ret;
	struct iovec *iovec;
	struct rpc_ctx *ctx = arg;
	struct device *dev = &ctx->pdev->dev;
	uint64_t msg_counter = 0;
	struct rpc_message_t *_msgdbg __maybe_unused;

	dev_info(dev, "%s: running\n", current->comm);

	while (true) {
		iovec = nbl_queue_pop(ctx->tx_msg_queue, /*wait=*/true);
		if (IS_ERR(iovec)) {
			ret = PTR_ERR(iovec);
			goto err_queue_pop;
		}

		ret = nbl_ipc_write(ctx->svc_fd, iovec->iov_base,
				    iovec->iov_len, NULL, 0);
		if (ret != iovec->iov_len) {
			dev_err(dev, "Failed to ipc write %d\n", ret);
			goto err_ipc_write;
		}

#ifdef DEBUG
		_msgdbg = iovec->iov_base;
		pr_info("%s: ipc send txid %u ordinal %u flags 0x%x size %d\n",
			current->comm, _msgdbg->header.txid,
			_msgdbg->header.ordinal, _msgdbg->header.flags, ret);
#endif

		if (++msg_counter % NUM_RPC_BUFFER == 0) {
			// Wait for ack from rx-thread.
			wait_for_completion(&ctx->ack_comp);
		}

		kfree(iovec->iov_base);
		kfree(iovec);
	}

err_ipc_write:
	kfree(iovec->iov_base);
	kfree(iovec);
err_queue_pop:
	dev_err(dev, "%s: exiting (%d)\n", current->comm, ret);
	return ret;
}

static int tipc_state_notify(struct notifier_block *nb, unsigned long action,
			     void *data)
{
	struct rpc_ctx *priv;

	if (action != TIPC_STATE_ONLINE)
		return NOTIFY_DONE;

	priv = container_of(nb, struct rpc_ctx, tipc_state_notifier);
	queue_work(priv->connect_rpc_wq, &priv->connect_rpc);

	return NOTIFY_OK;
}

#if defined(CONFIG_NEBULA_RPC_UNITTEST) || defined(CONFIG_NEBULA_RPC_UNITTEST_MODULE)
static nbl_status rpc_echo(uint32_t cmd, const void *in, size_t in_size,
			   void **out, size_t *out_size)
{
	return serialize(in, in_size, out, out_size);
}

static int nbl_rpc_unittest_init(void)
{
	nbl_rpc_add_cb(NBL_KRPC_ECHO, rpc_echo);
	return 0;
}
#endif

static void connect_rpc_service(struct work_struct *work)
{
	struct rpc_ctx *priv = container_of(work, struct rpc_ctx, connect_rpc);

	BUG_ON(!default_ctx);
	priv->svc_fd = nbl_ipc_connect(kSvcName);
	BUG_ON(priv->svc_fd <= 0);
	dev_info(&priv->pdev->dev, "%s connected\n", kSvcName);

	wake_up_process(priv->rx_thread);
	wake_up_process(priv->tx_thread);

#if defined(CONFIG_NEBULA_RPC_UNITTEST) || defined(CONFIG_NEBULA_RPC_UNITTEST_MODULE)
	nbl_rpc_unittest_init();
#endif
}

static int rpc_probe(struct platform_device *pdev)
{
	int err;
	struct rpc_ctx *priv;
	struct device *device = NULL;
	dev_t dev_num;

	priv = devm_kzalloc(&pdev->dev, sizeof(struct rpc_ctx), GFP_KERNEL);
	if (priv == NULL) {
		err = -ENOMEM;
		goto err_alloc_priv;
	}
	dev_set_drvdata(&pdev->dev, priv);

	err = rpc_minor_get(priv);
	if (err < 0) {
		dev_err(&pdev->dev, "failed to alloc minor number\n");
		goto err_minor_get;
	}

	INIT_WORK(&priv->connect_rpc, connect_rpc_service);
	priv->connect_rpc_wq = alloc_workqueue("connect-rpc-wq", WQ_UNBOUND, 0);
	if (!priv->connect_rpc_wq) {
		err = -ENODEV;
		dev_err(&pdev->dev, "Failed create connect-rpc-wq\n");
		goto err_create_connect_rpc_wq;
	}

	dev_set_name(&pdev->dev, "%s%d", DEVICE_NAME, priv->minor);
	priv->pdev = pdev;
	init_completion(&priv->ack_comp);

	priv->tipc_state_notifier.notifier_call = tipc_state_notify;
	err = nebula_tipc_state_notifier_register(&priv->tipc_state_notifier);
	if (err) {
		dev_err(&pdev->dev,
			"failed to register tipc state notifier: %d\n", err);
		goto err_tipc_state_notifier_register;
	}

	priv->urx_msg_queue = nbl_queue_init();
	if (IS_ERR(priv->urx_msg_queue)) {
		err = PTR_ERR(priv->urx_msg_queue);
		dev_err(&pdev->dev, "user rx queue init failed: %d\n", err);
		goto err_urx_msg_queue_init;
	}

	priv->krx_msg_queue = nbl_queue_init();
	if (IS_ERR(priv->krx_msg_queue)) {
		err = PTR_ERR(priv->krx_msg_queue);
		dev_err(&pdev->dev, "kernel rx queue init failed: %d\n", err);
		goto err_krx_msg_queue_init;
	}

	priv->tx_msg_queue = nbl_queue_init();
	if (IS_ERR(priv->tx_msg_queue)) {
		err = PTR_ERR(priv->tx_msg_queue);
		dev_err(&pdev->dev, "kernel tx queue init failed: %d\n", err);
		goto err_tx_msg_queue_init;
	}

	priv->transport.recv = _rpc_recv;
	priv->transport.send = _rpc_send;
	priv->transport.priv = priv;

	priv->mgr = nbl_rpcmgr_init(&priv->transport);
	if (IS_ERR(priv->mgr)) {
		err = PTR_ERR(priv->mgr);
		dev_err(&pdev->dev, "rpcmgr init failed: %d\n", err);
		goto err_rpcmgr_init;
	}

	priv->rx_thread = kthread_create(_rx_thread_func, priv, "rpc-rx-worker");
	if (IS_ERR(priv->rx_thread)) {
		err = PTR_ERR(priv->rx_thread);
		dev_err(&pdev->dev, "rx thread init failed: %d\n", err);
		goto err_rx_thread_init;
	}

	priv->tx_thread = kthread_create(_tx_thread_func, priv, "rpc-tx-worker");
	if (IS_ERR(priv->tx_thread)) {
		err = PTR_ERR(priv->tx_thread);
		dev_err(&pdev->dev, "tx thread init failed: %d\n", err);
		goto err_tx_thread_init;
	}

	dev_num = MKDEV(rpc_major, priv->minor);

	cdev_init(&priv->cdev, &rpc_fops);
	priv->cdev.owner = THIS_MODULE;
	err = cdev_add(&priv->cdev, dev_num, 1);
	if (err) {
		dev_err(&pdev->dev, "cdev_add err %d\n", err);
		goto err_cdev_add;
	}

	device = device_create(rpc_class, NULL, dev_num, NULL, DEVICE_NAME "%d",
			       priv->minor);
	if (IS_ERR(device)) {
		err = PTR_ERR(device);
		dev_err(&pdev->dev, "device_create err %d\n", err);
		goto err_device_create;
	}

	default_ctx = priv;
	return 0;

err_device_create:
	cdev_del(&priv->cdev);
err_cdev_add:
	kthread_stop(priv->tx_thread);
err_tx_thread_init:
	kthread_stop(priv->rx_thread);
err_rx_thread_init:
	nbl_rpcmgr_delref(priv->mgr);
err_rpcmgr_init:
	nbl_queue_delref(priv->tx_msg_queue);
err_tx_msg_queue_init:
	nbl_queue_delref(priv->krx_msg_queue);
err_krx_msg_queue_init:
	nbl_queue_delref(priv->urx_msg_queue);
err_urx_msg_queue_init:
	nebula_tipc_state_notifier_unregister(&priv->tipc_state_notifier);
err_tipc_state_notifier_register:
	destroy_workqueue(priv->connect_rpc_wq);
err_create_connect_rpc_wq:
	rpc_minor_free(priv);
err_minor_get:
	dev_set_drvdata(&pdev->dev, NULL);
	devm_kfree(&pdev->dev, priv);
err_alloc_priv:
	return err;
}

static int rpc_remove(struct platform_device *pdev)
{
	struct rpc_ctx *priv = dev_get_drvdata(&pdev->dev);

	default_ctx = NULL;
	cdev_del(&priv->cdev);
	nbl_rpcmgr_delref(priv->mgr);
	nbl_queue_delref(priv->krx_msg_queue);
	nbl_queue_delref(priv->urx_msg_queue);
	nbl_ipc_close(priv->svc_fd);
	nebula_tipc_state_notifier_unregister(&priv->tipc_state_notifier);

	destroy_workqueue(priv->connect_rpc_wq);
	rpc_minor_free(priv);
	dev_set_drvdata(&pdev->dev, NULL);
	devm_kfree(&pdev->dev, priv);
	return 0;
}

static struct platform_driver rpc_driver = {
    .probe      = rpc_probe,
    .remove     = rpc_remove,
    .driver = {
        .name = DRIVER_NAME,
        .owner = THIS_MODULE,
        .of_match_table = rpc_of_match,
    },
};

static int __init rpc_init(void)
{
	int err;
	dev_t dev_num = 0;

	if (rpc_major) {
		err = register_chrdev_region(MKDEV(rpc_major, 0), 1,
					     DEVICE_NAME);
		if (err < 0) {
			pr_err("%s: register_chrdev_region failed: %d\n",
			       __func__, err);
			return err;
		}
	} else {
		err = alloc_chrdev_region(&dev_num, 0, MINORMASK, DEVICE_NAME);
		if (err < 0) {
			pr_err("%s: alloc_chrdev_region failed: %d\n", __func__,
			       err);
			return err;
		}
		rpc_major = MAJOR(dev_num);
	}
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0)
	rpc_class = class_create(THIS_MODULE, DEVICE_NAME);
#else
	rpc_class = class_create(DEVICE_NAME);
#endif
	if (IS_ERR(rpc_class)) {
		err = PTR_ERR(rpc_class);
		pr_err("%s: class_create failed: %d\n", __func__, err);
		goto err_class_create;
	}

	err = platform_driver_register(&rpc_driver);
	if (err)
		goto err_driver_register;

	return 0;

err_driver_register:
	class_destroy(rpc_class);
err_class_create:
	unregister_chrdev_region(dev_num, MINORMASK);
	return err;
}

static void __exit rpc_exit(void)
{
	dev_t dev_num = MKDEV(rpc_major, 0);

	platform_driver_unregister(&rpc_driver);
	class_destroy(rpc_class);
	unregister_chrdev_region(dev_num, MINORMASK);
}

subsys_initcall(rpc_init);
module_exit(rpc_exit);

MODULE_DESCRIPTION("Nebula RPC Service driver");
MODULE_LICENSE("GPL v2");
