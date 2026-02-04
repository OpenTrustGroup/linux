/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright 2019 GoldenRiver Technologies Co., Ltd. All rights reserved.
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

#include <linux/version.h>
#include <linux/uaccess.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/nebula/trusty_kern_ipc.h>

struct tipc_dev {
	struct list_head tipc_chan_list;
	int fd;
	struct mutex lock;
};

static struct tipc_dev *default_dev;

struct tipc_chan {
	struct file *filp;
	int fd;
	struct list_head node;
};

static struct tipc_chan *fd_to_chan(int fd)
{
	struct tipc_chan *chan = NULL;
	bool found;

	mutex_lock(&default_dev->lock);
	if (!list_empty(&default_dev->tipc_chan_list)) {
		list_for_each_entry(chan, &default_dev->tipc_chan_list, node) {
			if (chan->fd == fd) {
				found = true;
				break;
			}
		}
	}
	mutex_unlock(&default_dev->lock);

	return found ? chan : NULL;
}

int tipc_connect(const char *dev_name, const char *srv_name)
{
	struct file *f;
	struct tipc_chan *chan;
	int rc = -1;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
	mm_segment_t old_fs = get_fs();
#endif
	if (!dev_name || !srv_name) {
		pr_err("%s: dev_name(%s) or srv_name(%s) invalid\n",
				__func__, dev_name, srv_name);
		goto err_out;
	}

	chan = kzalloc(sizeof(*chan), GFP_KERNEL);
	if (!chan)
		goto err_out;

	f = filp_open(dev_name, O_RDWR, 0);
	if (IS_ERR(f)) {
		pr_err("%s: failed to open tipc device \"%s\"\n",
				__func__, dev_name);
		goto err_filp_open;
	}

	if (!f->f_op || !f->f_op->unlocked_ioctl) {
		pr_err("%s: f_op or f_op->unlocked_ioctl NULL\n", __func__);
		goto err_unlocked_ioctl;
	}
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
	set_fs(KERNEL_DS);
#endif
	rc = f->f_op->unlocked_ioctl(f, TIPC_IOC_CONNECT, (ulong)srv_name);
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
	set_fs(old_fs);
#endif
	if (rc < 0) {
		pr_err("%s: failed to connect tipc service \"%s\", rc %d\n",
				__func__, srv_name, rc);
		goto err_unlocked_ioctl;
	}

	mutex_lock(&default_dev->lock);
	chan->filp = f;
	chan->fd = default_dev->fd++;
	list_add_tail(&chan->node, &default_dev->tipc_chan_list);
	mutex_unlock(&default_dev->lock);

	pr_debug("%s: chan %p fd %d\n", __func__, chan, chan->fd);

	return chan->fd;

err_unlocked_ioctl:
	filp_close(f, NULL);
err_filp_open:
	kfree(chan);
err_out:
	return rc;
}
EXPORT_SYMBOL(tipc_connect);

int tipc_close(int fd)
{
	struct tipc_chan *chan;

	chan = fd_to_chan(fd);
	if (!chan)
		return -1;

	pr_debug("%s: chan %p fd %d\n", __func__, chan, fd);
	mutex_lock(&default_dev->lock);
	filp_close(chan->filp, NULL);
	list_del(&chan->node);
	kfree(chan);
	mutex_unlock(&default_dev->lock);

	return 0;
}
EXPORT_SYMBOL(tipc_close);

ssize_t tipc_read(int fd, void *buf, size_t size)
{
	struct tipc_chan *chan;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
	mm_segment_t old_fs = get_fs();
#endif
	ssize_t ret = -1;
	loff_t pos = 0;

	if (!buf || !size)
		return ret;

	chan = fd_to_chan(fd);
	if (!chan)
		return -1;

	pr_debug("%s: chan %p fd %d\n", __func__, chan, fd);
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
	set_fs(KERNEL_DS);
#endif
	ret = vfs_read(chan->filp, buf, size, &pos);
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
	set_fs(old_fs);
#endif
	return ret;
}
EXPORT_SYMBOL(tipc_read);

ssize_t tipc_write(int fd, const void *buf, size_t size)
{
	struct tipc_chan *chan;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
	mm_segment_t old_fs = get_fs();
#endif
	ssize_t ret = -1;
	loff_t pos = 0;

	if (!buf || !size)
		return -1;

	chan = fd_to_chan(fd);
	if (!chan)
		return -1;

	pr_debug("%s: chan %p fd %d\n", __func__, chan, fd);
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
	set_fs(KERNEL_DS);
#endif
	ret = vfs_write(chan->filp, buf, size, &pos);
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
	set_fs(old_fs);
#endif
	return ret;
}
EXPORT_SYMBOL(tipc_write);

ssize_t tipc_poll(int fd, struct poll_table_struct *wait)
{
	struct tipc_chan *chan;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
	mm_segment_t old_fs = get_fs();
#endif
	ssize_t ret = -1;

	chan = fd_to_chan(fd);
	if (!chan)
		return -1;

	pr_debug("%s: chan %p fd %d wait %p\n", __func__, chan, fd, wait);
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
	set_fs(KERNEL_DS);
#endif
	ret = chan->filp->f_op->poll(chan->filp, wait);
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
	set_fs(old_fs);
#endif
	return ret;
}
EXPORT_SYMBOL(tipc_poll);

int tipc_send_msg(int fd, const struct iovec *iov, unsigned int iov_cnt,
		const struct tipc_memref *mrefv, unsigned int mrefv_cnt)
{
	unsigned int i;
	struct tipc_chan *chan;
	int rc = 0;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
	mm_segment_t old_fs = get_fs();
#endif
	struct tipc_send_msg_req msg;
	struct tipc_shmem shmemv[MAX_SHRMEM_COUNT];

	chan = fd_to_chan(fd);
	if (!chan)
		return -1;

	for (i = 0; i < mrefv_cnt && i < MAX_SHRMEM_COUNT; i++)
		shmemv[i] = mrefv[i].shmem;

	msg.msgiov = (__u64)(uintptr_t)iov;
	msg.msgiov_cnt = iov_cnt;
	msg.shmemv = (__u64)(uintptr_t)shmemv;
	msg.shmemv_cnt = mrefv_cnt;

	pr_debug("%s: chan %p fd %d\n", __func__, chan, fd);
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
	set_fs(KERNEL_DS);
#endif
	rc = chan->filp->f_op->unlocked_ioctl(chan->filp,
			TIPC_IOC_SEND_MSG, (ulong)&msg);
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
	set_fs(old_fs);
#endif
	return rc;
}
EXPORT_SYMBOL(tipc_send_msg);

int tipc_recv_msg(int fd, const struct iovec *iov, unsigned int iov_cnt)
{
	struct tipc_chan *chan;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
	mm_segment_t old_fs = get_fs();
#endif
	ssize_t ret = -1;
	loff_t pos = 0;

	if (!iov || !iov_cnt)
		return ret;

	chan = fd_to_chan(fd);
	if (!chan)
		return -1;

	pr_debug("%s: chan %p fd %d\n", __func__, chan, fd);
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
	set_fs(KERNEL_DS);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
	ret = vfs_read(chan->filp, (void *)iov, iov_cnt, &pos);
#elif KERNEL_VERSION(4, 6, 0) <= LINUX_VERSION_CODE
	ret = vfs_readv(chan->filp, iov, iov_cnt, &pos, 0);
#else
	ret = vfs_readv(chan->filp, iov, iov_cnt, &pos);
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
	set_fs(old_fs);
#endif
	return ret;
}
EXPORT_SYMBOL(tipc_recv_msg);

static int __init tipc_kern_init(void)
{
	default_dev = kzalloc(sizeof(*default_dev), GFP_KERNEL);
	if (!default_dev)
		return -ENOMEM;

	mutex_init(&default_dev->lock);
	INIT_LIST_HEAD(&default_dev->tipc_chan_list);

	return 0;
}

static void __exit tipc_kern_exit(void)
{
	kfree(default_dev);
}

module_init(tipc_kern_init);
module_exit(tipc_kern_exit);

MODULE_DESCRIPTION("Trusty Kernel IPC driver");
MODULE_LICENSE("GPL v2");
