/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright 2020 GoldenRiver Technologies Co., Ltd. All rights reserved.
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
#include <linux/circ_buf.h>
#include <linux/fs.h>
#include <linux/log2.h>
#include <linux/module.h>
#include <linux/mod_devicetable.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/poll.h>

#include "trusty-log.h"
#include "vtee-log.h"

#define TRUSTY_LOG_SIZE (PAGE_SIZE * 32)

#define DEVICE_NAME "nebula-log"
#define DRIVER_NAME "nebula-log"

#define NEBULA_LOG_MINORBITS 9
#define NEBULA_LOG_MINORS    (1 << NEBULA_LOG_MINORBITS)
#define NEBULA_LOG_MINOR_MAX (NEBULA_LOG_MINORS - 1)

#define BUF_SZ TRUSTY_LOG_SIZE /* should be power of 2 */

/* space used */
#define circ_count(circ) \
	(CIRC_CNT((circ)->head, (circ)->tail, BUF_SZ))
#define circ_count_to_end(circ) \
	(CIRC_CNT_TO_END((circ)->head, (circ)->tail, BUF_SZ))

/* space available */
#define circ_space(circ) \
	(CIRC_SPACE((circ)->head, (circ)->tail, BUF_SZ))
#define circ_space_to_end(circ) \
	(CIRC_SPACE_TO_END((circ)->head, (circ)->tail, BUF_SZ))

#define log_circ_empty(circ)		((circ)->head == (circ)->tail)
#define log_circ_clear(circ)		((circ)->head = (circ)->tail = 0)

#define log_circ_pending(circ)	\
	(CIRC_CNT((circ)->head, (circ)->tail, BUF_SZ))

#define log_circ_free(circ)	\
	(CIRC_SPACE((circ)->head, (circ)->tail, BUF_SZ))


static unsigned int nebula_log_major = CONFIG_NEBULA_VTEE_LOG_DEV_MAJOR;
static struct class *nebula_log_class;
static DEFINE_MUTEX(nebula_log_minor_lock);
static unsigned long nebula_log_ids[BITS_TO_LONGS(NEBULA_LOG_MINORBITS)];

static struct platform_device *g_pdev;
static bool nebula_log_ready = false;

struct nebula_log_state {
	struct device *dev;
	struct cdev cdev;
	int minor;
	struct mutex read_lock;
	wait_queue_head_t fifo_event;
	struct circ_buf fifo;
	char *fifo_buf;
};

static int nebula_log_minor_get(struct nebula_log_state *s)
{
	int ret;

	mutex_lock(&nebula_log_minor_lock);

	ret = find_first_zero_bit(nebula_log_ids, NEBULA_LOG_MINORS);

	if (ret >= NEBULA_LOG_MINORS) {
		dev_err(s->dev, "too many tlog devices\n");
		ret = -ENODEV;
	} else {
		s->minor = ret;
		set_bit(ret, nebula_log_ids);
		ret = 0;
	}
	mutex_unlock(&nebula_log_minor_lock);
	return ret;
}

static void nebula_log_minor_free(struct nebula_log_state *s)
{
	mutex_lock(&nebula_log_minor_lock);
	clear_bit(s->minor, nebula_log_ids);
	mutex_unlock(&nebula_log_minor_lock);
}

bool is_vtee_nebula_log_ready(void)
{
	return nebula_log_ready;
}

void vtee_nebula_log_fifo_write(void *buf, size_t sz)
{
	struct platform_device *pdev = g_pdev;
	struct nebula_log_state *s;
	struct circ_buf *fifo;
	const char *ptr = buf;

	BUG_ON(!is_vtee_nebula_log_ready());
	BUG_ON(buf == NULL);

	if (!sz)
		return;

	s = platform_get_drvdata(pdev);
	fifo = &s->fifo;

	while (sz > 0) {
		char *fptr = &fifo->buf[fifo->head];
		int n;

		if (circ_space(&s->fifo) <= 0) {
			/* discard old one */
			n = min_t(int, sz, circ_count_to_end(&s->fifo));
			fifo->tail = (fifo->tail + n) & (BUF_SZ - 1);
		}

		n = min_t(int, sz, circ_space_to_end(&s->fifo));
		memcpy(fptr, ptr, n);

		fifo->head = (fifo->head + n) & (BUF_SZ - 1);
		sz -= n;
		ptr += n;

		wake_up_all(&s->fifo_event);
	}
}

static ssize_t nebula_log_fifo_read(struct file *filp, char __user *buf,
				    size_t sz, loff_t *ppos)
{
	struct nebula_log_state *s = filp->private_data;
	struct circ_buf *fifo = &s->fifo;
	int ret = 0, len = 0;

	BUG_ON(!is_vtee_nebula_log_ready());
	BUG_ON(buf == NULL);

	if (!sz)
		return 0;

	BUG_ON(circ_count(&s->fifo) < 0);
	if (log_circ_empty(&s->fifo) && filp->f_flags & O_NONBLOCK) {
		goto no_data;
	}

	ret = wait_event_interruptible(s->fifo_event,
			circ_count(&s->fifo) > 0);
	if (ret)
		goto error_wait_event;

	mutex_lock(&s->read_lock);
	while (sz > 0) {
		const char *fptr = &fifo->buf[fifo->tail];
		int n;

		BUG_ON(circ_count(&s->fifo) < 0);
		if (log_circ_empty(&s->fifo))
			break;

		n = min_t(int, sz, circ_count_to_end(&s->fifo));
		if (copy_to_user(buf, fptr, n)) {
			ret = -EFAULT;
			goto error_copy_to_user;
		}

		fifo->tail = (fifo->tail + n) & (BUF_SZ - 1);
		*ppos += n;
		sz -= n;
		buf += n;
		len += n;
	}

error_copy_to_user:
	mutex_unlock(&s->read_lock);
error_wait_event:
no_data:
	if (ret)
		return ret;
	return len;
}

static int nebula_log_open(struct inode *inode, struct file *filp)
{
	struct nebula_log_state *s =
		container_of(inode->i_cdev, struct nebula_log_state, cdev);

	filp->private_data = s;
	return 0;
}

static int nebula_log_release(struct inode *inode, struct file *filp)
{
	return 0;
}

static ssize_t nebula_log_read(struct file *filp, char __user *buf, size_t sz,
			       loff_t *ppos)
{
	return nebula_log_fifo_read(filp, buf, sz, ppos);
}

static unsigned int nebula_log_poll(struct file *filp, poll_table *wait)
{
	struct nebula_log_state *s = filp->private_data;
	unsigned int mask = 0;

	if(!is_vtee_nebula_log_ready())
		return 0;

	mutex_lock(&s->read_lock);
	poll_wait(filp, &s->fifo_event, wait);

	if (log_circ_pending(&s->fifo))
		mask |= POLLIN | POLLRDNORM;

	mutex_unlock(&s->read_lock);
	return mask;
}

static const struct file_operations nebula_log_fops = {
	.owner = THIS_MODULE,
	.read = nebula_log_read,
	.open = nebula_log_open,
	.poll = nebula_log_poll,
	.release = nebula_log_release,
};

static int nebula_log_probe(struct platform_device *pdev)
{
	struct nebula_log_state *s;
	int result;
	struct device *device = NULL;
	dev_t dev_num;

	s = kzalloc(sizeof(*s), GFP_KERNEL);
	if (!s) {
		result = -ENOMEM;
		goto error_alloc_state;
	}

	g_pdev = pdev;
	s->dev = &pdev->dev;

	BUG_ON(!is_power_of_2(BUF_SZ));

	s->fifo_buf = alloc_pages_exact(BUF_SZ, GFP_KERNEL | __GFP_ZERO);
	if (!s->fifo_buf) {
		result = -ENOMEM;
		goto error_alloc_buf;
	}
	s->fifo.buf = s->fifo_buf;

	init_waitqueue_head(&s->fifo_event);
	mutex_init(&s->read_lock);

	/* get minor */
	result = nebula_log_minor_get(s);
	if (result < 0)
		goto error_minor_get;

	cdev_init(&s->cdev, &nebula_log_fops);
	s->cdev.owner = THIS_MODULE;

	/* Add character device */
	dev_num = MKDEV(nebula_log_major, s->minor);
	result = cdev_add(&s->cdev, dev_num, 1);
	if (result) {
		dev_err(&pdev->dev, "cdev_add err %d\n", result);
		goto error_cdev_add;
	}

	/* Create a device node */
	device = device_create(nebula_log_class, NULL, dev_num, NULL,
			       DEVICE_NAME "-dev%d", s->minor);
	if (IS_ERR(device)) {
		result = PTR_ERR(device);
		dev_err(&pdev->dev, "device_create err %d\n", result);
		goto error_device_create;
	}

	platform_set_drvdata(pdev, s);

	nebula_log_ready = true;

	return 0;

error_device_create:
	cdev_del(&s->cdev);
error_cdev_add:
	nebula_log_minor_free(s);
error_minor_get:
	mutex_destroy(&s->read_lock);
	free_pages_exact(s->fifo_buf, BUF_SZ);
error_alloc_buf:
	kfree(s);
error_alloc_state:
	return result;
}

static int nebula_log_remove(struct platform_device *pdev)
{
	struct nebula_log_state *s = platform_get_drvdata(pdev);
	dev_t dev_num = MKDEV(nebula_log_major, s->minor);

	nebula_log_ready = false;

	device_destroy(nebula_log_class, dev_num);
	cdev_del(&s->cdev);
	nebula_log_minor_free(s);

	mutex_destroy(&s->read_lock);
	free_pages_exact(s->fifo_buf, BUF_SZ);
	kfree(s);

	return 0;
}

static const struct of_device_id nebula_log_of_match[] = {
	{
		.compatible = "grt,vtee-nblmsg-v1",
	},
	{},
};

static struct platform_driver nebula_log_driver = {
	.probe = nebula_log_probe,
	.remove = nebula_log_remove,
	.driver = {
		.name = DRIVER_NAME,
		.owner = THIS_MODULE,
		.of_match_table = nebula_log_of_match,
	},
};

int vtee_nebula_log_init(void)
{
	int err;
	dev_t dev_num = 0;

	if (nebula_log_major) {
		err = register_chrdev_region(MKDEV(nebula_log_major, 0), 1,
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
		nebula_log_major = MAJOR(dev_num);
	}
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0)
	nebula_log_class = class_create(THIS_MODULE, DEVICE_NAME);
#else
	nebula_log_class = class_create(DEVICE_NAME);
#endif
	if (IS_ERR(nebula_log_class)) {
		err = PTR_ERR(nebula_log_class);
		pr_err("%s: class_create failed: %d\n", __func__, err);
		goto error_class_create;
	}

	err = platform_driver_register(&nebula_log_driver);
	if (err)
		goto error_driver_register;

	return 0;

error_driver_register:
	class_destroy(nebula_log_class);
error_class_create:
	unregister_chrdev_region(dev_num, MINORMASK);
	return err;
}

void vtee_nebula_log_exit(void)
{
	dev_t dev_num = MKDEV(nebula_log_major, 0);

	platform_driver_unregister(&nebula_log_driver);
	class_destroy(nebula_log_class);
	unregister_chrdev_region(dev_num, MINORMASK);
}
