// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2024 GoldenRiver Inc.

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/of_platform.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/kfifo.h>
#include <linux/mutex.h>

#include "nebula_rproc_remote.h"
#include "rpmsg.h"
#include "rpmsg_virtio.h"
#include "remoteproc_virtio.h"

#define VIRTIO_RPMSG_F_NS    0
#define RPMSG_VDEV_DFEATURES (1 << VIRTIO_RPMSG_F_NS)

/* Resource table entries */
#define NUM_VRINGS  0x02
#define VRING_ALIGN 0x1000
#define RING_TX	    0
#define RING_RX	    1
#define VRING_SIZE  256

struct rpmsg_device_descriptor {
	struct fw_rsc_vdev vdev;
	struct fw_rsc_vdev_vring vrings[NUM_VRINGS];
} __packed;

static const struct rpmsg_device_descriptor rpmsg_desc = {
	.vdev		= {
		.type		= RSC_VDEV,
		.id		= VIRTIO_ID_RPMSG,
		.dfeatures	= RPMSG_VDEV_DFEATURES,
		.config_len	= 0,
		.num_of_vrings	= NUM_VRINGS,
	},
	.vrings	= {
		[RING_TX]	= {
			.da		= FW_RSC_U32_ADDR_ANY,
			.align		= VRING_ALIGN,
			.num		= VRING_SIZE,
		},
		[RING_RX]	= {
			.da		= FW_RSC_U32_ADDR_ANY,
			.align		= VRING_ALIGN,
			.num		= VRING_SIZE,
		},
	},
};

#define MSG_COUNT 10
#define MSG_SIZE  64

#define DEV_RPMSG_NUM 2

struct rpmsg_device_priv {
	struct rpmsg_virtio_device rvdev;
	struct rpmsg_endpoint echo_ept;
	struct rpmsg_endpoint sink_ept;
	struct kfifo rec_fifo;
	unsigned int priv_index;
	struct mutex fifo_mutex;
	wait_queue_head_t read_queue;
};

struct rpmsg_dev_data {
	struct cdev cdev;
	int device_index;
};

static struct rpmsg_device_priv *g_priv[DEV_RPMSG_NUM] = { NULL };
static unsigned int rpmsg_dev_cal = 0;
static struct rpmsg_dev_data rpmsg_devices[DEV_RPMSG_NUM];

static int dev_open[DEV_RPMSG_NUM];
static int ept_open[DEV_RPMSG_NUM];

static int sink_endpoint_cb(struct rpmsg_endpoint *ept, void *data, size_t len,
			    uint32_t src, void *priv)
{
	return RPMSG_SUCCESS;
}

static void sink_endpoint_unbind(struct rpmsg_endpoint *ept)
{
	struct rpmsg_device *rdev = ept->rdev;
	struct rpmsg_virtio_device *rvdev =
		container_of(rdev, struct rpmsg_virtio_device, rdev);
	struct rpmsg_device_priv *priv =
		container_of(rvdev, struct rpmsg_device_priv, rvdev);

	rpmsg_destroy_ept(&priv->sink_ept);
}

static int echo_endpoint_cb(struct rpmsg_endpoint *ept, void *data, size_t len,
			    uint32_t src, void *t_priv)
{
	unsigned int copied;
	struct rpmsg_device *rdev = ept->rdev;
	struct rpmsg_virtio_device *rvdev =
		container_of(rdev, struct rpmsg_virtio_device, rdev);
	struct rpmsg_device_priv *priv =
		container_of(rvdev, struct rpmsg_device_priv, rvdev);

	if (!dev_open[priv->priv_index])
		return RPMSG_SUCCESS;

	// pr_info("echo_endpoint_cb+ : priv : %d\n", priv->priv_index);

	mutex_lock(&priv->fifo_mutex);
	copied = kfifo_in(&priv->rec_fifo, data, len);
	mutex_unlock(&priv->fifo_mutex);

	wake_up_interruptible(&priv->read_queue);

	return RPMSG_SUCCESS;
}

static void echo_endpoint_unbind(struct rpmsg_endpoint *ept)
{
}

static void rproc_remote_ns_bind_cb(struct rpmsg_device *rdev, const char *name,
				    uint32_t dest)
{
	int ret;
	struct rpmsg_virtio_device *rvdev =
		container_of(rdev, struct rpmsg_virtio_device, rdev);
	struct rpmsg_device_priv *priv =
		container_of(rvdev, struct rpmsg_device_priv, rvdev);

	// frontend is expected to announce a service called "sink"
	const char expected[] = "sink";
	if (strncmp(expected, name, sizeof(expected)) == 0) {
		char msg[MSG_SIZE];
		int i;

		ret = rpmsg_create_ept(&priv->sink_ept, rdev, name,
				       RPMSG_ADDR_ANY, dest, sink_endpoint_cb,
				       sink_endpoint_unbind);
		if (ret != RPMSG_SUCCESS) {
			pr_err("failed to create ept, ret = %d\n", ret);
			return;
		}

		for (i = 0; i < MSG_COUNT; i++) {
			memset(msg, 0, sizeof(msg));
			snprintf(msg, MSG_SIZE, "hello from remote %d!", i);
			ret = rpmsg_trysend(&priv->sink_ept, msg, sizeof(msg));
			if (ret < 0) {
				pr_err("failed to send msg, ret = %d\n", ret);
				return;
			}
		}
	}
}

int rpmsg_device_create(struct virtio_device *vdev, struct metal_io_region *shm_io)
{
	int ret;
	int rpmsg_ret;
	struct rpmsg_device_priv *priv;

	priv = kzalloc(sizeof(struct rpmsg_device_priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	rpmsg_ret = rpmsg_init_vdev(&priv->rvdev, vdev, rproc_remote_ns_bind_cb,
				    shm_io, NULL);
	if (rpmsg_ret != RPMSG_SUCCESS) {
		pr_err("failed to init rpmsg device: %d\n", rpmsg_ret);
		ret = -EINVAL;
		goto err_free_priv;
	}

	mutex_init(&priv->fifo_mutex);
    init_waitqueue_head(&priv->read_queue);

	ret = kfifo_alloc(&priv->rec_fifo, 1024, GFP_KERNEL);
	if (ret) {
		goto err_free_priv;
    }

	// annonce a service called "echo" to frontend
	rpmsg_ret = rpmsg_create_ept(&priv->echo_ept, &priv->rvdev.rdev, "echo",
				     RPMSG_ADDR_ANY, RPMSG_ADDR_ANY,
				     echo_endpoint_cb, echo_endpoint_unbind);
	if (rpmsg_ret) {
		pr_err("failed to create rpmsg ept: %d\n", rpmsg_ret);
		ret = -EINVAL;
		goto err_deinit_rpmsg_vdev;
	}

	if (rpmsg_dev_cal >= DEV_RPMSG_NUM) {
		pr_err("rpmsg rpmsg_dev_cal >= DEV_RPMSG_NUM\n");
		rpmsg_dev_cal = 0;
	}

	priv->priv_index = rpmsg_dev_cal++;
	g_priv[priv->priv_index] = priv;
	ept_open[priv->priv_index] = 1;

	return 0;

err_deinit_rpmsg_vdev:
	rpmsg_deinit_vdev(&priv->rvdev);

err_free_priv:
    kfree(priv);
	return ret;
}

void rpmsg_device_destroy(struct virtio_device *vdev)
{
	struct rpmsg_virtio_device *rvdev = vdev->priv;
	struct rpmsg_device_priv *priv =
		container_of(rvdev, struct rpmsg_device_priv, rvdev);
	int dindex = priv->priv_index;

	ept_open[dindex] = 0;
	wake_up_interruptible(&priv->read_queue);

	rpmsg_deinit_vdev(rvdev);
	pr_info("rpmsg destroy: %d\n", rpmsg_dev_cal--);
	kfifo_free(&priv->rec_fifo);
	kfree(priv);
}

static void rpmsg_device_reset(struct virtio_device *vdev)
{
	pr_debug("rpmsg vdev reset\n");
}

static struct nebula_rproc_vdev_ops rpmsg_vdev_ops = {
	.on_create = rpmsg_device_create,
	.on_destroy = rpmsg_device_destroy,
	.on_reset = rpmsg_device_reset,
};

static dev_t dev_num;
static struct class *rpmsg_class = NULL;
static struct cdev rpmsg_cdevs[DEV_RPMSG_NUM];

static int rpmsg_char_dev_open(struct inode *inode, struct file *file) {
	struct rpmsg_dev_data *dev_data;

	dev_data = container_of(inode->i_cdev, struct rpmsg_dev_data, cdev);
	file->private_data = dev_data;

	if (!ept_open[dev_data->device_index]) {
		pr_err("Ept %d is not ready\n", dev_data->device_index);
		return -EBUSY;
	}

	if (dev_open[dev_data->device_index]) {
		pr_err("Device %d is busy\n", dev_data->device_index);
		return -EBUSY;
	}
	dev_open[dev_data->device_index]++;
	pr_info("Opened rpmsg device %d\n", dev_data->device_index);
	return 0;
}

static int rpmsg_char_dev_release(struct inode *inode, struct file *file) {
	struct rpmsg_dev_data *dev_data;

	dev_data = container_of(inode->i_cdev, struct rpmsg_dev_data, cdev);
	file->private_data = dev_data;

	dev_open[dev_data->device_index]--;
	pr_info("Closed rpmsg device %d\n", dev_data->device_index);
	return 0;
}

static ssize_t rpmsg_char_dev_read(struct file *file, char __user *buf, size_t count, loff_t *offset) {
	int ret;
	unsigned int copied;
	struct rpmsg_dev_data *dev_data = file->private_data;
	int rindex = dev_data->device_index;
	// pr_info("Reading from device %d\n", dev_data->device_index);

	if (!g_priv[rindex]) {
		pr_err("priv not ready\n");
		return -ENOMEM;
	}

    if (kfifo_is_empty(&g_priv[rindex]->rec_fifo)) {
        if (file->f_flags & O_NONBLOCK)
            return -EAGAIN;
        ret = wait_event_interruptible(g_priv[rindex]->read_queue, ept_open[rindex] == 0 || !kfifo_is_empty(&g_priv[rindex]->rec_fifo));
		if (!ept_open[rindex])
			return 0;
        if (ret)
            return ret;
    }

	mutex_lock(&g_priv[rindex]->fifo_mutex);
    ret = kfifo_to_user(&g_priv[rindex]->rec_fifo, buf, count, &copied);
	mutex_unlock(&g_priv[rindex]->fifo_mutex);

    return ret ? ret : copied;
}

static ssize_t rpmsg_char_dev_write(struct file *file, const char __user *buf, size_t count, loff_t *offset) {
    int ret;
    char *kbuf;
	struct rpmsg_dev_data *dev_data = file->private_data;
	int windex = dev_data->device_index;
	// pr_info("Reading from device %d\n", dev_data->device_index);

    if (!g_priv[windex]) {
        pr_err("priv not ready\n");
        return -ENOMEM;
    }

    kbuf = kzalloc(count, GFP_KERNEL);
    if (!kbuf) {
        pr_err("Failed to allocate memory\n");
        return -ENOMEM;
    }

    if (copy_from_user(kbuf, buf, count)) {
        pr_err("Failed to copy data from user\n");
        ret = -EFAULT;
        goto out;
    }

    ret = rpmsg_send(&g_priv[windex]->echo_ept, kbuf, count);
    if (ret < 0) {
        pr_err("rpmsg_send failed: %d\n", ret);
        goto out;
    }

    ret = count;

out:
    kfree(kbuf);
    return ret;
}

static struct file_operations rpmsg_dev_fops = {
    .open = rpmsg_char_dev_open,
    .read = rpmsg_char_dev_read,
    .write = rpmsg_char_dev_write,
    .release = rpmsg_char_dev_release,
};

static void setup_char_devs(void)
{
    int i, ret;
    for (i = 0; i < DEV_RPMSG_NUM; ++i) {
        cdev_init(&rpmsg_devices[i].cdev, &rpmsg_dev_fops);
        rpmsg_devices[i].device_index = i;
        ret = cdev_add(&rpmsg_devices[i].cdev, MKDEV(MAJOR(dev_num), MINOR(dev_num) + i), 1);
        if (ret < 0) {
            pr_err("Failed to add cdev for device %d\n", i);
        }
    }
}

static int __init nebula_rpmsg_sample_init(void)
{
    int ret;

    ret = alloc_chrdev_region(&dev_num, 0, DEV_RPMSG_NUM, "rpmsg_devs");
    if (ret < 0) {
        pr_err("Failed to allocate chrdev region\n");
        return ret;
    }

    rpmsg_class = class_create("rpmsg_class");
    if (IS_ERR(rpmsg_class)) {
        unregister_chrdev_region(dev_num, DEV_RPMSG_NUM);
        return PTR_ERR(rpmsg_class);
    }

    setup_char_devs();

    for (int i = 0; i < DEV_RPMSG_NUM; ++i) {
        device_create(rpmsg_class, NULL, MKDEV(MAJOR(dev_num), MINOR(dev_num) + i), NULL, "rpmsg%d", i);
    }

	for (int i = 0; i < DEV_RPMSG_NUM; ++i) {
		nebula_rproc_register_device(&rpmsg_desc, sizeof(rpmsg_desc),
						&rpmsg_vdev_ops);
	}
	return 0;
}

static void __exit nebula_rpmsg_sample_exit(void)
{
    int i;
    for (i = 0; i < DEV_RPMSG_NUM; ++i) {
        device_destroy(rpmsg_class, MKDEV(MAJOR(dev_num), MINOR(dev_num) + i));
        cdev_del(&rpmsg_cdevs[i]);
    }

    class_destroy(rpmsg_class);
    unregister_chrdev_region(dev_num, DEV_RPMSG_NUM);
}

module_init(nebula_rpmsg_sample_init);
module_exit(nebula_rpmsg_sample_exit);
MODULE_LICENSE("Dual BSD/GPL");
