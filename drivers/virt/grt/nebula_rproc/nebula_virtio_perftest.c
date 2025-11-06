// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright 2023 GoldenRiver Technologies Co., Ltd.
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

#include <linux/dma-mapping.h>
#include <linux/debugfs.h>
#include <linux/wait.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/virtio.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_config.h>
#include <linux/sched/clock.h>
#include <uapi/linux/sched/types.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/completion.h>

#define VIRTIO_ID_SAMPLE 80U

struct perftest_priv *s_priv;

struct statistic {
	uint64_t counter_us;
	uint64_t max_us;
	uint64_t min_us;
};

struct perftest_priv {
	struct virtio_device *vdev;
	volatile bool received;
	struct completion done;
	struct completion all_done;
	uint64_t remote_ts;

	struct statistic uos_latency;
	struct statistic sos_latency;

	int last_sbuf;
	void *rbufs, *sbufs;
	unsigned int num_bufs;
	unsigned int buf_size;
	dma_addr_t bufs_dma;

	struct virtqueue *rvq;
	struct virtqueue *svq;
};

static void statistic_init(struct statistic *s)
{
	s->counter_us = 0;
	s->max_us = 0;
	s->min_us = ULONG_MAX;
}

static void statistic_add_value(struct statistic *s, uint64_t value)
{
	if (value > s->max_us)
		s->max_us = value;
	if (value < s->min_us)
		s->min_us = value;
	s->counter_us += value;
}

static uint64_t ticks_to_us(uint64_t ticks)
{
	u32 ticks_per_second = arch_timer_get_cntfrq();
	return ticks * 1000000 / ticks_per_second;
}

#define WAIT_TIMEOUT HZ
#define NUM_ITERATIONS 10000

static int perftest_recv_single(struct perftest_priv *priv,
				 struct device *dev, void *msg,
				 unsigned int len)
{
	struct scatterlist sg;
	int err;

	priv->remote_ts = *(uint64_t *)msg;
	complete(&priv->done);

	sg_init_table(&sg, 1);
	sg_set_page(&sg, vmalloc_to_page(msg), len, offset_in_page(msg));
	err = virtqueue_add_inbuf(priv->rvq, &sg, 1, msg, GFP_KERNEL);
	if (err < 0) {
		dev_err(dev, "failed to add a virtqueue buffer: %d\n", err);
		return err;
	}

	return 0;
}

/* super simple buffer "allocator" that is just enough for now */
static void *get_a_tx_buf(struct perftest_priv *priv, unsigned int *len)
{
	void *ret;

	/*
	 * either pick the next unused tx buffer
	 * (half of our buffers are used for sending messages)
	 */
	if (priv->last_sbuf < priv->num_bufs / 2)
		ret = priv->sbufs + priv->buf_size * priv->last_sbuf++;
	/* or recycle a used one */
	else
		ret = virtqueue_get_buf(priv->svq, len);

	return ret;
}

static void perftest_send_single(struct perftest_priv *priv)
{
	int err;
	struct scatterlist sg;
	unsigned int len;

	void *msg = get_a_tx_buf(priv, &len);
	BUG_ON(msg == NULL);

	sg_init_table(&sg, 1);
	sg_set_page(&sg, vmalloc_to_page(msg), len, offset_in_page(msg));
	err = virtqueue_add_inbuf(priv->svq, &sg, 1, msg, GFP_KERNEL);
	BUG_ON(err != 0);

	virtqueue_kick(priv->svq);
}

static void roundtrip_test(struct perftest_priv *priv)
{
	u64 start, end;
	u64 uos_latency_us;
	u64 sos_latency_us;

	init_completion(&priv->done);

	start = __arch_counter_get_cntvct();

	perftest_send_single(priv);

	wait_for_completion_timeout(&priv->done, WAIT_TIMEOUT);
	end = __arch_counter_get_cntvct();

	uos_latency_us = ticks_to_us(priv->remote_ts - start);
	sos_latency_us = ticks_to_us(end - priv->remote_ts);
	statistic_add_value(&priv->uos_latency, uos_latency_us);
	statistic_add_value(&priv->sos_latency, sos_latency_us);
}

static int rpmsg_test(void *data) {
	struct perftest_priv *priv = s_priv;
	struct device *dev = &priv->vdev->dev;
	int i;

	statistic_init(&priv->uos_latency);
	statistic_init(&priv->sos_latency);

	for (i = 0; i < NUM_ITERATIONS; i++) {
		roundtrip_test(priv);
	}

	dev_info(dev, "uos notify latency:\n");
	dev_info(dev, "  average: %lld us\n",
		 priv->uos_latency.counter_us / NUM_ITERATIONS);
	dev_info(dev, "  max: %lld us\n", priv->uos_latency.max_us);
	dev_info(dev, "  min: %lld us\n", priv->uos_latency.min_us);
	dev_info(dev, "sos notify latency:\n");
	dev_info(dev, "  average: %lld us\n",
		 priv->sos_latency.counter_us / NUM_ITERATIONS);
	dev_info(dev, "  max: %lld us\n", priv->sos_latency.max_us);
	dev_info(dev, "  min: %lld us\n", priv->sos_latency.min_us);

	complete(&s_priv->all_done);

	return 0;
}

static int trigger_show(struct seq_file *m, void *v)
{
	struct sched_param param = { .sched_priority = 99 };
	struct task_struct *task = kthread_create(rpmsg_test, NULL, "rpmsg_thread");
	cpumask_t mask;
	cpumask_clear(&mask);
	cpumask_set_cpu(5, &mask);

	init_completion(&s_priv->all_done);
	sched_setscheduler(task, SCHED_FIFO, &param);
	set_cpus_allowed_ptr(task, &mask);
	wake_up_process(task);
	wait_for_completion(&s_priv->all_done);
	return 0;
}

static int trigger_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, trigger_show, inode->i_private);
}

static const struct file_operations trigger_fops = {
	.open = trigger_open,
	.release = single_release,
	.read = seq_read,
	.owner = THIS_MODULE,
};

#define MAX_NUM_BUFS (512)
#define MAX_BUF_SIZE (512)

static void perftest_recv_done(struct virtqueue *rvq)
{
	struct perftest_priv *priv = rvq->vdev->priv;
	struct device *dev = &rvq->vdev->dev;
	void *msg;
	unsigned int len, msgs_received = 0;
	int err;

	msg = virtqueue_get_buf(rvq, &len);
	if (!msg) {
		dev_err(dev, "uhm, incoming signal, but no used buffer ?\n");
		return;
	}

	while (msg) {
		err = perftest_recv_single(priv, dev, msg, len);
		if (err)
			break;

		msgs_received++;

		msg = virtqueue_get_buf(rvq, &len);
	}

	/* tell the remote processor we added another available rx buffer */
	if (msgs_received)
		virtqueue_kick(priv->rvq);
}

static void perftest_xmit_done(struct virtqueue *svq)
{
}

static int perftest_probe(struct virtio_device *vdev)
{
	vq_callback_t *vq_cbs[] = { perftest_recv_done, perftest_xmit_done };
	static const char *const names[] = { "input", "output" };
	struct virtqueue *vqs[2];
	void *bufs_va;
	int err = 0, i;
	size_t total_buf_space;
	bool notify;
	const char *dir_name = "virtio_perftest";

	struct perftest_priv *priv;
	struct dentry *debugfs_root;

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	priv->vdev = vdev;

	/* We expect two virtqueues, rx and tx (and in this order) */
	err = virtio_find_vqs(vdev, 2, vqs, vq_cbs, names, NULL);
	if (err)
		goto free_priv;

	priv->rvq = vqs[0];
	priv->svq = vqs[1];

	/* we expect symmetric tx/rx vrings */
	WARN_ON(virtqueue_get_vring_size(priv->rvq) !=
		virtqueue_get_vring_size(priv->svq));

	/* we need less buffers if vrings are small */
	if (virtqueue_get_vring_size(priv->rvq) < MAX_NUM_BUFS / 2)
		priv->num_bufs = virtqueue_get_vring_size(priv->rvq) * 2;
	else
		priv->num_bufs = MAX_NUM_BUFS;

	priv->buf_size = MAX_BUF_SIZE;

	total_buf_space = priv->num_bufs * priv->buf_size;

	/* allocate coherent memory for the buffers */
	bufs_va = dma_alloc_coherent(vdev->dev.parent, total_buf_space,
				     &priv->bufs_dma, GFP_KERNEL);
	if (!bufs_va) {
		err = -ENOMEM;
		goto vqs_del;
	}

	dev_dbg(&vdev->dev, "buffers: va %pK, dma %pad\n", bufs_va,
		&priv->bufs_dma);

	/* half of the buffers is dedicated for RX */
	priv->rbufs = bufs_va;

	/* and half is dedicated for TX */
	priv->sbufs = bufs_va + total_buf_space / 2;

	/* set up the receive buffers */
	for (i = 0; i < priv->num_bufs / 2; i++) {
		struct scatterlist sg;
		void *cpu_addr = priv->rbufs + i * priv->buf_size;

		sg_init_table(&sg, 1);
		sg_set_page(&sg, vmalloc_to_page(cpu_addr), priv->buf_size,
			    offset_in_page(cpu_addr));

		err = virtqueue_add_inbuf(priv->rvq, &sg, 1, cpu_addr,
					  GFP_KERNEL);
		WARN_ON(err); /* sanity check; this can't really happen */
	}

	/* suppress "tx-complete" interrupts */
	virtqueue_disable_cb(priv->svq);

	vdev->priv = priv;

	/*
	 * Prepare to kick but don't notify yet - we can't do this before
	 * device is ready.
	 */
	notify = virtqueue_kick_prepare(priv->rvq);

	/* From this point on, we can notify and get callbacks. */
	virtio_device_ready(vdev);

	/* tell the remote processor it can start sending messages */
	/*
	 * this might be concurrent with callbacks, but we are only
	 * doing notify, not a full kick here, so that's ok.
	 */
	if (notify)
		virtqueue_notify(priv->rvq);

	dev_info(&vdev->dev, "nebula virtio perftest ready\n");

	debugfs_root = debugfs_create_dir(dir_name, NULL);
	BUG_ON(IS_ERR(debugfs_root));

	debugfs_create_file("trigger", 0600, debugfs_root, priv, &trigger_fops);

	s_priv = priv;

	return 0;

vqs_del:
	vdev->config->del_vqs(priv->vdev);
free_priv:
	kfree(priv);
	return err;
}

static void perftest_remove(struct virtio_device *vdev)
{
	struct perftest_priv *priv = vdev->priv;
	kfree(priv);
}

static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_SAMPLE, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static struct virtio_driver perftest_driver = {
	.feature_table_size = 0,
	.driver.name = KBUILD_MODNAME,
	.driver.owner = THIS_MODULE,
	.id_table = id_table,
	.probe = perftest_probe,
	.remove = perftest_remove,
};

static int __init perftest_driver_init(void)
{
	return register_virtio_driver(&perftest_driver);
}
module_init(perftest_driver_init);

MODULE_DEVICE_TABLE(virtio, id_table);
MODULE_LICENSE("Dual BSD/GPL");