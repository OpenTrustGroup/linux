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

#include <linux/debugfs.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/nebula/trusty_kern_ipc.h>
#include <uapi/linux/uio.h>

static int kMaxTestCpus = 2;
static char *dev_name = "/dev/trusty-ipc-dev0";
static char *srv_names[] = {
	"com.android.ipc-unittest.srv.echo",
	"com.android.ipc-unittest.srv.uuid",
};
static char *srv_inputs[] = {
	"com.android.ipc-unittest.srv.echo",
	NULL,
};

struct tipc_work {
	char *dev_name;
	char *srv_name;
	char *srv_input;
	struct work_struct work;
};

#define ASSERT_INT_EQ(actual, expect) WARN_ON(((actual) != (expect)))
#define ASSERT_INT_GE(actual, expect) WARN_ON(((actual) < (expect)))

static void trusty_kern_ipc_negative(const char *dev_name,
		const char *srv_name,
		const char *srv_input)
{
	int fd;
	char buf[128];

	ASSERT_INT_EQ(tipc_connect(NULL, srv_name), -1);
	ASSERT_INT_EQ(tipc_connect(dev_name, NULL), -1);
	ASSERT_INT_EQ(tipc_connect(NULL, NULL), -1);

	ASSERT_INT_EQ(tipc_read(0, buf, sizeof(buf)), -1);
	ASSERT_INT_EQ(tipc_read(1, buf, sizeof(buf)), -1);
	ASSERT_INT_EQ(tipc_read(-1, buf, sizeof(buf)), -1);

	ASSERT_INT_EQ(tipc_write(0, buf, sizeof(buf)), -1);
	ASSERT_INT_EQ(tipc_write(1, buf, sizeof(buf)), -1);
	ASSERT_INT_EQ(tipc_write(-1, buf, sizeof(buf)), -1);

	ASSERT_INT_EQ(tipc_close(0), -1);
	ASSERT_INT_EQ(tipc_close(1), -1);
	ASSERT_INT_EQ(tipc_close(-1), -1);

	fd = tipc_connect(dev_name, srv_name);
	ASSERT_INT_GE(fd, 0);
	ASSERT_INT_EQ(tipc_read(fd, NULL, sizeof(buf)), -1);
	ASSERT_INT_EQ(tipc_read(fd, buf, 0), -1);
	ASSERT_INT_EQ(tipc_read(fd, NULL, 0), -1);
	ASSERT_INT_EQ(tipc_write(fd, NULL, sizeof(buf)), -1);
	ASSERT_INT_EQ(tipc_write(fd, buf, 0), -1);
	ASSERT_INT_EQ(tipc_write(fd, NULL, 0), -1);
	ASSERT_INT_GE(tipc_close(fd), 0);
}

static void trusty_kern_ipc_basic(const char *dev_name,
		const char *srv_name,
		const char *srv_input)
{
	int fd;
	char buf[128];

	memset(buf, 0, sizeof(buf));
	fd = tipc_connect(dev_name, srv_name);
	ASSERT_INT_GE(fd, 0);
	if (srv_input)
		ASSERT_INT_GE(tipc_write(fd, srv_input, strlen(srv_input)), 0);
	ASSERT_INT_GE(tipc_read(fd, buf, sizeof(buf)), 0);
	pr_debug("%s: buf %s len %zu\n", __func__, buf, strlen(buf));
	ASSERT_INT_GE(tipc_close(fd), 0);
}

static void trusty_kern_ipc_msg(const char *dev_name,
		const char *srv_name,
		const char *srv_input)
{
	int fd;
	char buf[128];
	struct iovec iov = {};

	memset(buf, 0, sizeof(buf));
	fd = tipc_connect(dev_name, srv_name);
	ASSERT_INT_GE(fd, 0);
	if (srv_input) {
		iov.iov_base = (char *)srv_input;
		iov.iov_len = strlen(srv_input);
		ASSERT_INT_GE(tipc_send_msg(fd, &iov, 1, NULL, 0), 0);
	}
	iov.iov_base = &buf;
	iov.iov_len = sizeof(buf);
	ASSERT_INT_GE(tipc_recv_msg(fd, &iov, 1), 0);
	pr_debug("%s: buf %s len %zu\n", __func__, (char *)iov.iov_base,
			strlen(iov.iov_base));
	ASSERT_INT_GE(tipc_close(fd), 0);
}

static void work_func(struct work_struct *work)
{
	struct tipc_work *tw = container_of(work, struct tipc_work, work);

	pr_debug("%s: cpu: %u\n", __func__, smp_processor_id());
	trusty_kern_ipc_basic(tw->dev_name, tw->srv_name, tw->srv_input);
	trusty_kern_ipc_msg(tw->dev_name, tw->srv_name, tw->srv_input);
}

static void trusty_kern_ipc_thread(void)
{
	unsigned int cpu;
	struct workqueue_struct *wq;
	struct tipc_work __percpu *works;

	wq = alloc_workqueue("trusty-kern-ipc-wq", WQ_CPU_INTENSIVE, 0);
	works = alloc_percpu(struct tipc_work);
	for_each_online_cpu(cpu) {
		struct tipc_work *tw = per_cpu_ptr(works, cpu);

		if (cpu >= kMaxTestCpus)
			break;
		tw->dev_name = dev_name;
		tw->srv_name = srv_names[cpu];
		tw->srv_input = srv_inputs[cpu];
		INIT_WORK(&tw->work, work_func);
	}
	for_each_online_cpu(cpu) {
		if (cpu >= kMaxTestCpus)
			break;
		queue_work_on(cpu, wq, &per_cpu_ptr(works, cpu)->work);
	}
	for_each_online_cpu(cpu) {
		if (cpu >= kMaxTestCpus)
			break;
		flush_work(&per_cpu_ptr(works, cpu)->work);
	}

	free_percpu(works);
	destroy_workqueue(wq);
}

static int trusty_kern_ipc_sample_show(struct seq_file *m, void *v)
{
	trusty_kern_ipc_basic(dev_name, srv_names[0], srv_inputs[0]);
	trusty_kern_ipc_msg(dev_name, srv_names[0], srv_inputs[0]);
	trusty_kern_ipc_negative(dev_name, srv_names[0], srv_inputs[0]);
	trusty_kern_ipc_thread();
	pr_info("Trusty Kernel IPC UT PASS!\n");
	return 0;
}

static int trusty_kern_ipc_sample_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, trusty_kern_ipc_sample_show, NULL);
}

static const struct file_operations sample_fops = {
	.open = trusty_kern_ipc_sample_open,
	.read = seq_read,
	.release = single_release,
};

int trusty_kern_ipc_sample_init(void)
{
	struct dentry *debugfs_root;
	const char *dev_name = "trusty-kern-ipc-sample";

	pr_debug("%s\n", __func__);

	debugfs_root = debugfs_create_dir(dev_name, NULL);
	if (!IS_ERR_OR_NULL(debugfs_root)) {
		debugfs_create_file("ut", 0600,
				debugfs_root, NULL, &sample_fops);
	} else {
		pr_err("debugfs_create_dir '%s' failed ret %ld\n",
				dev_name, PTR_ERR(debugfs_root));
	}

	return 0;
}

void trusty_kern_ipc_sample_cleanup(void)
{
	pr_debug("%s\n", __func__);
}

late_initcall(trusty_kern_ipc_sample_init);
