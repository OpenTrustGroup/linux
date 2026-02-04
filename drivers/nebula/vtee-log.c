// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015 Google, Inc.
 */
#include <linux/platform_device.h>
#include <linux/nebula/smcall.h>
#include <linux/nebula/trusty.h>
#include <linux/nebula/nebula_shm.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#include <linux/panic_notifier.h>
#else
#include <linux/notifier.h>
#endif
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/log2.h>
#include <linux/of.h>
#include <asm/page.h>

#include "trusty-log.h"
#include "vtee-log.h"

#define TRUSTY_LOG_SIZE (PAGE_SIZE * 32)
#define TRUSTY_LINE_BUFFER_SIZE 256

struct trusty_log_state {
	struct device *dev;
	struct device *trusty_dev;

	/*
	 * This lock is here to ensure only one consumer will read
	 * from the log ring buffer at a time.
	 */
	struct mutex lock;
	struct log_rb *log;
	uint32_t get;

	struct page *log_pages;

	struct notifier_block call_notifier;
	struct notifier_block panic_notifier;
	char line_buffer[TRUSTY_LINE_BUFFER_SIZE];

	struct workqueue_struct	*dump_log_wq;
	struct work_struct	dump_log_worker;
};

enum vtee_log_to_dmesg_options {
	NEVER = 0,
	ALWAYS,
};

static const char * const vtee_log_to_dmesg_opt_names[] = {
	"never", "always"
};

static int vtee_log_to_dmesg_param = ALWAYS;

static int vtee_log_mode_set(const char *val, const struct kernel_param *kp)
{
	int i = sysfs_match_string(vtee_log_to_dmesg_opt_names, val);
	if (i < 0)
		return i;

	vtee_log_to_dmesg_param = i;
	return 0;
}

static int vtee_log_mode_get(char *buffer, const struct kernel_param *kp)
{
	int i;

	/*
	 * Output buffer is PAGE_SIZE, of which we'll use only 35 bytes,
	 * so bounds checks are not necessary in the following code.
	 */
	*buffer = 0;
	for (i = 0; i < ARRAY_SIZE(vtee_log_to_dmesg_opt_names); i++) {
		if (vtee_log_to_dmesg_param == i)
			strcat(buffer, "[");
		strcat(buffer, vtee_log_to_dmesg_opt_names[i]);
		if (vtee_log_to_dmesg_param == i)
			strcat(buffer, "]");
		strcat(buffer, " ");
	}
	strcat(buffer, "\n");
	return strlen(buffer);
}

module_param_call(vtee_log_to_dmesg, vtee_log_mode_set, vtee_log_mode_get, NULL, 0644);


static inline u32 u32_add_overflow(u32 a, u32 b)
{
	u32 d;

	if (check_add_overflow(a, b, &d)) {
		/*
		 * silence the overflow,
		 * what matters in the log buffer context
		 * is the casted addition
		 */
	}
	return d;
}

static inline u32 u32_sub_overflow(u32 a, u32 b)
{
	u32 d;

	if (check_sub_overflow(a, b, &d)) {
		/*
		 * silence the overflow,
		 * what matters in the log buffer context
		 * is the casted substraction
		 */
	}
	return d;
}

static int log_read_line(struct trusty_log_state *s, u32 put, u32 get)
{
	struct log_rb *log = s->log;
	int i;
	char c = '\0';
	size_t max_to_read =
		min_t(size_t,
		      u32_sub_overflow(put, get),
				 sizeof(s->line_buffer) - 1);
	size_t mask = log->sz - 1;

	for (i = 0; i < max_to_read && c != '\n';) {
		c = log->data[get & mask];
		s->line_buffer[i++] = c;
		get = u32_add_overflow(get, 1);
	}
	s->line_buffer[i] = '\0';

	return i;
}

static void trusty_dump_logs(struct trusty_log_state *s)
{
	struct log_rb *log = s->log;
	uint32_t get, put, alloc;
	int read_chars;

	BUG_ON(!is_power_of_2(log->sz));

	/*
	 * For this ring buffer, at any given point, alloc >= put >= get.
	 * The producer side of the buffer is not locked, so the put and alloc
	 * pointers must be read in a defined order (put before alloc) so
	 * that the above condition is maintained. A read barrier is needed
	 * to make sure the hardware and compiler keep the reads ordered.
	 */
	get = s->get;
	while ((put = log->put) != get) {
		/* Make sure that the read of put occurs before the read of log data */
		rmb();

		/* Read a line from the log */
		read_chars = log_read_line(s, put, get);

		/* Force the loads from log_read_line to complete. */
		rmb();
		alloc = log->alloc;

		/*
		 * Discard the line that was just read if the data could
		 * have been corrupted by the producer.
		 */
		if (u32_sub_overflow(alloc, get) > log->sz) {
			pr_err("nebula-vtee: log overflow.");
			get = u32_sub_overflow(alloc, log->sz);
			continue;
		}
		if (vtee_log_to_dmesg_param)
			pr_info("nebula-vtee: %s", s->line_buffer);
		if (is_vtee_nebula_log_ready())
			vtee_nebula_log_fifo_write(s->line_buffer, read_chars);
		/* compute next line index */
		get = u32_add_overflow(get, read_chars);
	}
	s->get = get;
}

static void dump_log_worker_func(struct work_struct *work)
{
	struct trusty_log_state *s =
		container_of(work, struct trusty_log_state, dump_log_worker);

	mutex_lock(&s->lock);
	trusty_dump_logs(s);
	mutex_unlock(&s->lock);
}

static int trusty_log_call_notify(struct notifier_block *nb,
				  unsigned long action, void *data)
{
	struct trusty_log_state *s;

	if (action != TRUSTY_CALL_RETURNED && action != TRUSTY_NOTIFY_LOG)
		return NOTIFY_DONE;

	s = container_of(nb, struct trusty_log_state, call_notifier);
	queue_work(s->dump_log_wq, &s->dump_log_worker);
	return NOTIFY_OK;
}

static int trusty_log_panic_notify(struct notifier_block *nb,
				   unsigned long action, void *data)
{
	struct trusty_log_state *s;

	/*
	 * Don't grab the spin lock to hold up the panic notifier, even
	 * though this is racy.
	 */
	s = container_of(nb, struct trusty_log_state, panic_notifier);
	pr_info("vtee-log panic notifier - version %s",
		nebula_version_str_get(s->trusty_dev));
	trusty_dump_logs(s);
	return NOTIFY_OK;
}

static bool trusty_supports_logging(struct device *device)
{
	int result;

	result = nebula_std_call32(device, SMC_SC_SHARED_LOG_VERSION,
				   TRUSTY_LOG_API_VERSION, 0, 0);
	if (result == SM_ERR_UNDEFINED_SMC) {
		pr_info("trusty-log not supported on secure side.\n");
		return false;
	} else if (result < 0) {
		pr_err("trusty std call (SMC_SC_SHARED_LOG_VERSION) failed: %d\n",
		       result);
		return false;
	}

	if (result == TRUSTY_LOG_API_VERSION) {
		return true;
	} else {
		pr_info("trusty-log unsupported api version: %d, supported: %d\n",
			result, TRUSTY_LOG_API_VERSION);
		return false;
	}
}

static int vtee_log_probe(struct platform_device *pdev)
{
	struct trusty_log_state *s;
	int result;
	phys_addr_t pa;
	struct device_node *node;
	u32 log_num_pages = DIV_ROUND_UP(TRUSTY_LOG_SIZE + sizeof(struct log_rb),
				PAGE_SIZE);
	size_t log_size = log_num_pages * PAGE_SIZE;

	dev_dbg(&pdev->dev, "%s\n", __func__);

	node = pdev->dev.of_node;
	if (!node)
		return -ENODEV;

	if (!trusty_supports_logging(pdev->dev.parent)) {
		return -ENXIO;
	}

	s = kzalloc(sizeof(*s), GFP_KERNEL);
	if (!s) {
		result = -ENOMEM;
		goto error_alloc_state;
	}

	mutex_init(&s->lock);
	s->dev = &pdev->dev;
	s->trusty_dev = s->dev->parent;
	s->get = 0;

	s->log = nbl_shm_alloc(log_size, GFP_KERNEL | __GFP_ZERO);
	if (!s->log) {
		result = -ENOMEM;
		goto error_alloc_log;
	}
	s->log_pages = virt_to_page(s->log);

	pa = nbl_shm_virt_to_phys(s->log);
	result = nebula_std_call32(s->trusty_dev,
				   SMC_SC_SHARED_LOG_ADD,
				   (u32)(pa), (u32)(pa >> 32),
				   log_size);
	if (result < 0) {
		pr_err("trusty std call (SMC_SC_SHARED_LOG_ADD) failed: %d %pa\n",
		       result, &pa);
		goto error_std_call;
	}

	/* log size is initialized by nebula memlog_add() */
	pr_info("vtee log ring buffer size = %u\n", s->log->sz);

	INIT_WORK(&s->dump_log_worker, dump_log_worker_func);
	s->dump_log_wq = alloc_workqueue("vtee-dump-log-wq", WQ_UNBOUND, 0);
	if (!s->dump_log_wq) {
		result = -ENODEV;
		dev_err(&pdev->dev, "failed to create vtee-dump-log-wq\n");
		goto error_dump_log_wq;
	}

	s->call_notifier.notifier_call = trusty_log_call_notify;
	result = nebula_call_notifier_register(s->trusty_dev,
					       &s->call_notifier);
	if (result < 0) {
		dev_err(&pdev->dev,
			"failed to register trusty call notifier\n");
		goto error_call_notifier;
	}

	s->panic_notifier.notifier_call = trusty_log_panic_notify;
	result = atomic_notifier_chain_register(&panic_notifier_list,
						&s->panic_notifier);
	if (result < 0) {
		dev_err(&pdev->dev,
			"failed to register panic notifier\n");
		goto error_panic_notifier;
	}
	platform_set_drvdata(pdev, s);

	return 0;

error_panic_notifier:
	nebula_call_notifier_unregister(s->trusty_dev, &s->call_notifier);
error_call_notifier:
	destroy_workqueue(s->dump_log_wq);
error_dump_log_wq:
	nebula_std_call32(s->trusty_dev, SMC_SC_SHARED_LOG_RM,
			  (u32)pa, (u32)(pa >> 32), 0);
error_std_call:
	nbl_shm_free(s->log, log_size);
error_alloc_log:
	kfree(s);
error_alloc_state:
	return result;
}

static int vtee_log_remove(struct platform_device *pdev)
{
	int result;
	struct trusty_log_state *s = platform_get_drvdata(pdev);
	phys_addr_t pa = page_to_phys(s->log_pages);
	u32 log_num_pages = DIV_ROUND_UP(TRUSTY_LOG_SIZE + sizeof(struct log_rb),
				PAGE_SIZE);
	size_t log_size = log_num_pages * PAGE_SIZE;

	dev_dbg(&pdev->dev, "%s\n", __func__);

	atomic_notifier_chain_unregister(&panic_notifier_list,
					 &s->panic_notifier);
	nebula_call_notifier_unregister(s->trusty_dev, &s->call_notifier);

	destroy_workqueue(s->dump_log_wq);

	result = nebula_std_call32(s->trusty_dev, SMC_SC_SHARED_LOG_RM,
				   (u32)pa, (u32)(pa >> 32), 0);
	if (result) {
		pr_err("trusty std call (SMC_SC_SHARED_LOG_RM) failed: %d\n",
		       result);
	}
	nbl_shm_free(s->log, log_size);
	kfree(s);

	return 0;
}

static const struct of_device_id vtee_log_of_match[] = {
	{ .compatible = "grt,vtee-log-v1", },
	{},
};

static struct platform_driver vtee_log_driver = {
	.probe = vtee_log_probe,
	.remove = vtee_log_remove,
	.driver = {
		.name = "vtee-trusty-log",
		.owner = THIS_MODULE,
		.of_match_table = vtee_log_of_match,
	},
};

static int __init vtee_log_driver_init(void)
{
	int ret;

	/*
	 * Initialize vtee_nebula_log_driver first since vtee_log driver need to
	 * write log buffer to nebula log buffer.
	 */
	ret = vtee_nebula_log_init();
	if (ret < 0)
		return ret;

	ret = platform_driver_register(&vtee_log_driver);
	if (ret < 0)
		goto err_driver_register;

	return 0;

err_driver_register:
	vtee_nebula_log_exit();
	return ret;
}

static void __exit vtee_log_driver_exit(void)
{
	platform_driver_unregister(&vtee_log_driver);
	vtee_nebula_log_exit();
}

module_init(vtee_log_driver_init);
module_exit(vtee_log_driver_exit);

MODULE_DESCRIPTION("Nebula vTEE log driver");
MODULE_LICENSE("GPL v2");
