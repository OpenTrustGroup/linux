// SPDX-License-Identifier: GPL-2.0+
/*
 * vmlog interface to hvc_console.c
 *
 * Copyright 2025 GoldenRiver Technologies Co., Ltd. All rights reserved.
 */

#include <linux/console.h>
#include <linux/delay.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/kthread.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_reserved_mem.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/types.h>
#include <linux/version.h>
#include <asm/page.h>
#include <asm/acrn.h>

#include "trusty-log-def.h"

#ifdef pr_fmt
#undef pr_fmt
#endif

#define pr_fmt(fmt) "[%s:%d]" fmt,__func__,__LINE__

#define DISABLE_POLLING_AFTER_MS 5000

struct memlog {
	spinlock_t log_rb_lock;
	struct log_rb *rb;
	size_t rb_sz;

	phys_addr_t buf_pa;
	size_t buf_sz;
};

static struct memlog vmlog_sink_client;

#if USE_POLLING_MODE
static struct timer_list disable_polling_timer;
static bool polling_disabled = false;
#endif

static inline long hcall_notify_vmlog_sinking(void) {
#if USE_POLLING_MODE
	if (!likely(polling_disabled)) {
		return 0;
	}
#endif
	return acrn_fastcall0(FC_ID_NOTIFY_VMLOG_SINK);
}

#if USE_POLLING_MODE
void disable_polling_timer_callback(struct timer_list *timer) {
	polling_disabled = true;
	pr_info("disable vmlog client polling mode\n");
}
#endif

static inline u32 u32_add_overflow(u32 a, u32 b) {
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

static void __memlog_write(struct memlog *log, const char *str, size_t len) {
	uint32_t i;
	uint32_t log_offset;
	struct log_rb *rb = log->rb;

	log_offset = rb->alloc;
	rb->alloc = u32_add_overflow(rb->alloc, len);

	smp_wmb();

	for (i = 0; i < len; i++) {
		uint32_t offset = u32_add_overflow(log_offset, i);
		offset &= (log->rb_sz - 1);
		volatile char *ptr = &rb->data[offset];
		*ptr = str[i];
	}

	smp_wmb();

	rb->put += len;
}

static void memlog_write(struct memlog *log, const char *str, size_t len) {
	size_t i;
	const int chunk_size = 128;
	size_t rem;
	unsigned long flags = 0;

	spin_lock_irqsave(&log->log_rb_lock, flags);
	for (i = 0; i < len / chunk_size; i++) {
		__memlog_write(log, &str[i * chunk_size], chunk_size);
	}
	rem = len - i * chunk_size;
	if (rem)
		__memlog_write(log, &str[i * chunk_size], rem);
	spin_unlock_irqrestore(&log->log_rb_lock, flags);
}

static void vmlog_console_write(struct console *con, const char *str, unsigned int len) {
	memlog_write(&vmlog_sink_client, str, (size_t)len);
	hcall_notify_vmlog_sinking();
}

static struct console vmlog_console = {
	.name	= "vmlog-sink",
#if ENABLE_VMLOG_SELF_TEST
	.flags	= 0,
#else
	.flags	= CON_ENABLED,
#endif
	.write	= vmlog_console_write,
};

static int vmlog_test_write(const char *val, const struct kernel_param *kp) {
	size_t len = strlen(val);
	memlog_write(&vmlog_sink_client, val, len);
	hcall_notify_vmlog_sinking();
	return 0;
}

static int vmlog_test_read(char *buffer, const struct kernel_param *kp) {
	// not support
	return 0;
}

module_param_call(vmlog_sink_test, vmlog_test_write, vmlog_test_read, NULL, 0644);

static int vmlog_console_init(void) {
	register_console(&vmlog_console);
	return 0;
}

static void vmlog_console_deinit(void) {
	unregister_console(&vmlog_console);
}

// disable output printk message to virtio-console
static int disable_hvc(void *data) {
	struct console *con = NULL;
	bool found_hvc_console = false;
	int retry = 3;

retry_disable_hvc:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
	console_list_lock();
#else
	console_lock();
#endif
	for_each_console(con) {
		if (!strncmp(con->name, "hvc", 3)) {
			found_hvc_console = true;
			pr_info("disable %s\n", con->name);
			WRITE_ONCE(con->flags, READ_ONCE(con->flags) & ~CON_ENABLED);
			break;
		}
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
	console_list_unlock();
#else
	console_unlock();
#endif

	if (!found_hvc_console) {
		if (retry > 0) {
			retry--;
			mdelay(100);
			goto retry_disable_hvc;
		}

		pr_warn("hvc console not found\n");
	}

	return 0;
}

static int vmlog_sinking_probe(struct platform_device *pdev) {
	int ret;
	struct log_rb *rb;
	struct resource *rmem;
	resource_size_t buf_sz;
	struct memlog *log = &vmlog_sink_client;

	rmem = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!rmem) {
		ret = -EINVAL;
		goto out;
	}

	buf_sz = resource_size(rmem);
	pr_info("platform_get_resource, Physical address: %pa buf_sz:0x%llx\n", &rmem->start, buf_sz);

	log->buf_pa = rmem->start;
	log->buf_sz = buf_sz;

	pr_info("devm_ioremap offset:%llx\n", rmem->start);
	rb = (struct log_rb *)devm_memremap(&pdev->dev, rmem->start, buf_sz, MEMREMAP_WB);
	if (!rb) {
		pr_err("failed to map memory region\n");
		ret = -ENOMEM;
		return ret;
	}

	log->rb = rb;
	log->rb_sz = rounddown_pow_of_two((uint32_t)(log->buf_sz - offsetof(struct log_rb, data)));
	rb->sz = (uint32_t)log->rb_sz;
	rb->alloc = 0;
	rb->put = 0;
	pr_info("vmlog sinking client ring buffer size=0x%x, reserved_mem buf_pa=0x%llx,size=0x%zx offsetof=0x%lx\n",
					rb->sz, log->buf_pa, log->buf_sz, offsetof(struct log_rb, data));
	spin_lock_init(&log->log_rb_lock);

	vmlog_console_init();

	kthread_run(disable_hvc, NULL, "disable_hvc");

#if USE_POLLING_MODE
	timer_setup(&disable_polling_timer, disable_polling_timer_callback, 0);
	mod_timer(&disable_polling_timer, jiffies + msecs_to_jiffies(DISABLE_POLLING_AFTER_MS));
#endif
	return 0;

out:
	return ret;
}

static int vmlog_sinking_remove(struct platform_device *pdev) {
	vmlog_console_deinit();
	return 0;
}

static const struct of_device_id vmlog_sinking_of_match[] = {
	{
		.compatible = "grt,vmlog-sink",
	},
	{},
};

static struct platform_driver vmlog_sinking_driver = {
	.probe = vmlog_sinking_probe,
	.remove = vmlog_sinking_remove,
	.driver	= {
		.name = "vmlog-sinking",
		.owner = THIS_MODULE,
		.of_match_table = vmlog_sinking_of_match,
	},
};

static int __init vmlog_sink_client_init(void) {
	return platform_driver_register(&vmlog_sinking_driver);
}

module_init(vmlog_sink_client_init);

MODULE_DESCRIPTION("Nebula vmlog Sinking client driver");
MODULE_LICENSE("GPL v2");
