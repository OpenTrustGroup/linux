/* SPDX-License-Identifier: GPL-2.0-only */

#include <asm/acrn.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/genalloc.h>
#include <linux/ioctl.h>
#include <linux/uaccess.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/of_reserved_mem.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/time.h>

#define NEBULA_RTC_IOC_MAGIC 'r'

#define HC_GUEST_SET_RTC 0xB0000011
#define HC_GUEST_GET_RTC 0xB0000012

static int g_major;
static struct class *g_class;
static struct device *g_dev;

void set_nebula_rtc2(uint64_t tv_nsec, int tz_min_west)
{
	acrn_hypercall2(HC_GUEST_SET_RTC, tv_nsec, tz_min_west);
}
EXPORT_SYMBOL(set_nebula_rtc2);

void set_nebula_rtc(void)
{
	struct timespec64 ts;
	uint64_t tv_nsec = 0;
	int tz_minuteswest = sys_tz.tz_minuteswest;

	ktime_get_real_ts64(&ts);
	tv_nsec = timespec64_to_ns(&ts);

	pr_debug("%s: rtc time = (%lld.%ld)\n", __func__, ts.tv_sec, ts.tv_nsec);
	pr_debug("%s: tz_minuteswest = (%d)\n", __func__, tz_minuteswest);

	set_nebula_rtc2(tv_nsec, tz_minuteswest);
}
EXPORT_SYMBOL(set_nebula_rtc);

int get_nebula_rtc(uint64_t *tv_nsec, int *tz_min_west)
{
	struct arm_smccc_res res;
	long ret;

	ret = acrn_hypercall5_res(HC_GUEST_GET_RTC, 0, 0, 0, 0, 0, &res);
	if (ret != 0) {
		return -1;
	}

	*tv_nsec = res.a1;
	*tz_min_west = (int)res.a2;
	return 0;
}
EXPORT_SYMBOL(get_nebula_rtc);

static long nebula_rtc_ioctl(struct file *filp, unsigned int cmd,
			     unsigned long ioctl_param)
{
	long ret;
	if (_IOC_TYPE(cmd) != NEBULA_RTC_IOC_MAGIC)
		return -EINVAL;

	switch (cmd) {
	default:
		dev_warn(g_dev, "%s: Unhandled ioctl cmd: 0x%x\n", __func__,
			 cmd);
		ret = -EINVAL;
	}
	return ret;
}

static int nebula_rtc_open(struct inode *inodep, struct file *filep)
{
	return 0;
}

static int nebula_rtc_release(struct inode *inodep, struct file *filp)
{
	return 0;
}

static struct file_operations fops = {
	.owner = THIS_MODULE,
	.open = nebula_rtc_open,
	.release = nebula_rtc_release,
	.unlocked_ioctl = nebula_rtc_ioctl,
};

extern struct timezone sys_tz;

static ssize_t rtc_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct timespec64 ts;
	uint64_t tv_nsec = 0;
	int tz_minuteswest;
	int ret;

	ret = get_nebula_rtc(&tv_nsec, &tz_minuteswest);
	if (ret < 0) {
		pr_err("%s: failed to get nebula RTC\n", __func__);
		return -EIO;
	}

	ts = ns_to_timespec64(tv_nsec);

	pr_debug("%s: rtc time = (%lld.%ld)\n", __func__, ts.tv_sec, ts.tv_nsec);
	pr_debug("%s: tz_minuteswest = (%d)\n", __func__, tz_minuteswest);

	return scnprintf(buf, PAGE_SIZE, "%lld.%ld (tz_minuteswest: %d)\n",
		ts.tv_sec, ts.tv_nsec, tz_minuteswest);
}

static ssize_t rtc_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	set_nebula_rtc();
	return count;
}

static DEVICE_ATTR_RW(rtc);

static int __init nebula_rtc_init(void)
{
	int err;

	/* Try to dynamically allocate a major number for the device */
	err = register_chrdev(0, KBUILD_MODNAME, &fops);
	if (err < 0) {
		pr_warn("%s: failed to register nebula rtc device\n", __func__);
		goto err_register_chrdev;
	}
	g_major = err;
	pr_info("%s: registered correctly with major number %d\n", __func__,
		g_major);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
	g_class = class_create(KBUILD_MODNAME);
#else
	g_class = class_create(THIS_MODULE, KBUILD_MODNAME);
#endif
	if (IS_ERR(g_class)) {
		err = PTR_ERR(g_class);
		pr_err("%s: class_create failed: %d\n", __func__, err);
		goto err_class_create;
	}

	g_dev = device_create(g_class, NULL, MKDEV(g_major, 0), NULL,
			      KBUILD_MODNAME);
	if (IS_ERR(g_dev)) {
		pr_warn("%s: failed to create the device\n", __func__);
		err = PTR_ERR(g_dev);
		goto err_device_create;
	}

	err = device_create_file(g_dev, &dev_attr_rtc);
	if (err) {
		pr_err("Failed to create device file: rtc\n");
		goto err_create_rtc_device_file;
	}

	set_nebula_rtc();
	return 0;

err_create_rtc_device_file:
	device_destroy(g_class, MKDEV(g_major, 0));
err_device_create:
	class_destroy(g_class);
err_class_create:
	unregister_chrdev(g_major, KBUILD_MODNAME);
err_register_chrdev:
	return err;
}

static void __exit nebula_rtc_exit(void)
{
	device_remove_file(g_dev, &dev_attr_rtc);

	if (g_dev)
		device_destroy(g_class, MKDEV(g_major, 0));

	if (g_class)
		class_destroy(g_class);

	if (g_major)
		unregister_chrdev(g_major, KBUILD_MODNAME);
}

module_init(nebula_rtc_init);
module_exit(nebula_rtc_exit);

MODULE_LICENSE("GPL v2");
