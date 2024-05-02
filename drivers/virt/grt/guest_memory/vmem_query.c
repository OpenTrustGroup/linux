/* SPDX-License-Identifier: GPL-2.0-only */

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

#define VMEM_QUERY_IOC_MAGIC 'v'
#define VMEM_QUERY_IOC_QUERY _IOW(VMEM_QUERY_IOC_MAGIC, 0x81, char *)

static int g_major;
static struct class *g_class;
static struct device *g_dev;

#if 0
extern phys_addr_t gConEmiPhyBase;
extern unsigned long long gConEmiSize;
#endif

enum vmem_type {
	VMEM_TYPE_FRAMEBUFFER,
	VMEM_TYPE_PICACHU,
	VMEM_TYPE_ATF_LOG_RESERVED,
	VMEM_TYPE_LOG_STORE,
	VMEM_TYPE_CONSYS,
};

struct vmem_query_response {
	enum vmem_type type;
	uint64_t base;
	uint64_t size;
};

static int get_reserved_memory_region(const char *compatible,
				      struct vmem_query_response *rsp)
{
	struct device_node *node;
	uint32_t regs[4];

	node = of_find_compatible_node(NULL, NULL, compatible);
	if (!node) {
		dev_err(g_dev, "failed to get device node of compatible %s\n",
			compatible);
		return -EINVAL;
	}

	if (of_property_read_u32_array(node, "reg", regs, 4)) {
		dev_err(g_dev, "failed to get property of comptabile %s\n",
			compatible);
		return -EINVAL;
	}

	rsp->base = ((uint64_t)regs[0] << 32) | (uint64_t)regs[1];
	rsp->size = ((uint64_t)regs[2] << 32) | (uint64_t)regs[3];

	of_node_put(node);
	return 0;
}

static long handle_query_vmem_region(struct file *filp,
				     unsigned long ioctl_param)
{
	struct vmem_query_response rsp;
	int ret = 0;

	if (copy_from_user(&rsp, (void *)ioctl_param, sizeof(rsp)))
		return -EFAULT;

	switch (rsp.type) {
	case VMEM_TYPE_FRAMEBUFFER:
		ret = get_reserved_memory_region("mediatek,framebuffer", &rsp);
		break;
	case VMEM_TYPE_PICACHU:
		ret = get_reserved_memory_region("mediatek,PICACHU", &rsp);
		break;
	case VMEM_TYPE_ATF_LOG_RESERVED:
		ret = get_reserved_memory_region("mediatek,atf-log-reserved",
						 &rsp);
		break;
	case VMEM_TYPE_LOG_STORE:
		ret = get_reserved_memory_region("mediatek,log_store", &rsp);
		break;
#if 0
	case VMEM_TYPE_CONSYS:
		rsp.base = gConEmiPhyBase;
		rsp.size = gConEmiSize;
		break;
#endif
	default:
		dev_err(g_dev, "unknown vmem type %u\n", rsp.type);
		ret = -EINVAL;
		break;
	}

	if (ret < 0) {
		dev_err(g_dev, "failed to query vmem region, type=%u ret=%d\n",
			rsp.type, ret);
		goto out;
	}

	if (copy_to_user((void *)ioctl_param, &rsp, sizeof(rsp)))
		return -EFAULT;

out:
	return ret;
}

static long vmem_query_ioctl(struct file *filp, unsigned int cmd,
			     unsigned long ioctl_param)
{
	long ret;
	if (_IOC_TYPE(cmd) != VMEM_QUERY_IOC_MAGIC)
		return -EINVAL;

	switch (cmd) {
	case VMEM_QUERY_IOC_QUERY:
		ret = handle_query_vmem_region(filp, ioctl_param);
		break;
	default:
		dev_warn(g_dev, "%s: Unhandled ioctl cmd: 0x%x\n", __func__,
			 cmd);
		ret = -EINVAL;
	}
	return ret;
}

static int vmem_query_open(struct inode *inodep, struct file *filep)
{
	return 0;
}

static int vmem_query_release(struct inode *inodep, struct file *filp)
{
	return 0;
}

static struct file_operations fops = {
	.owner = THIS_MODULE,
	.open = vmem_query_open,
	.release = vmem_query_release,
	.unlocked_ioctl = vmem_query_ioctl,
};

static ssize_t cntpct_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
	uint64_t counter = __arch_counter_get_cntpct();
#else
	uint64_t counter = arch_counter_get_cntpct_internal();
#endif
	pr_info("%s: cntpct = %llu\n", __func__, counter);

	return scnprintf(buf, PAGE_SIZE, "%llu", counter);
}
static DEVICE_ATTR_RO(cntpct);

static int __init vmem_query_init(void)
{
	int err;

	/* Try to dynamically allocate a major number for the device */
	err = register_chrdev(0, KBUILD_MODNAME, &fops);
	if (err < 0) {
		pr_warn("%s: failed to register vmem query device\n", __func__);
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

	err = device_create_file(g_dev, &dev_attr_cntpct);
	if (err) {
		pr_err("Failed to create device file: cntpct\n");
		goto err_create_cntpct_device_file;
	}

	return 0;

err_create_cntpct_device_file:
	device_destroy(g_class, MKDEV(g_major, 0));
err_device_create:
	class_destroy(g_class);
err_class_create:
	unregister_chrdev(g_major, KBUILD_MODNAME);
err_register_chrdev:
	return err;
}

static void __exit vmem_query_exit(void)
{
	device_remove_file(g_dev, &dev_attr_cntpct);

	if (g_dev)
		device_destroy(g_class, MKDEV(g_major, 0));

	if (g_class)
		class_destroy(g_class);

	if (g_major)
		unregister_chrdev(g_major, KBUILD_MODNAME);
}

module_init(vmem_query_init);
module_exit(vmem_query_exit);

MODULE_LICENSE("GPL v2");
