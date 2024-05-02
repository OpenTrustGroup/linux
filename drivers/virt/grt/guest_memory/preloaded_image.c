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

enum {
	KERNEL = 0,
	DTB = 1,
	RAMDISK = 2,
	DMA = 3,
	DRAMBUF = 4,
	BOOTTAG = 5,
	SRAM = 6,
};

struct guest_memory_region {
	phys_addr_t phys_base;
	uintptr_t virt_base;
	size_t size;
};

struct guest_memory_query_response {
	uint64_t base;
	size_t size;
};

struct guest_memory_region g_dtb_region;
struct guest_memory_region g_kernel_region;
struct guest_memory_region g_ramdisk_region;
struct guest_memory_region g_dma_region;
struct guest_memory_region g_boottag_region;
struct guest_memory_region g_drambuf_region;
struct guest_memory_region g_sram_region = {
	.phys_base = 0x100000,
	.size = 0x20000,
};

static int g_major;
static struct class *g_class;
static struct device *g_dev;

#define PRELOADED_IMAGE_IOC_MAGIC 'h'
#define PRELOADED_IMAGE_IOC_SELECT \
	_IOW(PRELOADED_IMAGE_IOC_MAGIC, 0x80, unsigned long)
#define PRELOADED_IMAGE_IOC_QUERY \
	_IOW(PRELOADED_IMAGE_IOC_MAGIC, 0x81, char *)

static int handle_select_image(struct file *filp, unsigned long image_id) {
	switch (image_id) {
	case KERNEL:
		filp->private_data = &g_kernel_region;
		break;
	case DTB:
		filp->private_data = &g_dtb_region;
		break;
	case RAMDISK:
		filp->private_data = &g_ramdisk_region;
		break;
	case DMA:
		filp->private_data = &g_dma_region;
		break;
	case BOOTTAG:
		filp->private_data = &g_boottag_region;
		break;
	case DRAMBUF:
		filp->private_data = &g_drambuf_region;
		break;
	case SRAM:
		filp->private_data = &g_sram_region;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static long handle_query_guest_memory(struct file *filp,
				      unsigned long ioctl_param)
{
	struct guest_memory_region *region = filp->private_data;
	struct guest_memory_query_response rsp;

	if (!region)
		return -EINVAL;

	rsp.base = region->phys_base;
	rsp.size = region->size;

	if (copy_to_user((void *)ioctl_param, &rsp, sizeof(rsp)))
		return -EFAULT;
	return 0;
}

static long preloaded_image_ioctl(struct file *filp, unsigned int cmd,
				    unsigned long ioctl_param)
{
	long ret;
	if (_IOC_TYPE(cmd) != PRELOADED_IMAGE_IOC_MAGIC)
		return -EINVAL;

	switch (cmd) {
	case PRELOADED_IMAGE_IOC_SELECT:
		ret = handle_select_image(filp, ioctl_param);
		break;
	case PRELOADED_IMAGE_IOC_QUERY:
		ret = handle_query_guest_memory(filp, ioctl_param);
		break;
	default:
		dev_warn(g_dev, "%s: Unhandled ioctl cmd: 0x%x\n", __func__,
			 cmd);
		ret = -EINVAL;
	}
	return ret;
}

static int preloaded_image_open(struct inode *inodep, struct file *filep)
{
	return 0;
}

static int preloaded_image_release(struct inode *inodep, struct file *filp)
{
	return 0;
}

static int preloaded_image_mmap(struct file *filp, struct vm_area_struct *vma)
{
	size_t vma_size = vma->vm_end - vma->vm_start;
	struct guest_memory_region *region = filp->private_data;
	unsigned long pfn;

	if (!region) {
		dev_err(g_dev, "no image memory selected\n");
		return -EINVAL;
	}

	if (vma_size > region->size) {
		dev_err(g_dev, "requested size exceeded memory region\n");
		return -EINVAL;
	}

	pfn = region->phys_base >> PAGE_SHIFT;
	return remap_pfn_range(vma, vma->vm_start, pfn,
			       vma->vm_end - vma->vm_start, vma->vm_page_prot);
}

static loff_t preloaded_image_seek(struct file *filp, loff_t off, int whence) {
	struct guest_memory_region *region = filp->private_data;

	if (whence == SEEK_END) {
		return region->size;
	}

	return 0;
}


static struct file_operations fops = {
	.owner = THIS_MODULE,
	.open = preloaded_image_open,
	.release = preloaded_image_release,
	.unlocked_ioctl = preloaded_image_ioctl,
	.mmap = preloaded_image_mmap,
	.llseek = preloaded_image_seek,
};

static int __init reserve_boottag_memory(struct reserved_mem *rmem)
{
	g_boottag_region.phys_base = rmem->base;
	g_boottag_region.size = rmem->size;
	return 0;
}
RESERVEDMEM_OF_DECLARE(guest_boottag_paddr, "mediatek,pl-boottag",
		       reserve_boottag_memory);

static int __init reserve_drambuf_memory(struct reserved_mem *rmem)
{
	g_drambuf_region.phys_base = rmem->base;
	g_drambuf_region.size = rmem->size;
	return 0;
}
RESERVEDMEM_OF_DECLARE(guest_drambuf_paddr, "mediatek,pl-drambuf",
		       reserve_drambuf_memory);

static int __init reserve_dtb_memory(struct reserved_mem *rmem)
{
	g_dtb_region.phys_base = rmem->base;
	g_dtb_region.size = rmem->size;
	return 0;
}
RESERVEDMEM_OF_DECLARE(guest_dtb_paddr, "mediatek,android_dtb_kernel_addr_mb",
		       reserve_dtb_memory);

static int __init reserve_kernel_memory(struct reserved_mem *rmem)
{
	g_kernel_region.phys_base = rmem->base;
	g_kernel_region.size = rmem->size;
	return 0;
}
RESERVEDMEM_OF_DECLARE(guest_kernel_paddr, "mediatek,android_kernel_addr_mb",
		       reserve_kernel_memory);

static int __init reserve_ramdisk_memory(struct reserved_mem *rmem)
{
	g_ramdisk_region.phys_base = rmem->base;
	g_ramdisk_region.size = rmem->size;
	return 0;
}
RESERVEDMEM_OF_DECLARE(guest_ramdisk_paddr, "mediatek,android_ramdisk_addr_mb",
		       reserve_ramdisk_memory);

static int __init reserve_dma_memory(struct reserved_mem *rmem)
{
	g_dma_region.phys_base = rmem->base;
	g_dma_region.size = rmem->size;
	return 0;
}
RESERVEDMEM_OF_DECLARE(guest_dma_paddr, "mediatek,gz-dma-res",
		       reserve_dma_memory);

static bool is_valid(struct guest_memory_region *region) {
	return (region->phys_base != 0);
}

static int __init preloaded_image_init(void)
{
	int err;

	/* NOTICE: without boottag and drambuf, will crash in lk2 */
	if (!is_valid(&g_boottag_region) || !is_valid(&g_drambuf_region)) {
		pr_err("%s: failed to get reserved memory\n", __func__);
		return -ENODEV;
	}

	/* Try to dynamically allocate a major number for the device */
	err = register_chrdev(0, KBUILD_MODNAME, &fops);
	if (err < 0) {
		pr_warn("%s: failed to register guest memory device\n",
			__func__);
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

	return 0;

err_device_create:
	class_destroy(g_class);
err_class_create:
	unregister_chrdev(g_major, KBUILD_MODNAME);
err_register_chrdev:
	return err;
}

static void __exit preloaded_image_exit(void)
{
	unregister_chrdev(g_major, KBUILD_MODNAME);
}

module_init(preloaded_image_init);
module_exit(preloaded_image_exit);

MODULE_LICENSE("GPL v2");
