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

static int g_major;
static struct gen_pool *g_pool;
static struct class *g_class;
static struct device *g_dev;
struct reserved_mem *g_reserved;

#define GUEST_MEMORY_POOL_IOC_MAGIC 'g'
#define GUEST_MEMORY_POOL_IOC_ALLOC                                            \
	_IOW(GUEST_MEMORY_POOL_IOC_MAGIC, 0x80, char *)
#define GUEST_MEMORY_POOL_IOC_QUERY                                            \
	_IOW(GUEST_MEMORY_POOL_IOC_MAGIC, 0x81, char *)
#define MB (1024 * 1024)

struct guest_memory_alloc_request {
	uint16_t vmid;
	size_t size;
};

struct guest_memory_query_response {
	uint64_t base;
	size_t size;
};

struct guest_memory_region {
	phys_addr_t phys_base;
	uintptr_t virt_base;
	size_t size;
};

static long guest_memory_alloc(size_t size,
			       struct guest_memory_region **out_region)
{
	struct guest_memory_region *region;
	unsigned long virt_addr;
	long ret;

	virt_addr = gen_pool_alloc(g_pool, size);
	if (!virt_addr) {
		ret = -ENOMEM;
		dev_err(g_dev, "%s: not enough memory\n", __func__);
		goto err_gen_pool_alloc;
	}

	region = kzalloc(sizeof(struct guest_memory_region), GFP_KERNEL);
	if (!region) {
		ret = -ENOMEM;
		goto err_region_alloc;
	}

	region->virt_base = virt_addr;
	region->phys_base = gen_pool_virt_to_phys(g_pool, virt_addr);
	region->size = size;

	*out_region = region;
	return 0;

err_region_alloc:
	gen_pool_free(g_pool, virt_addr, size);
err_gen_pool_alloc:
	return ret;
}

static void guest_memory_free(struct guest_memory_region *region)
{
	gen_pool_free(g_pool, region->virt_base, region->size);
	kfree(region);
}

static long handle_alloc_guest_memory(struct file *filp,
				      unsigned long ioctl_param)
{
	long ret;
	struct guest_memory_region *region = filp->private_data;
	struct guest_memory_alloc_request req;

	if (copy_from_user(&req, (void *)ioctl_param, sizeof(req)))
		return -EFAULT;

	if (region) {
		dev_err(g_dev, "%s: already allocated\n", __func__);
		return -EINVAL;
	}

	ret = guest_memory_alloc(req.size, &region);
	if (ret) {
		dev_err(g_dev, "%s: failed to allocate guest memory\n",
			__func__);
		return -EINVAL;
	}

	filp->private_data = region;
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

static long guest_memory_pool_ioctl(struct file *filp, unsigned int cmd,
				    unsigned long ioctl_param)
{
	long ret;
	if (_IOC_TYPE(cmd) != GUEST_MEMORY_POOL_IOC_MAGIC)
		return -EINVAL;

	switch (cmd) {
	case GUEST_MEMORY_POOL_IOC_ALLOC:
		ret = handle_alloc_guest_memory(filp, ioctl_param);
		break;
	case GUEST_MEMORY_POOL_IOC_QUERY:
		ret = handle_query_guest_memory(filp, ioctl_param);
		break;
	default:
		dev_warn(g_dev, "%s: Unhandled ioctl cmd: 0x%x\n", __func__,
			 cmd);
		ret = -EINVAL;
	}
	return ret;
}

static int guest_memory_pool_open(struct inode *inodep, struct file *filep)
{
	return 0;
}

static int guest_memory_pool_release(struct inode *inodep, struct file *filp)
{
	struct guest_memory_region *region = filp->private_data;
	if (region) {
		guest_memory_free(region);
	}
	return 0;
}

static int guest_memory_pool_mmap(struct file *filp, struct vm_area_struct *vma)
{
	size_t vma_size = vma->vm_end - vma->vm_start;
	struct guest_memory_region *region = filp->private_data;
	unsigned long pfn;

	if (!region) {
		dev_err(g_dev, "no guest memory region allocated\n");
		return -EINVAL;
	}

	if (vma_size > region->size) {
		dev_err(g_dev, "requested size exceeded guest memory region\n");
		return -EINVAL;
	}

	pfn = region->phys_base >> PAGE_SHIFT;
	return remap_pfn_range(vma, vma->vm_start, pfn,
			       vma->vm_end - vma->vm_start, vma->vm_page_prot);
}

static loff_t guest_memory_pool_seek(struct file *filp, loff_t off, int whence) {
	struct guest_memory_region *region = filp->private_data;

	if (whence == SEEK_END) {
		return region->size;
	}

	return 0;
}

static struct file_operations fops = {
	.owner = THIS_MODULE,
	.open = guest_memory_pool_open,
	.release = guest_memory_pool_release,
	.unlocked_ioctl = guest_memory_pool_ioctl,
	.mmap = guest_memory_pool_mmap,
	.llseek = guest_memory_pool_seek,
};

static int __init reserve_guest_memory(struct reserved_mem *rmem)
{
	g_reserved = rmem;
	return 0;
}
RESERVEDMEM_OF_DECLARE(guest_memory_pool, "nbl,guest-memory",
		       reserve_guest_memory);

static int create_guest_memory_pool(struct reserved_mem *rmem)
{
	int err;
	int min_guest_memory_size = 32 * MB;
	int min_allocation_order = get_order(min_guest_memory_size);
	void *start = phys_to_virt(rmem->base);
	if (!start) {
		pr_err("%s: failed to get virtual address of memory pool\n",
		       __func__);
		err = -ENOMEM;
		goto ioremap_err;
	}

	g_pool = gen_pool_create(min_allocation_order, -1);
	if (!g_pool) {
		pr_err("%s: failed to create gen_pool\n", __func__);
		err = -ENOMEM;
		goto create_pool_err;
	}

	err = gen_pool_add_virt(g_pool, (unsigned long)start, rmem->base,
				rmem->size, -1);
	if (err) {
		pr_err("%s: failed to add new chunk\n", __func__);
		goto add_chunk_err;
	}

	pr_info("%s: guest memory pool created, base: 0x%pa, size: 0x%pa\n",
		__func__, &rmem->base, &rmem->size);
	return 0;

add_chunk_err:
	gen_pool_destroy(g_pool);
	g_pool = NULL;
create_pool_err:
ioremap_err:
	return err;
}

static void destroy_guest_memory_pool(void)
{
	gen_pool_destroy(g_pool);
}

static int __init guest_memory_pool_init(void)
{
    int err;
    struct device_node *acrn_memroy_node;

    if (!g_reserved) {
        acrn_memroy_node = of_find_node_by_path(
            "/reserved-memory/acrn_guest_memory");
        if (acrn_memroy_node != NULL) {
            g_reserved = of_reserved_mem_lookup(acrn_memroy_node);
        }
        if (!g_reserved) {
            pr_err("%s: failed to get reserved memory\n", __func__);
            return -ENODEV;
        }
    }

	err = create_guest_memory_pool(g_reserved);
	if (err < 0) {
		pr_err("%s: failed to create guest memory pool\n",
		       __func__);
		goto err_create_memory_pool;
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
	destroy_guest_memory_pool();
err_create_memory_pool:
	return err;
}

static void __exit guest_memory_pool_exit(void)
{
	unregister_chrdev(g_major, KBUILD_MODNAME);
}

module_init(guest_memory_pool_init);
module_exit(guest_memory_pool_exit);

MODULE_LICENSE("GPL v2");
