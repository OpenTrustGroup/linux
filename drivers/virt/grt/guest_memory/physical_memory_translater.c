/* SPDX-License-Identifier: GPL-2.0-only */

#include <linux/errno.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/pagemap.h>
#include <linux/fdtable.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>
#include <asm/page.h>

#include <linux/stddef.h>
#include <uapi/drm/drm.h>

#define _ALIGN_UP(addr, size)	(((addr)+((size)-1))&(~((size)-1)))

struct align_file_length_req {
	int fd;
	uint64_t length;
	loff_t old_size;
};

struct translate_phys_mem {
	uint64_t vaddr;
	uint32_t num_pages;
	uint32_t padding;
	uint64_t *page_list;
};

static phys_addr_t dmabuf_user_v2p(unsigned long va)
{
	unsigned long pageOffset = (va & (PAGE_SIZE - 1));
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	phys_addr_t pa;

	if (current == NULL) {
		pr_err("warning: %s, current is NULL!\n", __func__);
		return 0;
	}
	if (current->mm == NULL) {
		pr_err(
			"warning: %s, current->mm is NULL! tgid=0x%x, name=%s\n",
			__func__, current->tgid, current->comm);
		return 0;
	}

	pgd = pgd_offset(current->mm, va); /* what is tsk->mm */
	if (pgd_none(*pgd) || pgd_bad(*pgd)) {
		pr_err("%s(), va=0x%lx, pgd invalid!\n", __func__,
				 va);
		return 0;
	}

	p4d = p4d_offset(pgd, va);
	if (p4d_none(*p4d) || p4d_bad(*p4d)) {
		pr_err("%s(), va=0x%lx, p4d invalid!\n", __func__,
				 va);
		return 0;
	}

	pud = pud_offset(p4d, va);
	if (pud_none(*pud) || pud_bad(*pud)) {
		pr_err("%s(), va=0x%lx, pud invalid!\n", __func__,
				 va);
		return 0;
	}

	pmd = pmd_offset(pud, va);
	if (pmd_none(*pmd) || pmd_bad(*pmd)) {
		pr_err("%s(), va=0x%lx, pmd invalid!\n", __func__,
				 va);
		return 0;
	}

	pte = pte_offset_kernel(pmd, va);
	if (pte_present(*pte)) {
		/* pa=(pte_val(*pte) & (PAGE_MASK)) | pageOffset; */
		pa = (pte_val(*pte) & (PHYS_MASK) & (~((phys_addr_t)0xfff))) |
		     pageOffset;
		pte_unmap(pte);
		return pa;
	}

	pr_err("%s(), va=0x%lx, pte invalid!\n", __func__, va);
	return 0;
}

#define TRANSLATER_IOCTL_TYPE 0xF1
#define TRANSLATER_IOCTL_ALIGN_FILE_LENGTH                                     \
	_IOWR(TRANSLATER_IOCTL_TYPE, 0x1, struct align_file_length_req)
#define TRANSLATER_IOCTL_RESTORE_FILE_LENGTH                                   \
	_IOWR(TRANSLATER_IOCTL_TYPE, 0x2, struct align_file_length_req)
#define TRANSLATER_IOCTL_TRANSLATE_PHYS_MEM                                    \
	_IOWR(TRANSLATER_IOCTL_TYPE, 0x3, struct translate_phys_mem)

static long align_file_length(unsigned long arg) {
	struct align_file_length_req req;
	int ret = -EFAULT;
	struct file *target;
	struct inode *inode;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		goto out;

	target = files_lookup_fd_raw(current->files, req.fd);
	if (!target) {
		ret = -EINVAL;
		goto out;
	}

	inode = target->f_mapping->host;
	req.old_size = i_size_read(inode);
	i_size_write(inode, _ALIGN_UP(req.old_size, req.length));

	ret = copy_to_user((void __user *)arg, &req, sizeof(req));
	if (ret)
		ret = -EFAULT;

	return 0;

out:
	return ret;
}

static long restore_file_length(unsigned long arg) {
	struct align_file_length_req req;
	int ret = -EFAULT;
	struct file *target;
	struct inode *inode;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		goto out;

	target = files_lookup_fd_raw(current->files, req.fd);
	if (!target) {
		ret = -EINVAL;
		goto out;
	}

	inode = target->f_mapping->host;
	i_size_write(inode, req.old_size);
	return 0;

out:
	return ret;
}

static long translate_mmapped_addr(unsigned long arg)
{
	struct translate_phys_mem translater;
	int ret = -EFAULT;
	uintptr_t start, end;
	uintptr_t *page_list;
	int index;
	size_t page_list_size;

	if (copy_from_user(&translater, (void __user *)arg,
			   sizeof(struct translate_phys_mem)))
		goto out;

	page_list_size = sizeof(uintptr_t) * translater.num_pages;
	page_list = kmalloc(page_list_size, GFP_KERNEL);
	if (page_list == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	start = translater.vaddr;
	end = translater.vaddr + translater.num_pages * PAGE_SIZE;
	index = 0;
	while (start < end) {
		phys_addr_t pa = dmabuf_user_v2p(start);
		if (pa == 0) {
			ret = -EINVAL;
			goto out_free_page_list;
		}

		start += PAGE_SIZE;
		page_list[index++] = pa;
	}

	ret = copy_to_user((void __user *)translater.page_list, page_list,
			   page_list_size);
	if (ret)
		ret = -EFAULT;
out_free_page_list:
	kfree(page_list);
out:
	return ret;
}

static long physical_memory_translater_ioctl(struct file *filp,
					     unsigned int cmd,
					     unsigned long arg)
{
	switch (cmd) {
	case TRANSLATER_IOCTL_ALIGN_FILE_LENGTH:
		return align_file_length(arg);
	case TRANSLATER_IOCTL_RESTORE_FILE_LENGTH:
		return restore_file_length(arg);
	case TRANSLATER_IOCTL_TRANSLATE_PHYS_MEM:
		return translate_mmapped_addr(arg);
	default:
		return -EINVAL;
	}
}

static int physical_memory_translater_release(struct inode *inode,
					      struct file *f)
{
	return 0;
}

static struct file_operations physical_memory_translater_fops = {
	.owner = THIS_MODULE,
	.release = physical_memory_translater_release,
	.unlocked_ioctl = physical_memory_translater_ioctl,
};

static struct miscdevice translater_mdev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "physical_memory_translater",
	.fops = &physical_memory_translater_fops,
};

static int __init translater_init(void)
{
	return misc_register(&translater_mdev);
}

module_init(translater_init)

MODULE_LICENSE("GPL v2");
