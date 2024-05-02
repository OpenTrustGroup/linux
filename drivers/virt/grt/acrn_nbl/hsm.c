// SPDX-License-Identifier: GPL-2.0-only
/*
 * ACRN Hypervisor Service Module (HSM)
 *
 * Copyright (C) 2020 Intel Corporation. All rights reserved.
 *
 * Authors:
 *	Fengwei Yin <fengwei.yin@intel.com>
 *	Yakui Zhao <yakui.zhao@intel.com>
 */

#include <linux/cpu.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include <asm/acrn.h>
#include <asm/hypervisor.h>
#include <asm/smp_plat.h>
#include <uapi/acrn.h>

#include "acrn_drv.h"

/*
 * When /dev/acrn_hsm is opened, a 'struct acrn_vm' object is created to
 * represent a VM instance and continues to be associated with the opened file
 * descriptor. All ioctl operations on this file descriptor will be targeted to
 * the VM instance. Release of this file descriptor will destroy the object.
 */
static int acrn_dev_open(struct inode *inode, struct file *filp)
{
	struct acrn_vm *vm;

	vm = kzalloc(sizeof(*vm), GFP_KERNEL);
	if (!vm)
		return -ENOMEM;

	vm->vmid = ACRN_INVALID_VMID;
	filp->private_data = vm;
	return 0;
}

static int pmcmd_ioctl(u64 cmd, void __user *uptr)
{
	struct acrn_pstate_data *px_data;
	struct acrn_cstate_data *cx_data;
	u64 *pm_info;
	int ret = 0;

	switch (cmd & PMCMD_TYPE_MASK) {
	case ACRN_PMCMD_GET_PX_CNT:
	case ACRN_PMCMD_GET_CX_CNT:
		pm_info = kmalloc(sizeof(u64), GFP_KERNEL);
		if (!pm_info)
			return -ENOMEM;

		ret = hcall_get_cpu_state(cmd, virt_to_phys(pm_info));
		if (ret < 0) {
			kfree(pm_info);
			break;
		}

		if (copy_to_user(uptr, pm_info, sizeof(u64)))
			ret = -EFAULT;
		kfree(pm_info);
		break;
	case ACRN_PMCMD_GET_PX_DATA:
		px_data = kmalloc(sizeof(*px_data), GFP_KERNEL);
		if (!px_data)
			return -ENOMEM;

		ret = hcall_get_cpu_state(cmd, virt_to_phys(px_data));
		if (ret < 0) {
			kfree(px_data);
			break;
		}

		if (copy_to_user(uptr, px_data, sizeof(*px_data)))
			ret = -EFAULT;
		kfree(px_data);
		break;
	case ACRN_PMCMD_GET_CX_DATA:
		cx_data = kmalloc(sizeof(*cx_data), GFP_KERNEL);
		if (!cx_data)
			return -ENOMEM;

		ret = hcall_get_cpu_state(cmd, virt_to_phys(cx_data));
		if (ret < 0) {
			kfree(cx_data);
			break;
		}

		if (copy_to_user(uptr, cx_data, sizeof(*cx_data)))
			ret = -EFAULT;
		kfree(cx_data);
		break;
	default:
		break;
	}

	return ret;
}

/*
 * HSM relies on hypercall layer of the ACRN hypervisor to do the
 * sanity check against the input parameters.
 */
static long acrn_dev_ioctl(struct file *filp, unsigned int cmd,
			   unsigned long ioctl_param)
{
	struct acrn_vm *vm = filp->private_data;
	struct acrn_vm_creation *vm_param;
	struct acrn_vcpu_regs *cpu_regs;
	struct acrn_ioreq_notify notify;
	struct acrn_ptdev_irq *irq_info;
	struct acrn_ioeventfd ioeventfd;
	struct acrn_vm_memmap memmap;
	struct acrn_mmiodev *mmiodev;
	struct acrn_msi_entry *msi;
	struct acrn_pcidev *pcidev;
	struct acrn_irqfd irqfd;
	struct acrn_vdev *vdev;
	struct page *page;
	u64 cstate_cmd;
	int i, ret = 0;

	if (vm->vmid == ACRN_INVALID_VMID && (cmd != ACRN_IOCTL_CREATE_VM && cmd != ACRN_IOCTL_LIST_VM)) {
		dev_dbg(acrn_dev.this_device,
			"ioctl 0x%x: Invalid VM state!\n", cmd);
		return -EINVAL;
	}

	switch (cmd) {
	case ACRN_IOCTL_LIST_VM:
		acrn_list_vm();
		break;
	case ACRN_IOCTL_CREATE_VM:
		vm_param = memdup_user((void __user *)ioctl_param,
				       sizeof(struct acrn_vm_creation));
		if (IS_ERR(vm_param))
			return PTR_ERR(vm_param);

		if ((vm_param->reserved0 | vm_param->reserved1) != 0)
			return -EINVAL;

		vm = acrn_vm_create(vm, vm_param);
		if (!vm) {
			ret = -EINVAL;
			kfree(vm_param);
			break;
		}

		if (copy_to_user((void __user *)ioctl_param, vm_param,
				 sizeof(struct acrn_vm_creation))) {
			acrn_vm_destroy(vm);
			ret = -EFAULT;
		}

		kfree(vm_param);
		break;
	case ACRN_IOCTL_START_VM:
		ret = hcall_start_vm(vm->vmid);
		if (ret < 0)
			dev_dbg(acrn_dev.this_device,
				"Failed to start VM %u!\n", vm->vmid);
		break;
	case ACRN_IOCTL_PAUSE_VM:
		ret = hcall_pause_vm(vm->vmid);
		if (ret < 0)
			dev_dbg(acrn_dev.this_device,
				"Failed to pause VM %u!\n", vm->vmid);
		break;
	case ACRN_IOCTL_RESET_VM:
		ret = hcall_reset_vm(vm->vmid);
		if (ret < 0)
			dev_dbg(acrn_dev.this_device,
				"Failed to restart VM %u!\n", vm->vmid);
		break;
	case ACRN_IOCTL_DESTROY_VM:
		ret = acrn_vm_destroy(vm);
		break;
	case ACRN_IOCTL_SET_VCPU_REGS:
		cpu_regs = memdup_user((void __user *)ioctl_param,
				       sizeof(struct acrn_vcpu_regs));
		if (IS_ERR(cpu_regs))
			return PTR_ERR(cpu_regs);

		for (i = 0; i < ARRAY_SIZE(cpu_regs->reserved); i++)
			if (cpu_regs->reserved[i])
				return -EINVAL;

		for (i = 0; i < ARRAY_SIZE(cpu_regs->vcpu_regs.reserved_32); i++)
			if (cpu_regs->vcpu_regs.reserved_32[i])
				return -EINVAL;

		for (i = 0; i < ARRAY_SIZE(cpu_regs->vcpu_regs.reserved_64); i++)
			if (cpu_regs->vcpu_regs.reserved_64[i])
				return -EINVAL;

		for (i = 0; i < ARRAY_SIZE(cpu_regs->vcpu_regs.gdt.reserved); i++)
			if (cpu_regs->vcpu_regs.gdt.reserved[i] |
			    cpu_regs->vcpu_regs.idt.reserved[i])
				return -EINVAL;

		ret = hcall_set_vcpu_regs(vm->vmid, virt_to_phys(cpu_regs));
		if (ret < 0)
			dev_dbg(acrn_dev.this_device,
				"Failed to set regs state of VM%u!\n",
				vm->vmid);
		kfree(cpu_regs);
		break;
	case ACRN_IOCTL_SET_MEMSEG:
		if (copy_from_user(&memmap, (void __user *)ioctl_param,
				   sizeof(memmap)))
			return -EFAULT;

		ret = acrn_vm_memseg_map(vm, &memmap);
		break;
	case ACRN_IOCTL_UNSET_MEMSEG:
		if (copy_from_user(&memmap, (void __user *)ioctl_param,
				   sizeof(memmap)))
			return -EFAULT;

		ret = acrn_vm_memseg_unmap(vm, &memmap);
		break;
	case ACRN_IOCTL_ASSIGN_MMIODEV:
		mmiodev = memdup_user((void __user *)ioctl_param,
				      sizeof(struct acrn_mmiodev));
		if (IS_ERR(mmiodev))
			return PTR_ERR(mmiodev);

		ret = hcall_assign_mmiodev(vm->vmid, virt_to_phys(mmiodev));
		if (ret < 0)
			dev_dbg(acrn_dev.this_device,
				"Failed to assign MMIO device!\n");
		kfree(mmiodev);
		break;
	case ACRN_IOCTL_DEASSIGN_MMIODEV:
		mmiodev = memdup_user((void __user *)ioctl_param,
				      sizeof(struct acrn_mmiodev));
		if (IS_ERR(mmiodev))
			return PTR_ERR(mmiodev);

		ret = hcall_deassign_mmiodev(vm->vmid, virt_to_phys(mmiodev));
		if (ret < 0)
			dev_dbg(acrn_dev.this_device,
				"Failed to deassign MMIO device!\n");
		kfree(mmiodev);
		break;
	case ACRN_IOCTL_ASSIGN_PCIDEV:
		pcidev = memdup_user((void __user *)ioctl_param,
				     sizeof(struct acrn_pcidev));
		if (IS_ERR(pcidev))
			return PTR_ERR(pcidev);

		ret = hcall_assign_pcidev(vm->vmid, virt_to_phys(pcidev));
		if (ret < 0)
			dev_dbg(acrn_dev.this_device,
				"Failed to assign pci device!\n");
		kfree(pcidev);
		break;
	case ACRN_IOCTL_DEASSIGN_PCIDEV:
		pcidev = memdup_user((void __user *)ioctl_param,
				     sizeof(struct acrn_pcidev));
		if (IS_ERR(pcidev))
			return PTR_ERR(pcidev);

		ret = hcall_deassign_pcidev(vm->vmid, virt_to_phys(pcidev));
		if (ret < 0)
			dev_dbg(acrn_dev.this_device,
				"Failed to deassign pci device!\n");
		kfree(pcidev);
		break;
	case ACRN_IOCTL_CREATE_VDEV:
		vdev = memdup_user((void __user *)ioctl_param,
				   sizeof(struct acrn_vdev));
		if (IS_ERR(vdev))
			return PTR_ERR(vdev);

		ret = hcall_create_vdev(vm->vmid, virt_to_phys(vdev));
		if (ret < 0)
			dev_dbg(acrn_dev.this_device,
				"Failed to create virtual device!\n");
		kfree(vdev);
		break;
	case ACRN_IOCTL_DESTROY_VDEV:
		vdev = memdup_user((void __user *)ioctl_param,
				   sizeof(struct acrn_vdev));
		if (IS_ERR(vdev))
			return PTR_ERR(vdev);
		ret = hcall_destroy_vdev(vm->vmid, virt_to_phys(vdev));
		if (ret < 0)
			dev_dbg(acrn_dev.this_device,
				"Failed to destroy virtual device!\n");
		kfree(vdev);
		break;
	case ACRN_IOCTL_SET_PTDEV_INTR:
		irq_info = memdup_user((void __user *)ioctl_param,
				       sizeof(struct acrn_ptdev_irq));
		if (IS_ERR(irq_info))
			return PTR_ERR(irq_info);

		ret = hcall_set_ptdev_intr(vm->vmid, virt_to_phys(irq_info));
		if (ret < 0)
			dev_dbg(acrn_dev.this_device,
				"Failed to configure intr for ptdev!\n");
		kfree(irq_info);
		break;
	case ACRN_IOCTL_RESET_PTDEV_INTR:
		irq_info = memdup_user((void __user *)ioctl_param,
				       sizeof(struct acrn_ptdev_irq));
		if (IS_ERR(irq_info))
			return PTR_ERR(irq_info);

		ret = hcall_reset_ptdev_intr(vm->vmid, virt_to_phys(irq_info));
		if (ret < 0)
			dev_dbg(acrn_dev.this_device,
				"Failed to reset intr for ptdev!\n");
		kfree(irq_info);
		break;
	case ACRN_IOCTL_SET_IRQLINE:
		ret = hcall_set_irqline(vm->vmid, ioctl_param);
		if (ret < 0)
			dev_dbg(acrn_dev.this_device,
				"Failed to set interrupt line!\n");
		break;
	case ACRN_IOCTL_INJECT_MSI:
		msi = memdup_user((void __user *)ioctl_param,
				  sizeof(struct acrn_msi_entry));
		if (IS_ERR(msi))
			return PTR_ERR(msi);

		ret = hcall_inject_msi(vm->vmid, virt_to_phys(msi));
		if (ret < 0)
			dev_dbg(acrn_dev.this_device,
				"Failed to inject MSI!\n");
		kfree(msi);
		break;
	case ACRN_IOCTL_VM_INTR_MONITOR:
		ret = get_user_pages_fast(ioctl_param, 1, 1, &page);
		if (unlikely(ret != 1)) {
			dev_dbg(acrn_dev.this_device,
				"Failed to pin intr hdr buffer!\n");
			return -EFAULT;
		}

		ret = hcall_vm_intr_monitor(vm->vmid, page_to_phys(page));
		if (ret < 0) {
			put_page(page);
			dev_dbg(acrn_dev.this_device,
				"Failed to monitor intr data!\n");
			return ret;
		}
		if (vm->monitor_page)
			put_page(vm->monitor_page);
		vm->monitor_page = page;
		break;
	case ACRN_IOCTL_CREATE_IOREQ_CLIENT:
		if (vm->default_client)
			return -EEXIST;
		if (!acrn_ioreq_client_create(vm, NULL, NULL, true, "acrndm"))
			ret = -EINVAL;
		break;
	case ACRN_IOCTL_DESTROY_IOREQ_CLIENT:
		if (vm->default_client)
			acrn_ioreq_client_destroy(vm->default_client);
		break;
	case ACRN_IOCTL_ATTACH_IOREQ_CLIENT:
		if (vm->default_client)
			ret = acrn_ioreq_client_wait(vm->default_client);
		else
			ret = -ENODEV;
		break;
	case ACRN_IOCTL_NOTIFY_REQUEST_FINISH:
		if (copy_from_user(&notify, (void __user *)ioctl_param,
				   sizeof(struct acrn_ioreq_notify)))
			return -EFAULT;

		if (notify.reserved != 0)
			return -EINVAL;

		ret = acrn_ioreq_request_default_complete(vm, notify.vcpu);
		break;
	case ACRN_IOCTL_CLEAR_VM_IOREQ:
		acrn_ioreq_request_clear(vm);
		break;
	case ACRN_IOCTL_PM_GET_CPU_STATE:
		if (copy_from_user(&cstate_cmd, (void __user *)ioctl_param,
				   sizeof(cstate_cmd)))
			return -EFAULT;

		ret = pmcmd_ioctl(cstate_cmd, (void __user *)ioctl_param);
		break;
	case ACRN_IOCTL_IOEVENTFD:
		if (copy_from_user(&ioeventfd, (void __user *)ioctl_param,
				   sizeof(ioeventfd)))
			return -EFAULT;

		if (ioeventfd.reserved != 0)
			return -EINVAL;

		ret = acrn_ioeventfd_config(vm, &ioeventfd);
		break;
	case ACRN_IOCTL_IRQFD:
		if (copy_from_user(&irqfd, (void __user *)ioctl_param,
				   sizeof(irqfd)))
			return -EFAULT;
		ret = acrn_irqfd_config(vm, &irqfd);
		break;
	case ACRN_IOCTL_GET_PCPU_INFO: {
		struct acrn_pcpu_info info;
		int cpu;
		struct device_node *cn = NULL;

		for_each_possible_cpu(cpu) {
			uint32_t cpu_id;
			const __be32 *addrp;

			cn = of_get_cpu_node(cpu, NULL);
			if (!cn) {
				pr_debug("missing device node for CPU %d\n",
					 cpu);
				return -ENOENT;
			}

			addrp = of_get_address(cn, 0, NULL, NULL);
			if (!addrp) {
				pr_debug("missing reg property for CPU %d\n",
					 cpu);
				return -ENOENT;

			}
			cpu_id = of_read_number(addrp, 1);
			info.hwid[cpu] = cpu_id;

		}
		info.num_online_cpus = num_possible_cpus();

		if (copy_to_user((void *)ioctl_param, &info,
				 sizeof(struct acrn_pcpu_info)))
			return -EFAULT;

		break;
	}
	case ACRN_IOCTL_ADD_MMIO_MAPPING: {
		struct acrn_mmio_mapping *mmio_mapping = memdup_user((void __user *)ioctl_param,
								     sizeof(struct acrn_mmio_mapping));
		if (IS_ERR(mmio_mapping))
			return PTR_ERR(mmio_mapping);

		ret = acrn_hypercall2(HC_ADD_MMIO_MAPPING, vm->vmid, virt_to_phys(mmio_mapping));
		kfree(mmio_mapping);

		if (ret < 0) {
			pr_err("vhm: failed add mmio mapping\n");
			return -EFAULT;
		}
		break;
	}
	case ACRN_IOCTL_SET_VM_CONFIG: {
		struct acrn_set_vm_config config;
		void* kbuf;
		int ret;

		if (copy_from_user(&config, (void *)ioctl_param,
				   sizeof(struct acrn_set_vm_config)))
			return -EFAULT;

		if (config.size > PAGE_SIZE)
			return -EINVAL;

		kbuf = alloc_pages_exact(PAGE_SIZE, GFP_KERNEL | __GFP_ZERO);
		if (!kbuf)
			return -ENOMEM;

		if (copy_from_user(kbuf, config.data, config.size)) {
			free_pages_exact(kbuf, config.size);
			return -EFAULT;
		}

		ret = acrn_hypercall3(HC_SET_VM_CONFIG, vm->vmid,
				      virt_to_phys(kbuf), config.size);

		free_pages_exact(kbuf, config.size);
		if (ret < 0) {
			pr_err("vhm: failed to set config of vm %d!\n", vm->vmid);
			return -EFAULT;
		}
		break;
	}
	case ACRN_IOCTL_VM_CALL: {
		struct acrn_msg msg;
		static void *tx_kbuf = NULL, *rx_kbuf = NULL;
		int ret;

		if (copy_from_user(&msg, (void *)ioctl_param,
				   sizeof(struct acrn_msg)))
			return -EFAULT;
		if (msg.tx_size > PAGE_SIZE || msg.rx_size > PAGE_SIZE)
			return -EINVAL;
		if (tx_kbuf == NULL) {
			tx_kbuf = alloc_pages_exact(PAGE_SIZE, GFP_KERNEL | __GFP_ZERO);
			BUG_ON(tx_kbuf == NULL);
		}
		if (rx_kbuf == NULL) {
			rx_kbuf = alloc_pages_exact(PAGE_SIZE, GFP_KERNEL | __GFP_ZERO);
			BUG_ON(rx_kbuf == NULL);
		}
		if (copy_from_user(tx_kbuf, msg.tx_data, msg.tx_size)) {
			return -EFAULT;
		}
		ret = acrn_hypercall5(HC_CALL, vm->vmid, virt_to_phys(tx_kbuf),
				      msg.tx_size, virt_to_phys(rx_kbuf), msg.rx_size);
		if (ret < 0) {
			pr_err("vhm: failed to send/recv msg to/from vm%d!\n",
			       vm->vmid);
			return -EFAULT;
		}
		msg.rx_size = ret;
		if (copy_to_user(msg.rx_data, rx_kbuf, msg.rx_size)) {
			return -EFAULT;
		}
		if (copy_to_user((void *)ioctl_param, &msg,
				 sizeof(struct acrn_msg)))
			return -EFAULT;
		break;
	}
	case ACRN_IOCTL_ASYNC_IOREQS: {
		struct acrn_async_ioreqs ioreqs;
		ioreqs.count = 0;
		ret = acrn_get_async_ioreqs(vm, &ioreqs);
		if (copy_to_user((void *)ioctl_param, &ioreqs,
				 sizeof(struct acrn_async_ioreqs))) {
			return -EFAULT;
		}
		break;
	}
	default:
		dev_dbg(acrn_dev.this_device, "Unknown IOCTL 0x%x!\n", cmd);
		ret = -ENOTTY;
	}

	return ret;
}

static int acrn_dev_release(struct inode *inode, struct file *filp)
{
	struct acrn_vm *vm = filp->private_data;

	acrn_vm_destroy(vm);
	kfree(vm);

	// GRT:TODO add power service later.
//	android_reboot_notifier_all(0, NULL);

	return 0;
}

static ssize_t remove_cpu_store(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
#ifdef CONFIG_X86
	u64 cpu, lapicid;
	int ret;

	if (kstrtoull(buf, 0, &cpu) < 0)
		return -EINVAL;

	if (cpu >= num_possible_cpus() || cpu == 0 || !cpu_is_hotpluggable(cpu))
		return -EINVAL;

	if (cpu_online(cpu))
		cpu_down(cpu);

	lapicid = cpu_data(cpu).apicid;
	dev_dbg(dev, "Try to remove cpu %lld with lapicid %lld\n", cpu, lapicid);
	ret = hcall_sos_remove_cpu(lapicid);
	if (ret < 0) {
		dev_err(dev, "Failed to remove cpu %lld!\n", cpu);
		goto fail_remove;
	}

	return count;

fail_remove:
	cpu_up(cpu);
	return ret;
#else
	return -EINVAL;
#endif
}
static DEVICE_ATTR_WO(remove_cpu);

static umode_t acrn_attr_visible(struct kobject *kobj, struct attribute *a, int n)
{
       if (a == &dev_attr_remove_cpu.attr)
               return IS_ENABLED(CONFIG_HOTPLUG_CPU) ? a->mode : 0;

       return a->mode;
}

static struct attribute *acrn_attrs[] = {
	&dev_attr_remove_cpu.attr,
	NULL
};

static struct attribute_group acrn_attr_group = {
	.attrs = acrn_attrs,
	.is_visible = acrn_attr_visible,
};

static const struct attribute_group *acrn_attr_groups[] = {
	&acrn_attr_group,
	NULL
};

static const struct file_operations acrn_fops = {
	.owner		= THIS_MODULE,
	.open		= acrn_dev_open,
	.release	= acrn_dev_release,
	.unlocked_ioctl = acrn_dev_ioctl,
};

struct miscdevice acrn_dev = {
	.minor	= MISC_DYNAMIC_MINOR,
	.name	= "acrn_hsm",
	.fops	= &acrn_fops,
	.groups	= acrn_attr_groups,
};

static int __init hsm_init(void)
{
	int ret;

	ret = misc_register(&acrn_dev);
	if (ret) {
		pr_err("Create misc dev failed!\n");
		return ret;
	}

	ret = acrn_ioreq_intr_setup();
	if (ret) {
		pr_err("Setup I/O request handler failed!\n");
		misc_deregister(&acrn_dev);
		return ret;
	}
	return 0;
}

static void __exit hsm_exit(void)
{
	acrn_ioreq_intr_remove();
	misc_deregister(&acrn_dev);
}
module_init(hsm_init);
module_exit(hsm_exit);

MODULE_AUTHOR("Intel Corporation");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("ACRN Hypervisor Service Module (HSM)");
