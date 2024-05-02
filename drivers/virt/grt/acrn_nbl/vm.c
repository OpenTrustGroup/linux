// SPDX-License-Identifier: GPL-2.0-only
/*
 * ACRN_HSM: Virtual Machine management
 *
 * Copyright (C) 2020 Intel Corporation. All rights reserved.
 *
 * Authors:
 *	Jason Chen CJ <jason.cj.chen@intel.com>
 *	Yakui Zhao <yakui.zhao@intel.com>
 */
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/slab.h>

#include "acrn_drv.h"

/* List of VMs */
LIST_HEAD(acrn_vm_list);
/*
 * acrn_vm_list is read in a worker thread which dispatch I/O requests and
 * is wrote in VM creation ioctl. Use the rwlock mechanism to protect it.
 */
DEFINE_RWLOCK(acrn_vm_list_lock);

/* List of VMs used to process async io request */
LIST_HEAD(arcn_async_io_vm_list);
/*
 * dispatch async io might go to sleep while allocating memory, so we
 * use mutex instead of rwlock to protect the vm list.
 */
DEFINE_MUTEX(arcn_async_io_vm_list_mutex);


int acrn_list_vm()
{
	struct list_head *pos;
	struct acrn_vm * vm;
	read_lock_bh(&acrn_vm_list_lock);
	list_for_each(pos, &acrn_vm_list) {
		vm = list_entry(pos, struct acrn_vm, list);
		dev_info(acrn_dev.this_device, "VM id : %u.\n", vm->vmid);
	}
	write_unlock_bh(&acrn_vm_list_lock);
	return 0;
}

struct acrn_vm *acrn_vm_create(struct acrn_vm *vm,
			       struct acrn_vm_creation *vm_param)
{
	int ret;

	ret = hcall_create_vm(virt_to_phys(vm_param));
	if (ret < 0 || vm_param->vmid == ACRN_INVALID_VMID) {
		dev_err(acrn_dev.this_device,
			"Failed to create VM! Error: %d\n", ret);
		return NULL;
	}

	mutex_init(&vm->regions_mapping_lock);
	INIT_LIST_HEAD(&vm->ioreq_clients);
	spin_lock_init(&vm->ioreq_clients_lock);
	vm->vmid = vm_param->vmid;
	vm->vcpu_num = vm_param->vcpu_num;

	if (acrn_ioreq_init(vm, vm_param->ioreq_buf) < 0) {
		hcall_destroy_vm(vm_param->vmid);
		vm->vmid = ACRN_INVALID_VMID;
		return NULL;
	}

	write_lock_bh(&acrn_vm_list_lock);
	list_add(&vm->list, &acrn_vm_list);
	write_unlock_bh(&acrn_vm_list_lock);

	mutex_lock(&arcn_async_io_vm_list_mutex);
	list_add(&vm->async_io_vm_list, &arcn_async_io_vm_list);
	mutex_unlock(&arcn_async_io_vm_list_mutex);

	acrn_ioeventfd_init(vm);
	acrn_irqfd_init(vm);

	INIT_LIST_HEAD(&vm->async_ioreqs);
	spin_lock_init(&vm->async_ioreqs_lock);
	if (acrn_async_ioreq_init(vm) < 0) {
		hcall_destroy_vm(vm_param->vmid);
		vm->vmid = ACRN_INVALID_VMID;
		return NULL;
	}
	init_waitqueue_head(&vm->async_ioreqs_wq);
	vm->is_destroying = false;

	dev_dbg(acrn_dev.this_device, "VM %u created.\n", vm->vmid);

	return vm;
}

int acrn_vm_destroy(struct acrn_vm *vm)
{
	int ret;

	if (vm->vmid == ACRN_INVALID_VMID ||
	    test_and_set_bit(ACRN_VM_FLAG_DESTROYED, &vm->flags))
		return 0;

	ret = hcall_destroy_vm(vm->vmid);
	if (ret < 0) {
		dev_err(acrn_dev.this_device,
				"Failed to destroy VM %u\n", vm->vmid);
		clear_bit(ACRN_VM_FLAG_DESTROYED, &vm->flags);
		return ret;
	}

	/* Remove from global VM list */
	write_lock_bh(&acrn_vm_list_lock);
	list_del_init(&vm->list);
	write_unlock_bh(&acrn_vm_list_lock);

	mutex_lock(&arcn_async_io_vm_list_mutex);
	list_del_init(&vm->async_io_vm_list);
	mutex_unlock(&arcn_async_io_vm_list_mutex);

	acrn_ioeventfd_deinit(vm);
	acrn_irqfd_deinit(vm);
	acrn_ioreq_deinit(vm);

	if (vm->monitor_page) {
		put_page(vm->monitor_page);
		vm->monitor_page = NULL;
	}

	vm->is_destroying = true;
	wake_up_interruptible(&vm->async_ioreqs_wq);
	acrn_async_ioreq_deinit(vm);

	acrn_vm_all_ram_unmap(vm);

	dev_dbg(acrn_dev.this_device, "VM %u destroyed.\n", vm->vmid);
	vm->vmid = ACRN_INVALID_VMID;
	return 0;
}

/**
 * acrn_msi_inject() - Inject a MSI interrupt into a User VM
 * @vm:		User VM
 * @msi_addr:	The MSI address
 * @msi_data:	The MSI data
 *
 * Return: 0 on success, <0 on error
 */
int acrn_msi_inject(struct acrn_vm *vm, u64 msi_addr, u64 msi_data)
{
	struct acrn_msi_entry *msi;
	int ret;

	/* might be used in interrupt context, so use GFP_ATOMIC */
	msi = kzalloc(sizeof(*msi), GFP_ATOMIC);
	if (!msi)
		return -ENOMEM;

	/*
	 * msi_addr: addr[19:12] with dest vcpu id
	 * msi_data: data[7:0] with vector
	 */
	msi->msi_addr = msi_addr;
	msi->msi_data = msi_data;
	ret = hcall_inject_msi(vm->vmid, virt_to_phys(msi));
	if (ret < 0)
		dev_err(acrn_dev.this_device,
			"Failed to inject MSI to VM %u!\n", vm->vmid);
	kfree(msi);
	return ret;
}
