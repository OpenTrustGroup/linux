/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright 2018 GoldenRiver Technologies Co., Ltd. All rights reserved.
 * Copyright (C) 2015 Google, Inc.
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

#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/dma-buf.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/nebula/trusty_kern_ipc.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <uapi/linux/uio.h>

#include <linux/kthread.h>

#include <linux/nebula/nbl-tui.h> /* pwrkey */
#include "nebula-rpc.h"
#include "nebula-rpc-proto.h"

#include "hal/tui-hal_mt.h"

struct task_struct *pwrkey_observer_thread;
static bool pwrkey_pressed;
static DECLARE_WAIT_QUEUE_HEAD(pwrkey_wq);

#define ZX_OK		     (0)
#define ZX_ERR_NOT_SUPPORTED (-2)
#define ZX_ERR_INVALID_ARGS  (-10)
struct smmu_map_req_t {
	union {
		uint64_t paddr; // paddr is used for map
		uint64_t vaddr; // vaddr is used for unmap
	};
	uint64_t size;
} __attribute__((packed));
struct smmu_map_rsp_t {
	int32_t status;
	uint64_t smmu_va;
} __attribute__((packed));

void nbl_tui_notify_pwrkey(void)
{
	pwrkey_pressed = true;
	wake_up(&pwrkey_wq);
}

EXPORT_SYMBOL(nbl_tui_notify_pwrkey);

struct nbl_tui_tpd_ops g_tpd_ops;

void nbl_tui_register_tpd_ops(struct nbl_tui_tpd_ops ops)
{
	g_tpd_ops = ops;
}
EXPORT_SYMBOL(nbl_tui_register_tpd_ops);

int nbl_tui_tpd_enter(void)
{
	BUG_ON(!g_tpd_ops.enter);
	return g_tpd_ops.enter();
}
EXPORT_SYMBOL(nbl_tui_tpd_enter);

int nbl_tui_tpd_exit(void)
{
	BUG_ON(!g_tpd_ops.exit);
	return g_tpd_ops.exit();
}
EXPORT_SYMBOL(nbl_tui_tpd_exit);

enum tpd_devid_t nbl_tui_tpd_devid(void)
{
	BUG_ON(!g_tpd_ops.devid);
	return g_tpd_ops.devid();
}
EXPORT_SYMBOL(nbl_tui_tpd_devid);

static int powerkey_observer(void *data)
{
	pr_info("powerkey observer thread started\n");
	while (1) {
		int ret;

		wait_event_interruptible(
			pwrkey_wq, pwrkey_pressed || kthread_should_stop());
		if (kthread_should_stop()) {
			break;
		}

		pwrkey_pressed = false;
		ret = nbl_rpc_send(NBL_URPC_TUI_POWER_KEY_PRESSED, NULL, 0);
		if (ret < 0) {
			pr_warn("unable to send power key pressed event");
		}
	}
	pr_info("powerkey observer thread stopped\n");

	return 0;
}

static nbl_status start_powerkey_observer(uint32_t cmd, const void *in,
					  size_t in_size, void **out,
					  size_t *out_size)
{
	pwrkey_observer_thread =
		kthread_run(powerkey_observer, NULL, "powerkey_observer");
	if (IS_ERR(pwrkey_observer_thread)) {
		int ret = PTR_ERR(pwrkey_observer_thread);
		pr_err("failed to start power key observer thread (%d)\n", ret);
		return serialize_status(ret, out, out_size);
	}
	return serialize_status(0, out, out_size);
}

static nbl_status stop_powerkey_observer(uint32_t cmd, const void *in,
					 size_t in_size, void **out,
					 size_t *out_size)
{
	if (pwrkey_observer_thread)
		kthread_stop(pwrkey_observer_thread);
	pwrkey_observer_thread = NULL;
	return serialize_status(0, out, out_size);
}

static nbl_status tpd_off(uint32_t cmd, const void *in, size_t in_size,
			  void **out, size_t *out_size)
{
	return serialize_status(nbl_tui_tpd_enter(), out, out_size);
}

static nbl_status tpd_on(uint32_t cmd, const void *in, size_t in_size,
			 void **out, size_t *out_size)
{
	return serialize_status(nbl_tui_tpd_exit(), out, out_size);
}

static nbl_status tpd_devid(uint32_t cmd, const void *in, size_t in_size,
			    void **out, size_t *out_size)
{
	return serialize_status(nbl_tui_tpd_devid(), out, out_size);
}

static nbl_status i2c_clk_on(uint32_t cmd, const void *in, size_t in_size,
			     void **out, size_t *out_size)
{
	int ret;
	int clk_id;

	if (in_size < sizeof(clk_id))
		return kNblErrInvalidArgs;

	clk_id = *((int *)in);
	ret = i2c_tui_enable_clock(clk_id);

	return serialize_status(ret, out, out_size);
}

static nbl_status i2c_clk_off(uint32_t cmd, const void *in, size_t in_size,
			      void **out, size_t *out_size)
{
	int ret;
	int clk_id;

	if (in_size < sizeof(clk_id))
		return kNblErrInvalidArgs;

	clk_id = *((int *)in);
	ret = i2c_tui_disable_clock(clk_id);

	return serialize_status(ret, out, out_size);
}

static nbl_status disp_off(uint32_t cmd, const void *in, size_t in_size,
			   void **out, size_t *out_size)
{
	return serialize_status(display_enter_tui(), out, out_size);
}

static nbl_status disp_on(uint32_t cmd, const void *in, size_t in_size,
			  void **out, size_t *out_size)
{
	return serialize_status(display_exit_tui(), out, out_size);
}

static nbl_status rpc_mempool_acquire(uint32_t cmd, const void *in,
				      size_t in_size, void **out,
				      size_t *out_size)
{
	struct {
		int32_t status;
		uint64_t base;
		uint64_t size;
	} resp = {};

	resp.status = ssmr_offline(&resp.base, (size_t *)&resp.size,
				   /*allow64=*/true, SSMR_FEAT_TUI);

	return serialize(&resp, sizeof(resp), out, out_size);
}

static nbl_status rpc_mempool_release(uint32_t cmd, const void *in,
				      size_t in_size, void **out,
				      size_t *out_size)
{
	struct {
		int32_t status;
	} resp = {};

	resp.status = ssmr_online(SSMR_FEAT_TUI);

	return serialize(&resp, sizeof(resp), out, out_size);
}

static nbl_status rpc_smmu_alloc(uint32_t cmd, const void *in, size_t in_size,
				 void **out, size_t *out_size)
{
	int ret;
	struct smmu_map_req_t *req = (void *)in;
	struct smmu_map_rsp_t rsp = {};
	unsigned long mva_addr;

	if (in_size < sizeof(*req) || (!req->paddr && !req->size)) {
		rsp.status = ZX_ERR_INVALID_ARGS;
		goto err_invalid_args;
	}

	ret = disp_smmu_map(req->paddr, req->size, &mva_addr);
	if (ret) {
		rsp.status = ret;
		goto err_smmu_map;
	}

	rsp.status = ZX_OK;
	rsp.smmu_va = mva_addr;

err_smmu_map:
err_invalid_args:
	pr_info("smmu_alloc: status %d smmu_va %llx paddr %#llx, size %#llx\n",
		rsp.status, rsp.smmu_va, req->paddr, req->size);

	return serialize(&rsp, sizeof(rsp), out, out_size);
};

static nbl_status rpc_smmu_free(uint32_t cmd, const void *in, size_t in_size,
				void **out, size_t *out_size)
{
	int ret;
	struct smmu_map_req_t *req = (void *)in;
	struct smmu_map_rsp_t rsp = {};

	if (in_size < sizeof(*req) || !req->vaddr) {
		rsp.status = ZX_ERR_INVALID_ARGS;
		goto err_invalid_args;
	}

	ret = disp_smmu_unmap(req->vaddr);
	if (ret) {
		rsp.status = ret;
		goto err_smmu_unmap;
	}

	rsp.status = ZX_OK;

err_smmu_unmap:
err_invalid_args:
	pr_info("smmu_free: status %d smmu_va %llx\n", rsp.status, req->vaddr);

	return serialize(&rsp, sizeof(rsp), out, out_size);
}

static int __init nbl_tui_init(void)
{
	nbl_rpc_add_cb(NBL_KRPC_TUI_START_POWERKEY_OBSERVER,
		       start_powerkey_observer);
	nbl_rpc_add_cb(NBL_KRPC_TUI_STOP_POWERKEY_OBSERVER,
		       stop_powerkey_observer);
	nbl_rpc_add_cb(NBL_KRPC_TUI_TPD_OFF, tpd_off);
	nbl_rpc_add_cb(NBL_KRPC_TUI_TPD_ON, tpd_on);
	nbl_rpc_add_cb(NBL_KRPC_TUI_TPD_DEVID, tpd_devid);
	nbl_rpc_add_cb(NBL_KRPC_TUI_I2C_CLK_ON, i2c_clk_on);
	nbl_rpc_add_cb(NBL_KRPC_TUI_I2C_CLK_OFF, i2c_clk_off);
	nbl_rpc_add_cb(NBL_KRPC_TUI_DISP_OFF, disp_off);
	nbl_rpc_add_cb(NBL_KRPC_TUI_DISP_ON, disp_on);
	nbl_rpc_add_cb(NBL_KRPC_MEMPOOL_ACQUIRE, rpc_mempool_acquire);
	nbl_rpc_add_cb(NBL_KRPC_MEMPOOL_RELEASE, rpc_mempool_release);
	nbl_rpc_add_cb(NBL_KRPC_SMMU_ALLOC, rpc_smmu_alloc);
	nbl_rpc_add_cb(NBL_KRPC_SMMU_FREE, rpc_smmu_free);

	return 0;
}

late_initcall(nbl_tui_init);

MODULE_DESCRIPTION("NBL TUI driver");
MODULE_LICENSE("GPL v2");
