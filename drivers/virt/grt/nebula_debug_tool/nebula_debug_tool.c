/* SPDX-License-Identifier: GPL-2.0-only */

#include <linux/module.h>
#include <linux/mm.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/err.h>
#include <linux/uaccess.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/of_reserved_mem.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/nebula/hvcall.h>
#include <linux/arm-smccc.h>

#define LOG_TAG "nebula_debug_tool"

static int split_params_string(const char *val, char p[3][64]) {
	char param_str[128] = {0};
	memcpy(param_str, val, strlen(val) - 1);
	char *tmp_ptr1 = &param_str[0];
	char *tmp_ptr2 = NULL;
	int index = 0;

	if (!p) {
		pr_err("%s: NULL output parameters\n", LOG_TAG);
		return -EINVAL;
	}

	do {
		size_t param_size = 0;
		tmp_ptr2 = strchr(tmp_ptr1, ':');
		if (!tmp_ptr2) {
			param_size = strlen(tmp_ptr1);
			memcpy(p[index], tmp_ptr1, param_size);
			p[index][param_size] = '\0';
			break;
		}

		param_size = (size_t)(tmp_ptr2 - tmp_ptr1);
		memcpy(p[index], tmp_ptr1, param_size);
		p[index][param_size] = '\0';

		tmp_ptr1 = tmp_ptr2 + 1;
		index++;
	} while (true);

	return index + 1;
}

static int reserved_mem_test_set(const char *val, const struct kernel_param *kp)
{
	struct device_node *rmem_node = NULL;
	struct reserved_mem *rmem = NULL;
	char params[3][64];
	int param_count = 0;
	phys_addr_t addr_offset = 0;

	memset(params, 0, sizeof(params));
	param_count = split_params_string(val, params);

	if (param_count != 2) {
		pr_err("%s: parameter format <reserved_mem_name>:<addr_offset_hex>\n", LOG_TAG);
		return -EINVAL;
	}

	addr_offset = simple_strtoul(params[1], NULL, 16);
	pr_info("%s: start read reserved_mem %s offset 0x%llx\n", LOG_TAG, params[0], addr_offset);
	rmem_node = of_find_node_by_name(NULL, params[0]);
	if (!rmem_node) {
		pr_err("%s: failed to find device node\n", LOG_TAG);
		return -EINVAL;
	}

	rmem = of_reserved_mem_lookup(rmem_node);
	if (!rmem) {
		pr_err("%s: failed to find reserved_mem in device tree\n", LOG_TAG);
		return -EINVAL;
	}

	void* rmem_virt = ioremap(rmem->base, rmem->size);
	if (!rmem_virt) {
		pr_err("%s: failed to remap reserved_mem\n", LOG_TAG);
		return -EIO;
	}

	pr_info("%s: virt 0x%lx phys 0x%llx size 0x%llx\n", LOG_TAG,
		(uintptr_t)rmem_virt, rmem->base, rmem->size);

	uintptr_t virt_addr = (uintptr_t)rmem_virt + addr_offset;
	pr_info("%s: read addr offset 0x%llx = 0x%x\n", LOG_TAG, addr_offset, *(uint32_t*)virt_addr);

	// do not invoke iounmap to avoid kernel stucked before dumping data abort backtrace information
	//iounmap(rmem_virt);
	return 0;
}

static int reserved_mem_test_get(char *buffer, const struct kernel_param *kp)
{
	return 0;
}

module_param_call(reserved_mem_test, reserved_mem_test_set, reserved_mem_test_get, NULL, 0644);

static int smc_test_set(const char *val, const struct kernel_param *kp)
{
	char params[3][64];
	int param_count = 0;

	memset(params, 0, sizeof(params));
	param_count = split_params_string(val, params);

	if (param_count != 3) {
		pr_err("%s: parameter format <smc_fid_hex>:<hc_id_hex>:<secure_id>\n", LOG_TAG);
		return -EINVAL;
	}

	unsigned long smc_fid = simple_strtoul(params[0], NULL, 16);
	unsigned long hc_id = simple_strtoul(params[1], NULL, 16);
	unsigned long secure_id = simple_strtoul(params[2], NULL, 10);
	struct arm_smccc_res res;
	unsigned long r7 = secure_id << 16;

	pr_info("%s: smc fid 0x%lx hc_id 0x%lx secure id %lu\n", LOG_TAG, smc_fid, hc_id, secure_id);

	arm_smccc_smc(smc_fid, hc_id, 0, 0, 0, 0, 0, r7, &res);
	pr_info("%s: ret 0x%lx 0x%lx 0x%lx\n", LOG_TAG, res.a0, res.a1, res.a2);
	return 0;
}

static int smc_test_get(char *buffer, const struct kernel_param *kp)
{
	return 0;
}

module_param_call(smc_test, smc_test_set, smc_test_get, NULL, 0644);


static int __init nebula_debug_tool_init(void)
{
	return 0;
}

static void __exit nebula_debug_tool_exit(void)
{
	return;
}

module_init(nebula_debug_tool_init);
module_exit(nebula_debug_tool_exit);

MODULE_LICENSE("GPL v2");
