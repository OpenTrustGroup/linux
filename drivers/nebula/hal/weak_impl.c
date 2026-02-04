/*
 * Copyright 2019 GoldenRiver Technologies Co., Ltd. All rights reserved.
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

#include <linux/module.h>
#include <linux/sizes.h>
#include <linux/types.h>
#include <linux/of_address.h>

#include <hal/tui-hal_mt.h>


int __weak i2c_tui_enable_clock(int id)
{
	return 0;
}

int __weak i2c_tui_disable_clock(int id)
{
	return 0;
}

int __weak tui_region_offline(phys_addr_t *pa, unsigned long *size)
{
	return ssmr_offline(pa, size, 0, SSMR_FEAT_TUI);
}

int __weak tui_region_online(void)
{
	return ssmr_online(SSMR_FEAT_TUI);
}

int __weak display_enter_tui(void)
{
	return 0;
}

int __weak display_exit_tui(void)
{
	return 0;
}

int __weak ssmr_offline(phys_addr_t *pa, unsigned long *size, bool is_64bit,
			unsigned int feat)
{
	int ret;
	struct device_node *np;
	static struct resource buffer = {};

	if (!buffer.start && !buffer.end) {
		np = of_find_compatible_node(NULL, NULL, "ion_carveout");
		if (!np || !of_device_is_available(np))
			return -ENODEV;

		ret = of_address_to_resource(np, 0, &buffer);
		pr_info("%s: detected carveout ion reserved memory, base: 0x%llx, size: 0x%llx\n",
			__func__, buffer.start, resource_size(&buffer));
	}

	*pa = buffer.start;
	*size = resource_size(&buffer);
	return 0;
}

int __weak ssmr_online(unsigned int feat)
{
	return 0;
}

bool __weak is_mcdi_working(void)
{
	return false;
}

void __weak set_mcdi_enable_status(bool enabled)
{
}

int __weak disp_smmu_map(phys_addr_t pa_start, unsigned int size,
			 unsigned long *mva)
{
	return 0;
}

int __weak disp_smmu_unmap(phys_addr_t mva)
{
	return 0;
}