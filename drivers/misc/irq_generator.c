/*
 * Copyright 2023 GoldenRiver Technologies Co., Ltd.
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

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/debugfs.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/nebula/hvcall.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/arm-smccc.h>

static void *__iomem reg_base;
static int hwirq;

#define TRIGGER_REG 4

static ssize_t trigger_write(struct file *filp, const char __user *buf,
			     size_t count, loff_t *ppos)
{
	size_t len;
	char bitmask[32];
	int val;

	len = min(count, sizeof(bitmask) - 1);
	if (copy_from_user(bitmask, buf, len))
		return -EFAULT;

	while (len > 0 && bitmask[len - 1] == '\n')
		len--;
	bitmask[len] = '\0';

	val = simple_strtoul(bitmask, NULL, 0);
	iowrite32(val, reg_base + TRIGGER_REG);

	return count;
}

static int trigger_show(struct seq_file *m, void *v)
{
	return 0;
}

static int trigger_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, trigger_show, inode->i_private);
}

static const struct file_operations trigger_fops = {
	.open = trigger_open,
	.release = single_release,
	.read = seq_read,
	.write = trigger_write,
	.owner = THIS_MODULE,
};

static uint32_t get_irq_status(uint16_t vector)
{
	struct arm_smccc_res res;
	arm_smccc_smc(SMC_SC_NBL_VHM_REQ, 0x90000000, vector, 0, 0, 0, 0, 0,
		      &res);
	return res.a0;
}

static void clear_irq_status(uint16_t vector, uint32_t bitmask)
{
	struct arm_smccc_res res;
	arm_smccc_smc(SMC_SC_NBL_VHM_REQ, 0x90000001, vector, bitmask, 0, 0, 0,
		      0, &res);
}

static irqreturn_t irq_handler(int irq, void *data)
{
	uint32_t status = get_irq_status(hwirq);
	pr_err("irq_handler, status = %x\n", status);

	clear_irq_status(hwirq, status);
	return IRQ_HANDLED;
}

static int irq_generator_probe(struct platform_device *pdev)
{
	struct dentry *debugfs_root;
	const char *dir_name = "irq_generator";
	struct resource *mem;
	struct irq_desc *desc;
	int ret, virq;

	mem = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!mem)
		return -EINVAL;

	reg_base = devm_ioremap_resource(&pdev->dev, mem);
	if (IS_ERR(reg_base))
		return PTR_ERR(reg_base);

	virq = platform_get_irq(pdev, 0);
	if (virq < 0) {
		dev_err(&pdev->dev, "failed to get platform irq\n");
		return -EINVAL;
	}

	desc = irq_to_desc(virq);
	if (!desc) {
		dev_err(&pdev->dev, "failed to get irq_desc\n");
		return -EINVAL;
	}
	hwirq = desc->irq_data.hwirq;

	ret = devm_request_irq(&pdev->dev, virq, irq_handler, 0,
			       dev_name(&pdev->dev), NULL);
	if (ret < 0) {
		dev_err(&pdev->dev, "failed to request_irq\n");
		return -EINVAL;
	}

	debugfs_root = debugfs_create_dir(dir_name, NULL);
	if (IS_ERR(debugfs_root)) {
		pr_err("debugfs_create_dir failed: %ld\n",
		       PTR_ERR(debugfs_root));
		return PTR_ERR(debugfs_root);
	}

	debugfs_create_file("trigger", 0600, debugfs_root, NULL, &trigger_fops);
	return 0;
}

static int irq_generator_remove(struct platform_device *pdev)
{
	return 0;
}

static const struct of_device_id irq_generator_of_match[] = {
	{
		.compatible = "nbl,irq-generator",
	},
	{},
};

static struct platform_driver irq_generator_driver = {
	.probe = irq_generator_probe,
	.remove = irq_generator_remove,
	.driver	= {
		.name = "irq-generator",
		.owner = THIS_MODULE,
		.of_match_table = irq_generator_of_match,
	},
};

static int __init irq_generator_driver_init(void)
{
	return platform_driver_register(&irq_generator_driver);
}

module_init(irq_generator_driver_init);
