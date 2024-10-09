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

#ifdef pr_fmt
#undef pr_fmt
#endif

#define pr_fmt(fmt) "[%s:%d]" fmt,__func__,__LINE__

static int hwirq;

static irqreturn_t simple_irq_handler(int irq, void *data)
{
	pr_info("recv irq = %d\n", irq);

	return IRQ_HANDLED;
}

static int simple_irq_probe(struct platform_device *pdev)
{
	struct irq_desc *desc;
	int ret, virq;

	pr_info("compatible=%s \n", pdev->dev.driver->of_match_table->compatible);

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
	pr_info("virq=%d hwirq=%d\n", virq, hwirq);
	ret = devm_request_irq(&pdev->dev, virq, simple_irq_handler, 0,
			       "simple-fake-irq", NULL);
	if (ret < 0) {
		dev_err(&pdev->dev, "failed to request_irq\n");
		return -EINVAL;
	}

	return 0;
}

static int simple_irq_remove(struct platform_device *pdev)
{
	return 0;
}

static const struct of_device_id simple_irq_of_match[] = {
	{
		.compatible = "nbl,simple-fake-irq",
	},
	{},
};

static struct platform_driver simple_irq_driver = {
	.probe = simple_irq_probe,
	.remove = simple_irq_remove,
	.driver	= {
		.name = "simple-fake-irq",
		.owner = THIS_MODULE,
		.of_match_table = simple_irq_of_match,
	},
};

static int __init simple_irq_driver_init(void)
{
	return platform_driver_register(&simple_irq_driver);
}

module_init(simple_irq_driver_init);
