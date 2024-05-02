/* SPDX-License-Identifier: GPL-2.0-only */

#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/init.h>
#include <linux/interrupt.h>

#include <asm/acrn.h>

static void (*acrn_intr_handler)(void);

void acrn_setup_intr_handler(void (*handler)(void))
{
	acrn_intr_handler = handler;
}
EXPORT_SYMBOL_GPL(acrn_setup_intr_handler);

void acrn_remove_intr_handler(void)
{
	acrn_intr_handler = NULL;
}
EXPORT_SYMBOL_GPL(acrn_remove_intr_handler);

static irqreturn_t hsm_intr_handler(int irq, void *data)
{
	if (acrn_intr_handler)
		acrn_intr_handler();
	return IRQ_HANDLED;
}

static int acrn_hsm_probe(struct platform_device *pdev)
{
	int ret;

	dev_err(&pdev->dev, "Enter acrn_hsm_probe\n");
	int irq = platform_get_irq(pdev, 0);
	if (irq < 0) {
		dev_err(&pdev->dev, "Failed to get_irq: %d\n", irq);
		return -EINVAL;
	}

	ret = devm_request_irq(&pdev->dev, irq, hsm_intr_handler, 0, "acrn-hsm",
			       NULL);
	if (ret < 0) {
		dev_err(&pdev->dev, "Failed to request_irq: %d\n", ret);
		return -EINVAL;
	}

	return 0;
}

static const struct of_device_id acrn_hsm_of_match[] = {
	{
		.compatible = "nbl,acrn-hsm",
	},
	{},
};

static struct platform_driver acrn_hsm_driver = {
	.probe = acrn_hsm_probe,
	.driver	= {
		.name = "acrn-hsm",
		.owner = THIS_MODULE,
		.of_match_table = acrn_hsm_of_match,
	},
};

static int __init acrn_hsm_init(void)
{
	return platform_driver_register(&acrn_hsm_driver);
}
subsys_initcall(acrn_hsm_init);

MODULE_LICENSE("GPL v2");
