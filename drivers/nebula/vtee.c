/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright 2018 GoldenRiver Technologies Co., Ltd. All rights reserved.
 * Copyright (C) 2013 Google, Inc.
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

#include <linux/delay.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/nebula/smcall.h>
#include <linux/nebula/sm_err.h>
#include <linux/nebula/trusty.h>

#include "trusty.h"
#include "vtee-irq.h"

static int trusty_remove_child(struct device *dev, void *data)
{
	platform_device_unregister(to_platform_device(dev));
	return 0;
}

ssize_t vtee_version_show(struct device *dev, struct device_attribute *attr,
			    char *buf)
{
	struct trusty_state *s = platform_get_drvdata(to_platform_device(dev));

	return scnprintf(buf, PAGE_SIZE, "%s\n", s->version_str);
}

DEVICE_ATTR(vtee_version, S_IRUSR, vtee_version_show, NULL);

static int vtee_probe(struct platform_device *pdev)
{
	int ret;
	unsigned int cpu;
	work_func_t work_func;
	struct trusty_state *s;
	struct device_node *node = pdev->dev.of_node;

	if (!node) {
		dev_err(&pdev->dev, "of_node required\n");
		return -EINVAL;
	}

	s = kzalloc(sizeof(*s), GFP_KERNEL);
	if (!s) {
		ret = -ENOMEM;
		goto err_allocate_state;
	}

	s->smc_secure_id = SMC_TEE_SECURE_ID;
	s->dev = &pdev->dev;
	spin_lock_init(&s->nop_lock);
	INIT_LIST_HEAD(&s->nop_queue);
	mutex_init(&s->smc_lock);
	ATOMIC_INIT_NOTIFIER_HEAD(&s->notifier);
	init_completion(&s->cpu_idle_completion);
	platform_set_drvdata(pdev, s);

	nebula_init_version(s, &pdev->dev, &dev_attr_vtee_version);

	ret = nebula_init_api_version(s, &pdev->dev);
	if (ret < 0)
		goto err_api_version;

	s->nop_wq = alloc_workqueue("trusty-nop-wq", WQ_CPU_INTENSIVE, 0);
	if (!s->nop_wq) {
		ret = -ENODEV;
		dev_err(&pdev->dev, "Failed create trusty-nop-wq\n");
		goto err_create_nop_wq;
	}

	s->nop_works = alloc_percpu(struct trusty_work);
	if (!s->nop_works) {
		ret = -ENOMEM;
		dev_err(&pdev->dev, "Failed to allocate works\n");
		goto err_alloc_works;
	}

	if (s->api_version < TRUSTY_API_VERSION_SMP)
		work_func = nebula_locked_nop_work_func;
	else
		work_func = nebula_nop_work_func;

	for_each_possible_cpu(cpu) {
		struct trusty_work *tw = per_cpu_ptr(s->nop_works, cpu);

		tw->ts = s;
		INIT_WORK(&tw->work, work_func);
	}

	ret = of_platform_populate(pdev->dev.of_node, NULL, NULL, &pdev->dev);
	if (ret < 0) {
		dev_err(&pdev->dev, "Failed to add children: %d\n", ret);
		goto err_add_children;
	}

	return 0;

err_add_children:
	for_each_possible_cpu(cpu) {
		struct trusty_work *tw = per_cpu_ptr(s->nop_works, cpu);

		flush_work(&tw->work);
	}
	free_percpu(s->nop_works);
err_alloc_works:
	destroy_workqueue(s->nop_wq);
err_create_nop_wq:
err_api_version:
	if (s->version_str) {
		device_remove_file(&pdev->dev, &dev_attr_vtee_version);
		kfree(s->version_str);
	}
	device_for_each_child(&pdev->dev, NULL, trusty_remove_child);
	mutex_destroy(&s->smc_lock);
	kfree(s);
err_allocate_state:
	return ret;
}

static int vtee_remove(struct platform_device *pdev)
{
	unsigned int cpu;
	struct trusty_state *s = platform_get_drvdata(pdev);

	device_for_each_child(&pdev->dev, NULL, trusty_remove_child);

	for_each_possible_cpu(cpu) {
		struct trusty_work *tw = per_cpu_ptr(s->nop_works, cpu);

		flush_work(&tw->work);
	}
	free_percpu(s->nop_works);
	destroy_workqueue(s->nop_wq);

	mutex_destroy(&s->smc_lock);
	if (s->version_str) {
		device_remove_file(&pdev->dev, &dev_attr_vtee_version);
		kfree(s->version_str);
	}
	kfree(s);
	return 0;
}

static const struct of_device_id vtee_of_match[] = {
	{ .compatible = "grt,vtee-smc-v1", },
	{},
};

static struct platform_driver vtee_driver = {
	.probe = vtee_probe,
	.remove = vtee_remove,
	.driver	= {
		.name = "vtee",
		.owner = THIS_MODULE,
		.of_match_table = vtee_of_match,
	},
};

static int __init vtee_driver_init(void)
{
	int ret;

	/*
	 * Initialize vtee_irq_driver first since vtee_probe makes an
	 * std-call at the end where interrupts might be needed.
	 */
	ret = vtee_irq_driver_init();
	if (ret < 0)
		return ret;

	ret = platform_driver_register(&vtee_driver);
	if (ret < 0)
		goto err_driver_register;

	return 0;

err_driver_register:
	vtee_irq_driver_exit();
	return ret;
}

static void __exit vtee_driver_exit(void)
{
	platform_driver_unregister(&vtee_driver);
	vtee_irq_driver_exit();
}

subsys_initcall(vtee_driver_init);
module_exit(vtee_driver_exit);

MODULE_DESCRIPTION("Nebula vTEE core driver");
MODULE_LICENSE("GPL v2");
