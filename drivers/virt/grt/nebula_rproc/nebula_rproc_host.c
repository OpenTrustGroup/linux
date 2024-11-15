
// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2024 GoldenRiver Inc.

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/debugfs.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/remoteproc.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/virtio_ids.h>
#include <linux/spinlock.h>
#include <linux/dma-mapping.h>
#include <linux/dma-map-ops.h>
#include <linux/genalloc.h>
#include <linux/arm-smccc.h>
#include <linux/nebula/hvcall.h>

irqreturn_t rproc_vq_interrupt(struct rproc *rproc, int vq_id);

enum {
	RPROC_REG_SET_READY = 0x0,
	RPROC_REG_CLEAR_READY = 0x4,
	RPROC_REG_STATE = 0x8,
	RPROC_REG_KICK = 0xc,
};

enum {
	STATE_NOT_READY,
	STATE_READY,
};

static void signal_irq(uint16_t irq)
{
	struct arm_smccc_res res;
	unsigned long r7 = SMC_HYP_SECURE_ID << 16;
	arm_smccc_smc(SMC_FC_NBL_VHM_REQ, 0, irq, 0, 0, 0, 0, r7, &res);
}

#define RSC_TAB_SIZE 0x1000
#define NBL_RPROC_MAGIC 0x6E626C5F72656d6fULL

struct irq_info {
	int local_virq;
	int remote_hwirq;
	struct rproc *rproc;
	int notifyid;
};

struct rproc_host_priv {
	uint64_t magic;
	void *__iomem reg_base;
	void *shm_base;
	size_t shm_size;
	uint64_t shm_phys;
	struct workqueue_struct *workq;
	struct work_struct attach_work;
	struct rproc *rproc;
	struct gen_pool *dma_buf_pool;

	int num_queues;
	struct irq_info *irq_info;
	bool notify_with_phys_irq;
};

static irqreturn_t rproc_notify_irq_handler(int irq, void *data)
{
	struct irq_info *info = data;
	if (rproc_vq_interrupt(info->rproc, info->notifyid) == IRQ_NONE)
		dev_dbg(&info->rproc->dev, "no message found in vq%d\n",
			info->notifyid);
	return IRQ_HANDLED;
}

static irqreturn_t rproc_ctrl_irq_handler(int irq, void *data)
{
	// nothing to do currently
	return IRQ_HANDLED;
}

static int nebula_rproc_attach(struct rproc *rproc)
{
	return 0;
}

static int nebula_rproc_detach(struct rproc *rproc)
{
	return 0;
}

static struct resource_table *
nebula_rproc_get_loaded_rsc_table(struct rproc *rproc, size_t *table_sz)
{
	struct rproc_host_priv *priv = rproc->priv;

	*table_sz = SZ_4K;
	return (struct resource_table *)priv->shm_base;
}

static void nebula_rproc_kick(struct rproc *rproc, int notifyid)
{
	struct rproc_host_priv *priv = rproc->priv;

	if (priv->notify_with_phys_irq) {
		struct irq_info *info = &priv->irq_info[notifyid];
		signal_irq(info->remote_hwirq);
	} else {
		writel_relaxed(notifyid, priv->reg_base + RPROC_REG_KICK);
	}
}

static struct rproc_ops nebula_rproc_ops = {
	.attach = nebula_rproc_attach,
	.detach = nebula_rproc_detach,
	.kick = nebula_rproc_kick,
	.get_loaded_rsc_table = nebula_rproc_get_loaded_rsc_table,
};

static void rproc_host_attach_work(struct work_struct *work)
{
	struct rproc_host_priv *priv =
		container_of(work, struct rproc_host_priv, attach_work);
	rproc_boot(priv->rproc);
}

static struct rproc_host_priv *to_priv(struct device *dev)
{
	struct rproc_host_priv *priv = dev_get_drvdata(dev);

	// request may comes from out grandchild
	if (priv->magic != NBL_RPROC_MAGIC) {
		dev = dev->parent->parent;
		priv = dev_get_drvdata(dev);
	}

	BUG_ON(priv->magic != NBL_RPROC_MAGIC);
	return priv;
}

static void *rproc_alloc_coherent(struct device *dev, size_t size,
				  dma_addr_t *dma_addr, gfp_t flag,
				  unsigned long attrs)
{
	void *ptr;
	struct rproc_host_priv *priv = to_priv(dev);

	dev_dbg(dev, "rproc_alloc_coherent: size=%lx, attrs=%lx\n", size,
		attrs);

	ptr = gen_pool_dma_alloc(priv->dma_buf_pool, size, dma_addr);
	dev_dbg(dev, "rproc_alloc_coherent: addr=%px, dma_addr=%llx\n", ptr,
		*dma_addr);

	return ptr;
}

static void rproc_free_coherent(struct device *dev, size_t size, void *vaddr,
				dma_addr_t dma_addr, unsigned long attrs)
{
	struct rproc_host_priv *priv = to_priv(dev);

	dev_dbg(dev, "rproc_alloc_coherent: addr=%llx size=%lx, attrs=%lx\n",
		dma_addr, size, attrs);
	gen_pool_free(priv->dma_buf_pool, (unsigned long)vaddr, size);
}

static const struct dma_map_ops rproc_dma_ops = {
	.alloc = rproc_alloc_coherent,
	.free = rproc_free_coherent,
};

#define MAX_VIRTIO_DEVICES 20

struct rproc_resource_table
{
	u32 ver;
	u32 num;
	u32 reserved[2];
	u32 offset[MAX_VIRTIO_DEVICES];
} __packed;

struct rproc_vdev_desc
{
	struct fw_rsc_hdr hdr;
	struct fw_rsc_vdev vdev;
} __packed;

static void dump_rsc_table(struct device *dev, void *table)
{
	struct rproc_resource_table *rsc_table = table;
	int i;
	dev_dbg(dev, "dump_rsc_table\n");
	dev_dbg(dev, "ver=%d\n", rsc_table->ver);
	dev_dbg(dev, "num=%d\n", rsc_table->num);

	for (i = 0; i < rsc_table->num; i++)
	{
		struct rproc_vdev_desc *vdev_desc;
		u32 offset = rsc_table->offset[i];

		vdev_desc = table + offset;
		dev_dbg(dev, "vdev%d, offset=%x\n", i, rsc_table->offset[i]);
		dev_dbg(dev, "vdev%d, type=%x", i, vdev_desc->hdr.type);
		dev_dbg(dev, "vdev%d, num_vrings=%d", i, vdev_desc->vdev.num_of_vrings);
	}
}

static int rproc_host_probe(struct platform_device *pdev)
{
	struct resource *mem;
	struct device *dev = &pdev->dev;
	struct rproc_host_priv *priv;
	int ret, virq;
	struct rproc *rproc;
	void *__iomem reg_base;
	void *shm_base, *gen_pool_base;
	size_t shm_size, gen_pool_size;
	uint64_t shm_phys, gen_pool_phys;
	int irq_count, remote_irq_count, i;
	cpumask_t mask;

	rproc = devm_rproc_alloc(dev, "nbl_rproc_remote", &nebula_rproc_ops,
				 NULL, sizeof(*priv));
	if (!rproc)
		return -ENOMEM;

	priv = rproc->priv;
	mem = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!mem) {
		ret = -EINVAL;
		goto err_free_priv;
	}

	reg_base = devm_ioremap_resource(dev, mem);
	if (IS_ERR(reg_base)) {
		ret = PTR_ERR(reg_base);
		goto err_free_priv;
	}

	mem = platform_get_resource(pdev, IORESOURCE_MEM, 1);
	if (!mem) {
		ret = -EINVAL;
		goto err_unmap_reg;
	}

	shm_phys = mem->start;
	shm_size = resource_size(mem);
	shm_base = devm_memremap(dev, shm_phys, shm_size, MEMREMAP_WB);
	if (!shm_base) {
		ret = -EINVAL;
		goto err_unmap_reg;
	}
	dev_info(dev, "shared memory mapped @ %px, size %lx\n", shm_base,
		 shm_size);

	priv->magic = NBL_RPROC_MAGIC;
	priv->reg_base = reg_base;
	priv->shm_phys = shm_phys;
	priv->shm_base = shm_base;
	priv->shm_size = shm_size;
	priv->rproc = rproc;
	INIT_WORK(&priv->attach_work, rproc_host_attach_work);

	priv->workq = alloc_workqueue("nebula_rproc_host", WQ_MEM_RECLAIM, 0);
	if (!priv->workq) {
		ret = -ENOMEM;
		goto err_unmap_reg;
	}

	priv->dma_buf_pool = gen_pool_create(0, -1);
	if (priv->dma_buf_pool == NULL) {
		dev_err(dev, "failed to create gen pool\n");
		ret = -ENOMEM;
		goto err_unmap_shm;
	}

	gen_pool_phys = shm_phys + RSC_TAB_SIZE;
	gen_pool_base = shm_base + RSC_TAB_SIZE;
	gen_pool_size = shm_size - RSC_TAB_SIZE;
	memset(gen_pool_base, 0, gen_pool_size);
	ret = gen_pool_add_virt(priv->dma_buf_pool,
				(unsigned long)gen_pool_base, gen_pool_phys,
				gen_pool_size, -1);
	if (ret) {
		dev_err(dev, "failed to gen_pool_add_virt, ret=%d\n", ret);
		goto err_release_gen_pool;
	}
	set_dma_ops(dev, &rproc_dma_ops);

	rproc->auto_boot = false;
	rproc->state = RPROC_DETACHED;
	ret = devm_rproc_add(dev, rproc);
	if (ret) {
		dev_err(dev, "rproc_add failed\n");
		goto err_release_gen_pool;
	}

	irq_count = platform_irq_count(pdev);
	ret = of_property_read_u32(dev->of_node, "remote_irq_count",
				   &remote_irq_count);
	BUG_ON(ret != 0);

	if (remote_irq_count) {
		dev_info(dev, "notify using physical interrupt\n");
		priv->notify_with_phys_irq = true;
		BUG_ON(remote_irq_count != irq_count - 1);
	}

	// bind rproc irq to vcpu5
	cpumask_clear(&mask);
	cpumask_set_cpu(5, &mask);

	virq = platform_get_irq(pdev, 0);
	ret = devm_request_threaded_irq(&pdev->dev, virq, NULL,
					rproc_ctrl_irq_handler, IRQF_ONESHOT,
					dev_name(&pdev->dev), priv);
	BUG_ON(ret < 0);
	irq_set_affinity_hint(virq, &mask);

	priv->num_queues = irq_count - 1;
	priv->irq_info =
		kzalloc(irq_count * sizeof(struct irq_info), GFP_KERNEL);
	if (!priv->irq_info)
		goto err_remove_rproc;

	for (i = 0; i < priv->num_queues; i++) {
		struct irq_info *irq_info = &priv->irq_info[i];

		virq = platform_get_irq(pdev, i + 1);
		BUG_ON(virq < 0);

		irq_info->local_virq = virq;
		irq_info->notifyid = i;
		irq_info->rproc = rproc;
		if (priv->notify_with_phys_irq) {
			int hwirq;
			ret = of_property_read_u32_index(
				dev->of_node, "remote_irqs", i, &hwirq);
			BUG_ON(ret < 0);
			irq_info->remote_hwirq = hwirq;
		}

		ret = devm_request_threaded_irq(&pdev->dev, virq, NULL,
						rproc_notify_irq_handler,
						IRQF_ONESHOT,
						dev_name(&pdev->dev), irq_info);
		BUG_ON(ret < 0);
		irq_set_affinity_hint(virq, &mask);
	}

	platform_set_drvdata(pdev, priv);
	writel_relaxed(0, priv->reg_base + RPROC_REG_SET_READY);

	// TODO: should check remote is alive before attach
	queue_work(priv->workq, &priv->attach_work);
	return 0;

err_remove_rproc:
	rproc_del(rproc);
err_release_gen_pool:
	gen_pool_destroy(priv->dma_buf_pool);
err_unmap_shm:
	devm_memunmap(dev, shm_base);
err_unmap_reg:
	devm_iounmap(dev, reg_base);
err_free_priv:
	rproc_free(rproc);
	return ret;
}

static int rproc_host_remove(struct platform_device *pdev)
{
	return 0;
}

static const struct of_device_id rproc_host_of_match[] = {
	{
		.compatible = "grt,rproc-host",
	},
	{},
};

static struct platform_driver nebula_rproc_host = {
	.probe = rproc_host_probe,
	.remove = rproc_host_remove,
	.driver	= {
		.name = "nebula-rproc-host",
		.owner = THIS_MODULE,
		.of_match_table = rproc_host_of_match,
	},
};

static int __init nebula_rproc_host_init(void)
{
	return platform_driver_register(&nebula_rproc_host);
}

module_init(nebula_rproc_host_init);
MODULE_LICENSE("Dual BSD/GPL");