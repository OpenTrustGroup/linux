// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2024 GoldenRiver Inc.

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/debugfs.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/idr.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/kthread.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/uaccess.h>

#include <linux/arm-smccc.h>
#include <linux/nebula/hvcall.h>

#include "rpmsg_virtio.h"
#include "remoteproc.h"
#include "remoteproc_virtio.h"
#include "nebula_rproc_remote.h"

enum {
	RPROC_REG_SET_READY = 0x0,
	RPROC_REG_CLEAR_READY = 0x4,
	RPROC_REG_SHM_BASE_LOW = 0x8,
	RPROC_REG_SHM_BASE_HIGH = 0xc,
	RPROC_REG_STATE = 0x10,
	RPROC_REG_KICK = 0x14,
};

enum {
	STATE_NOT_READY,
	STATE_READY,
};

#define VIRTIO_RPMSG_F_NS    0
#define RPMSG_VDEV_DFEATURES (1 << VIRTIO_RPMSG_F_NS)

/* Resource table entries */
#define NUM_VRINGS    0x02
#define VRING_ALIGN   0x1000
#define RING_TX	      0
#define RING_RX	      1
#define VRING_SIZE    256
#define MAX_RESOURCES 8

struct rpmsg_resource_table {
	u32 ver;
	u32 num;
	u32 reserved[2];
	u32 offset[MAX_RESOURCES];
	struct fw_rsc_hdr hdr;
	struct fw_rsc_vdev vdev;
	struct fw_rsc_vdev_vring vrings[NUM_VRINGS];
	struct fw_rsc_carveout carveout;
} __packed;

// TODO: automatically populate rsc table from dts
static const struct rpmsg_resource_table rpmsg_rsc_table = {
	.ver		= 1,
	.num            = 1,
	.reserved       = { 0, 0 },
	.offset         = {
		offsetof(struct rpmsg_resource_table, hdr),
	 },
	.hdr.type	= RSC_VDEV,
	.vdev		= {
		.id		= VIRTIO_ID_RPMSG,
		.dfeatures	= RPMSG_VDEV_DFEATURES,
		.config_len	= 0,
		.num_of_vrings	= NUM_VRINGS,
	},
	.vrings	= {
		[RING_TX]	= {
			.da		= FW_RSC_U32_ADDR_ANY,
			.align		= VRING_ALIGN,
			.num		= VRING_SIZE,
		},
		[RING_RX]	= {
			.da		= FW_RSC_U32_ADDR_ANY,
			.align		= VRING_ALIGN,
			.num		= VRING_SIZE,
		},
	},
};

static void signal_irq(uint16_t irq)
{
	struct arm_smccc_res res;
	unsigned long r7 = SMC_HYP_SECURE_ID << 16;
	arm_smccc_smc(SMC_FC_NBL_VHM_REQ, 0, irq, 0, 0, 0, 0, r7, &res);
}

// TODO: currently only one rpmsg device is supported
static struct nebula_rpmsg_backend *rpmsg_backend;

void nebula_rpmsg_backend_register(struct nebula_rpmsg_backend *backend)
{
	rpmsg_backend = backend;
}
EXPORT_SYMBOL(nebula_rpmsg_backend_register);

void nebula_rpmsg_backend_unregister(struct nebula_rpmsg_backend *backend)
{
	rpmsg_backend = NULL;
}
EXPORT_SYMBOL(nebula_rpmsg_backend_unregister);

void *nebula_rpmsg_backend_get_priv(void)
{
	if (rpmsg_backend)
		return rpmsg_backend->priv;

	return NULL;
}
EXPORT_SYMBOL(nebula_rpmsg_backend_get_priv);

struct irq_info {
	int local_virq;
	int remote_hwirq;
	struct virtio_vring_info *vring_info;
};

struct rproc_remote_priv {
	void *__iomem reg_base;
	void *shm_base;
	size_t shm_size;
	struct rpmsg_resource_table *rsc_table;
	struct rpmsg_virtio_device rvdev;
	struct virtio_device *vdev;
	phys_addr_t host_shm_phys;
	struct metal_io_region shm_io;
	atomic_t rvdev_inited;

	struct device *dev;
	int num_queues;
	struct irq_info *irq_info;
	bool notify_with_phys_irq;
};

static void *rproc_paddr_to_vaddr(struct virtqueue *vq, phys_addr_t phys)
{
	struct remoteproc_virtio *rpvdev =
		container_of(vq->vq_dev, struct remoteproc_virtio, vdev);
	struct rproc_remote_priv *priv = rpvdev->priv;

	u32 off = phys - priv->host_shm_phys;
	return priv->shm_base + off;
}

static phys_addr_t rproc_vaddr_to_paddr(struct virtqueue *vq, void *vaddr)
{
	struct remoteproc_virtio *rpvdev =
		container_of(vq->vq_dev, struct remoteproc_virtio, vdev);
	struct rproc_remote_priv *priv = rpvdev->priv;

	u32 off = (vaddr - priv->shm_base);
	return priv->host_shm_phys + off;
}

static void rproc_remote_ns_bind_cb(struct rpmsg_device *rdev, const char *name,
				    uint32_t dest)
{
	if (rpmsg_backend && rpmsg_backend->ops &&
	    rpmsg_backend->ops->on_bind) {
		rpmsg_backend->ops->on_bind(rdev, name, dest,
					    rpmsg_backend->priv);
	}
}

static void rproc_vdev_reset_cb(struct virtio_device *vdev)
{
}

static int rproc_vdev_notify(void *data, uint32_t notifyid)
{
	struct rproc_remote_priv *priv = data;

	if (priv->notify_with_phys_irq) {
		struct irq_info *info = &priv->irq_info[notifyid];
		signal_irq(info->remote_hwirq);
	} else {
		writel_relaxed(notifyid, priv->reg_base + RPROC_REG_KICK);
	}
	return 0;
}

static irqreturn_t rproc_notify_irq_handler(int irq, void *data)
{
	struct irq_info *info = data;

	if (info->vring_info)
		virtqueue_notification(info->vring_info->vq);
	return IRQ_HANDLED;
}

static int create_rpmsg_vdev(struct rproc_remote_priv *priv,
			     unsigned int notifyid,
			     const struct fw_rsc_vdev *vdev_rsc)
{
	int ret, rpmsg_ret;
	unsigned int num_vrings, i;

	priv->vdev = rproc_virtio_create_vdev(VIRTIO_DEV_DEVICE, notifyid,
					      (void *)vdev_rsc, /*rsc_io=*/NULL,
					      priv, rproc_vdev_notify,
					      rproc_vdev_reset_cb);
	if (!priv->vdev) {
		dev_err(priv->dev, "failed to create virtio vdev");
		return -ENOMEM;
	}

	rproc_virtio_wait_remote_ready(priv->vdev);

	/* set the notification id for vrings */
	num_vrings = vdev_rsc->num_of_vrings;
	for (i = 0; i < num_vrings; i++) {
		const struct fw_rsc_vdev_vring *vring_rsc;
		phys_addr_t da;
		unsigned int num_descs, align;
		struct metal_io_region *io;
		void *va;
		size_t size;
		int ret;
		uint32_t off;
		struct irq_info *irq_info;

		vring_rsc = &vdev_rsc->vring[i];
		notifyid = vring_rsc->notifyid;
		da = vring_rsc->da;
		dev_dbg(priv->dev, "vring%d da=%llx\n", notifyid, da);
		num_descs = vring_rsc->num;
		align = vring_rsc->align;
		size = vring_size(num_descs, align);

		off = da - (priv->host_shm_phys & 0xffffffff);
		va = priv->shm_base + off;
		ret = rproc_virtio_init_vring(priv->vdev, i, notifyid, va, io,
					      num_descs, align);
		if (ret)
			goto err_free_vdev;

		BUG_ON(notifyid >= priv->num_queues);
		irq_info = &priv->irq_info[notifyid];
		irq_info->vring_info = &priv->vdev->vrings_info[i];
	}

	rpmsg_ret = rpmsg_init_vdev(&priv->rvdev, priv->vdev,
				    rproc_remote_ns_bind_cb, &priv->shm_io,
				    NULL);
	if (rpmsg_ret != RPMSG_SUCCESS) {
		dev_err(priv->dev, "failed to init rpmsg device: %d\n",
			rpmsg_ret);
		ret = -EINVAL;
		goto err_free_vdev;
	}

	if (rpmsg_backend && rpmsg_backend->ops &&
	    rpmsg_backend->ops->on_create) {
		rpmsg_ret = rpmsg_backend->ops->on_create(&priv->rvdev.rdev,
							  rpmsg_backend->priv);
		if (rpmsg_ret) {
			ret = -EINVAL;
			goto err_free_vdev;
		}
	}

	return 0;

err_free_vdev:
	rproc_virtio_remove_vdev(priv->vdev);
	return ret;
}

// TODO: only one vdev is assumed
static void rproc_vdev_init(struct rproc_remote_priv *priv)
{
	priv->host_shm_phys =
		readl_relaxed(priv->reg_base + RPROC_REG_SHM_BASE_LOW);
	priv->host_shm_phys |=
		(u64)readl_relaxed(priv->reg_base + RPROC_REG_SHM_BASE_HIGH)
		<< 32;

	int ret =
		create_rpmsg_vdev(priv, /*notifyid=*/0, &priv->rsc_table->vdev);
	if (ret < 0) {
		dev_err(priv->dev, "failed to create rmpsg vdev %d\n", ret);
	} else {
		atomic_set(&priv->rvdev_inited, true);
	}
}

// TODO: only one vdev is assumed
static void rproc_vdev_destroy(struct rproc_remote_priv *priv)
{
	int notifyid;

	if (!atomic_read(&priv->rvdev_inited))
		return;

	priv->rsc_table->vdev.status = 0;
	atomic_set(&priv->rvdev_inited, false);

	for (notifyid = 0; notifyid < priv->num_queues; notifyid++) {
		struct irq_info *irq_info = &priv->irq_info[notifyid];
		irq_info->vring_info = NULL;
	}

	dev_info(priv->dev, "destroy rpmsg\n");
	rpmsg_deinit_vdev(&priv->rvdev);

	dev_info(priv->dev, "destroy vdev\n");
	rproc_virtio_remove_vdev(priv->vdev);

	priv->vdev = NULL;
}

static irqreturn_t rproc_ctrl_irq_handler(int irq, void *data)
{
	struct rproc_remote_priv *priv = (struct rproc_remote_priv *)data;

	u32 state = readl_relaxed(priv->reg_base + RPROC_REG_STATE);
	if (state == STATE_READY)
		rproc_vdev_init(priv);
	else
		rproc_vdev_destroy(priv);
	return IRQ_HANDLED;
}

static int rproc_remote_probe(struct platform_device *pdev)
{
	struct resource *mem;
	struct device *dev = &pdev->dev;
	struct rproc_remote_priv *priv;
	int ret;
	void *__iomem reg_base;
	void *shm_base;
	size_t shm_size;
	int i, irq_count, remote_irq_count, virq;

	priv = kmalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

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

	shm_size = resource_size(mem);
	shm_base = devm_memremap(dev, mem->start, shm_size, MEMREMAP_WC);
	if (!shm_base) {
		ret = -EINVAL;
		goto err_unmap_reg;
	}

	priv->reg_base = reg_base;
	priv->shm_base = shm_base;
	priv->shm_size = shm_size;
	priv->rsc_table = (struct rpmsg_resource_table *)priv->shm_base;
	priv->dev = &pdev->dev;
	priv->shm_io.paddr_to_vaddr = rproc_paddr_to_vaddr;
	priv->shm_io.vaddr_to_paddr = rproc_vaddr_to_paddr;
	atomic_set(&priv->rvdev_inited, false);

	platform_set_drvdata(pdev, priv);

	irq_count = platform_irq_count(pdev);
	ret = of_property_read_u32(dev->of_node, "remote_irq_count",
				   &remote_irq_count);
	BUG_ON(ret != 0);

	if (remote_irq_count) {
		dev_info(dev, "notify using physical interrupt\n");
		priv->notify_with_phys_irq = true;
		BUG_ON(remote_irq_count != irq_count - 1);
	}

	virq = platform_get_irq(pdev, 0);
	ret = devm_request_threaded_irq(&pdev->dev, virq, NULL,
					rproc_ctrl_irq_handler, IRQF_ONESHOT,
					dev_name(&pdev->dev), priv);
	BUG_ON(ret < 0);

	priv->num_queues = irq_count - 1;
	priv->irq_info =
		kzalloc(irq_count * sizeof(struct irq_info), GFP_KERNEL);
	if (!priv->irq_info)
		goto err_unmap_reg;

	for (i = 0; i < priv->num_queues; i++) {
		struct irq_info *irq_info = &priv->irq_info[i];

		virq = platform_get_irq(pdev, i + 1);
		BUG_ON(virq < 0);

		irq_info->local_virq = virq;
		if (priv->notify_with_phys_irq) {
			int hwirq;
			ret = of_property_read_u32_index(
				dev->of_node, "remote_irqs", i, &hwirq);
			BUG_ON(ret < 0);
			irq_info->remote_hwirq = hwirq;
		}

		ret = devm_request_threaded_irq(priv->dev, irq_info->local_virq,
						NULL, rproc_notify_irq_handler,
						IRQF_ONESHOT,
						dev_name(priv->dev), irq_info);
		BUG_ON(ret < 0);
	}

	memcpy(priv->shm_base, &rpmsg_rsc_table, sizeof(rpmsg_rsc_table));

	return 0;

err_unmap_reg:
	devm_iounmap(dev, reg_base);
err_free_priv:
	kfree(priv);
	return ret;
}

static int rproc_remote_remove(struct platform_device *pdev)
{
	return 0;
}

static const struct of_device_id rproc_remote_of_match[] = {
	{
		.compatible = "grt,rproc-remote",
	},
	{},
};

static struct platform_driver nebula_rproc_remote = {
	.probe = rproc_remote_probe,
	.remove = rproc_remote_remove,
	.driver	= {
		.name = "nebula-rproc-remote",
		.owner = THIS_MODULE,
		.of_match_table = rproc_remote_of_match,
	},
};

static int __init nebula_rproc_remote_init(void)
{
	return platform_driver_register(&nebula_rproc_remote);
}

module_init(nebula_rproc_remote_init);
MODULE_LICENSE("Dual BSD/GPL");
