// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2024 GoldenRiver Inc.
// Copyright (c) 2024 MediaTek Inc.

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
#include <linux/mutex.h>
#include <linux/delay.h>
#include <linux/completion.h>
#include <linux/spinlock.h>

#include <linux/arm-smccc.h>
#include <linux/nebula/hvcall.h>

#include "rpmsg_virtio.h"
#include "nebula_rproc_remote.h"

enum {
	RPROC_REG_SET_READY = 0x0,
	RPROC_REG_CLEAR_READY = 0x4,
	RPROC_REG_SHM_BASE_LOW = 0x8,
	RPROC_REG_SHM_BASE_HIGH = 0xc,
	RPROC_REG_STATE = 0x10,
	RPROC_REG_KICK = 0x14,
	RPROC_REG_PEER_VMID = 0x18,
	RPROC_REG_PEER_ONLINE = 0x1c,
};

enum {
	STATE_NOT_READY,
	STATE_READY,
};

enum {
	IDLE,
	CREATING_VDEV,
	VDEV_CREATED,
	DESTROYING_VDEV,
};

char *state_string[] = {
	__stringify(IDLE),
	__stringify(CREATING_VDEV),
	__stringify(VDEV_CREATED),
	__stringify(DESTROYING_VDEV),
};

#define MAX_VIRTIO_DEVICES 20
#define ALL_HOSTS -2

struct rproc_resource_table {
	u32 ver;
	u32 num;
	u32 reserved[2];
	u32 offset[MAX_VIRTIO_DEVICES];
} __packed;

static void signal_irq(uint16_t irq)
{
	struct arm_smccc_res res;
	unsigned long r7 = SMC_HYP_SECURE_ID << 16;
	arm_smccc_smc(SMC_FC_NBL_VHM_REQ, 0, irq, 0, 0, 0, 0, r7, &res);
}

struct irq_info {
	int local_virq;
	int remote_hwirq;
	struct virtio_vring_info *vring_info;
};

struct virtio_device_info {
	struct virtio_device *dev;
	struct nebula_rproc_vdev_ops *ops;
	void *user_priv;
};

struct rproc_remote_priv {
	void *__iomem reg_base;
	void *shm_base;
	size_t shm_size;
	phys_addr_t host_shm_phys;
	struct metal_io_region shm_io;

	struct device *dev;
	int num_queues;
	struct irq_info *irq_info;
	bool notify_with_phys_irq;

	struct mutex rsc_table_mutex;
	struct virtio_device_info vdevs[MAX_VIRTIO_DEVICES];
	void *rsc_table;
	size_t rsc_table_offset;
	size_t num_vdevs;

	struct task_struct *thread;
	struct completion compl;
	bool need_release;

	int state;
	bool ready;
	spinlock_t state_lock;
	struct dentry *dbgfs;
	bool auto_restart;

	struct list_head node;
	bool force_offline;
};

static void set_state(struct rproc_remote_priv *priv, int state)
{
	unsigned long flags;
	int prev_state;

	spin_lock_irqsave(&priv->state_lock, flags);
	prev_state = priv->state;
	priv->state = state;
	spin_unlock_irqrestore(&priv->state_lock, flags);

	dev_info(priv->dev, "%s -> %s\n",
		 state_string[prev_state], state_string[state]);
}

static int get_host(struct rproc_remote_priv *priv)
{
	if (!priv)
		return -EINVAL;

	return readl_relaxed(priv->reg_base + RPROC_REG_PEER_VMID);
}

static int get_state(struct rproc_remote_priv *priv)
{
	unsigned long flags;
	int state;

	spin_lock_irqsave(&priv->state_lock, flags);
	state = priv->state;
	spin_unlock_irqrestore(&priv->state_lock, flags);

	return state;
}

static LIST_HEAD(rproc_devices);
static DEFINE_MUTEX(rproc_devices_lock);

int nebula_rproc_register_device_for_host(
	const void *rsc, size_t rsc_size,
	struct nebula_rproc_vdev_ops *vdev_ops, int vmid, void *user_priv)
{
	struct rproc_remote_priv *priv;
	struct rproc_resource_table *rsc_table;
	int vdev_idx, host_vmid;

	if (!vdev_ops)
		return -EINVAL;

	mutex_lock(&rproc_devices_lock);

	if (list_empty(&rproc_devices)) {
		mutex_unlock(&rproc_devices_lock);
		return -ENODEV;
	}

	list_for_each_entry(priv, &rproc_devices, node) {
		mutex_lock(&priv->rsc_table_mutex);

		host_vmid = get_host(priv);
		if(vmid != ALL_HOSTS && host_vmid != vmid){
			mutex_unlock(&priv->rsc_table_mutex);
			continue;
		}

		vdev_idx = priv->num_vdevs;
		if (vdev_idx < 0 || vdev_idx >= MAX_VIRTIO_DEVICES) {
			mutex_unlock(&priv->rsc_table_mutex);
			mutex_unlock(&rproc_devices_lock);
			return -EINVAL;
		}

		pr_debug("register vdev%d, rsc_offset %lx, rsc_size %lx\n",
			 vdev_idx, priv->rsc_table_offset, rsc_size);
		rsc_table = priv->rsc_table;
		rsc_table->offset[vdev_idx] = priv->rsc_table_offset;
		priv->vdevs[vdev_idx].ops = vdev_ops;
		priv->vdevs[vdev_idx].user_priv = user_priv;

		BUG_ON(priv->rsc_table_offset + rsc_size >= PAGE_SIZE);
		memcpy(priv->rsc_table + priv->rsc_table_offset, rsc, rsc_size);

		priv->num_vdevs++;
		priv->rsc_table_offset += rsc_size;
		rsc_table->num = priv->num_vdevs;

		mutex_unlock(&priv->rsc_table_mutex);
	}

	mutex_unlock(&rproc_devices_lock);
	return 0;
}
EXPORT_SYMBOL(nebula_rproc_register_device_for_host);

int nebula_rproc_register_device(const void *rsc, size_t rsc_size,
	struct nebula_rproc_vdev_ops *vdev_ops, void *user_priv)
{
	int ret;

	ret = nebula_rproc_register_device_for_host(rsc, rsc_size, vdev_ops,
				ALL_HOSTS, user_priv);
	if (ret) {
		pr_err("failed to register devices for host(%d)\n", ret);
		return ret;
	}

	return 0;

}
EXPORT_SYMBOL(nebula_rproc_register_device);

static inline bool is_shm_paddr(struct rproc_remote_priv *priv, phys_addr_t phys) {
	return phys > priv->host_shm_phys;
}

static inline bool is_shm_vaddr(struct rproc_remote_priv *priv, void *vaddr) {
	u64 start = (u64)priv->shm_base;
	u64 end = (u64)(priv->shm_base + priv->shm_size);
	u64 target = (u64)vaddr;
	return (target > start) && (target < end);
}

static void *rproc_paddr_to_vaddr(struct virtqueue *vq, phys_addr_t phys)
{
	struct remoteproc_virtio *rpvdev =
		container_of(vq->vq_dev, struct remoteproc_virtio, vdev);
	struct rproc_remote_priv *priv = rpvdev->priv;
	void *virt;

	if (is_shm_paddr(priv, phys)) {
		u32 off = phys - priv->host_shm_phys;
		virt = priv->shm_base + off;
	} else {
		virt = phys_to_virt(phys);
	}

	pr_debug("paddr_to_vaddr: phys: %llx, virt: %px\n", phys, virt);
	return virt;
}

static phys_addr_t rproc_vaddr_to_paddr(struct virtqueue *vq, void *vaddr)
{
	struct remoteproc_virtio *rpvdev =
		container_of(vq->vq_dev, struct remoteproc_virtio, vdev);
	struct rproc_remote_priv *priv = rpvdev->priv;
	phys_addr_t phys;

	if (is_shm_vaddr(priv, vaddr)) {
		u32 off = (vaddr - priv->shm_base);
		phys = priv->host_shm_phys + off;
	} else {
		phys = virt_to_phys(vaddr);
	}

	pr_debug("vaddr_to_paddr: phys: %llx, virt: %px\n", phys, vaddr);
	return phys;
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

	BUG_ON(info->vring_info == NULL || info->vring_info->vq == NULL);
	virtqueue_notification(info->vring_info->vq);

	return IRQ_HANDLED;
}

static void dump_rsc_table(struct device *dev, void *table)
{
	struct rproc_resource_table *rsc_table = table;
	int i;

	dev_dbg(dev, "dump_rsc_table\n");
	dev_dbg(dev, "ver=%d\n", rsc_table->ver);
	dev_dbg(dev, "num=%d\n", rsc_table->num);

	for (i = 0; i < rsc_table->num; i++) {
		struct fw_rsc_vdev *vdev_desc;
		u32 offset = rsc_table->offset[i];

		vdev_desc = table + offset;
		dev_dbg(dev, "vdev%d, offset=%x\n", i, rsc_table->offset[i]);
		dev_dbg(dev, "vdev%d, type=%x", i, vdev_desc->type);
		dev_dbg(dev, "vdev%d, num_vrings=%d", i, vdev_desc->num_of_vrings);
	}
}

static void rproc_vdev_destroy_single(struct rproc_remote_priv *priv, int vdev_idx)
{
	struct virtio_device_info *vdev = &priv->vdevs[vdev_idx];
	struct remoteproc_virtio *rpvdev;
	struct rproc_resource_table *rsc_table = priv->rsc_table;
	struct fw_rsc_vdev *rsc = priv->rsc_table + rsc_table->offset[vdev_idx];
	int i;

	// reset virtio device
	rsc->status = 0;

	if (!vdev->dev)
		return;

	rpvdev = container_of(vdev->dev, struct remoteproc_virtio, vdev);
	for (i = 0; i < vdev->dev->vrings_num; i++) {
		struct irq_info *irq_info;
		int notifyid = vdev->dev->vrings_info[i].notifyid;

		irq_info = &priv->irq_info[notifyid];
		if (irq_info->vring_info) {
			irq_set_affinity_hint(irq_info->local_virq, NULL);
			devm_free_irq(priv->dev, irq_info->local_virq,
				      irq_info);
			irq_info->vring_info = NULL;
		}
	}

	BUG_ON(vdev->ops->on_destroy == NULL);
	vdev->ops->on_destroy(vdev->dev);

	dev_dbg(priv->dev, "destroy vdev%d\n", vdev_idx);
	rproc_virtio_remove_vdev(vdev->dev);

	vdev->dev = NULL;
}

static bool vdev_wait_remote_ready(struct virtio_device *vdev)
{
	uint8_t status;
	struct remoteproc_virtio *rpvdev;
	struct rproc_remote_priv *priv;
	int ret, retry = 0;

	rpvdev = container_of(vdev, struct remoteproc_virtio, vdev);
	priv = rpvdev->priv;

	while (1) {
		if (priv->need_release) {
			pr_info("virtio-%d is not alive!!!!! just quit\n",
				vdev->id.device);
			return false;
		}

		ret = virtio_get_status(vdev, &status);
		if (ret) {
			pr_info("virtio-%d: can't get status\n",
				vdev->id.device);
			return false;
		}
		if (status & VIRTIO_CONFIG_STATUS_DRIVER_OK)
			return true;
		msleep(100);
		retry++;
		if (retry == 50) {
			pr_info("virtio-%d still waiting for remote ready\n",
				vdev->id.device);
			retry = 0;
		}
	}
}

static int create_rproc_vdev(struct rproc_remote_priv *priv)
{
	int ret, host_vmid;
	unsigned int num_vrings, i, vdev_idx;
	struct fw_rsc_vdev *vdev_rsc;
	struct virtio_device *vdev;
	struct rproc_resource_table *rsc_table = priv->rsc_table;
	struct nebula_rproc_vdev_ops *vdev_ops;
	cpumask_t mask;

	// bind rproc irq to vcpu4
	cpumask_clear(&mask);
	cpumask_set_cpu(4, &mask);

	priv->need_release = false;

	dump_rsc_table(priv->dev, priv->rsc_table);

	for (vdev_idx = 0; vdev_idx < rsc_table->num; vdev_idx++) {
		dev_dbg(priv->dev, "rproc vdev%d start init\n", vdev_idx);
		vdev_ops = priv->vdevs[vdev_idx].ops;
		vdev_rsc = priv->rsc_table + rsc_table->offset[vdev_idx];
		BUG_ON(vdev_rsc->type != RSC_VDEV);

		vdev = rproc_virtio_create_vdev(VIRTIO_DEV_DEVICE, vdev_idx,
						(void *)vdev_rsc,
						/*rsc_io=*/NULL, priv,
						rproc_vdev_notify,
						vdev_ops->on_reset);
		if (!vdev) {
			dev_info(priv->dev, "failed to create virtio vdev");
			ret = -ENOMEM;
			goto err_free_vdev;
		}

		ret = vdev_wait_remote_ready(vdev);
		if (!ret) {
			ret = -ENODEV;
			rproc_virtio_remove_vdev(vdev);
			goto err_free_vdev;
		}

		/* The dfeatures has been updated after remote driver is ready,
		 * we should apply it to local vdev->features */
		vdev->features = vdev_rsc->dfeatures;

		/* set the notification id for vrings */
		num_vrings = vdev_rsc->num_of_vrings;
		for (i = 0; i < num_vrings; i++) {
			const struct fw_rsc_vdev_vring *vring_rsc;
			phys_addr_t da;
			unsigned int num_descs, align;
			struct metal_io_region *io = NULL;
			void *va;
			size_t size;
			uint32_t off;
			struct irq_info *irq_info;
			int notifyid;

			vring_rsc = &vdev_rsc->vring[i];
			notifyid = vring_rsc->notifyid;
			da = vring_rsc->da;
			dev_dbg(priv->dev, "vdev%d vring%d da=%llx\n", vdev_idx,
				notifyid, da);
			num_descs = vring_rsc->num;
			align = vring_rsc->align;
			size = vring_size(num_descs, align);

			off = da - (priv->host_shm_phys & 0xffffffff);
			va = priv->shm_base + off;
			ret = rproc_virtio_init_vring(vdev, i, notifyid, va, io,
						      num_descs, align);
			if (ret) {
				dev_err(priv->dev, "vdev%d: failed to init vring, ret=%d\n",
					vdev_idx, ret);
				rproc_virtio_remove_vdev(vdev);
				goto err_free_vdev;
			}

			BUG_ON(notifyid >= priv->num_queues);
			irq_info = &priv->irq_info[notifyid];
			irq_info->vring_info = &vdev->vrings_info[i];
		}

		dev_info(priv->dev, "creating vdev%d (id:%d)\n", vdev_idx,
			 vdev->id.device);
		host_vmid = get_host(priv);
		BUG_ON(vdev_ops->on_create == NULL);
		ret = vdev_ops->on_create(vdev, &priv->shm_io, host_vmid,
					priv->vdevs[vdev_idx].user_priv);


		if (ret) {
			dev_info(priv->dev,
				"failed to create rproc vdev%d, ret=%d\n",
				vdev_idx, ret);
			rproc_virtio_remove_vdev(vdev);
			continue;
		}

		dev_info(priv->dev, "created vdev%d (id:%d)\n", vdev_idx,
			 vdev->id.device);
		priv->vdevs[vdev_idx].dev = vdev;

		// bind rproc irq to vcpu4
		cpumask_clear(&mask);
		cpumask_set_cpu(4, &mask);

		/* The virtqueue should be created in vdev's on_create() callback, and
		 * we should request irq only after virtqueue is created. */
		for (i = 0; i < num_vrings; i++) {
			int notifyid = vdev_rsc->vring[i].notifyid;
			struct irq_info *irq_info = &priv->irq_info[notifyid];
			ret = devm_request_threaded_irq(priv->dev, irq_info->local_virq,
							NULL, rproc_notify_irq_handler,
							IRQF_ONESHOT,
							dev_name(priv->dev), irq_info);
			if (ret) {
				dev_err(priv->dev, "vdev%d: failed to request irq, ret=%d\n",
					vdev_idx, ret);
				irq_info->vring_info = NULL;
				goto err_free_vdev;
			}
			irq_set_affinity_hint(irq_info->local_virq, &mask);
		}
		dev_dbg(priv->dev, "rproc vdev%d init done\n", vdev_idx);
	}
	return 0;

err_free_vdev:
	for (i = 0; i <= vdev_idx; i++) {
		rproc_vdev_destroy_single(priv, i);
	}

	return ret;
}

static void rproc_vdev_destroy(struct rproc_remote_priv *priv)
{
	int i, j;

	dev_info(priv->dev, "rproc vdev destroy start\n");

	for (i = 0; i < priv->num_vdevs; i++) {
		struct virtio_device_info *vdev = &priv->vdevs[i];
		struct remoteproc_virtio *rpvdev;
		struct rproc_resource_table *rsc_table = priv->rsc_table;
		struct fw_rsc_vdev *rsc =
			priv->rsc_table + rsc_table->offset[i];

		// reset virtio device
		rsc->status = 0;

		dev_info(priv->dev, "destroying vdev%d\n", i);
		if (!vdev->dev) {
			dev_info(priv->dev,
				 "vdev%d is not created, skipped\n", i);
			continue;
		}

		rpvdev =
			container_of(vdev->dev, struct remoteproc_virtio, vdev);

		for (j = 0; j < vdev->dev->vrings_num; j++) {
			struct irq_info *irq_info;
			int notifyid = vdev->dev->vrings_info[j].notifyid;

			irq_info = &priv->irq_info[notifyid];
			if (irq_info->vring_info) {
				irq_set_affinity_hint(irq_info->local_virq,
						      NULL);
				devm_free_irq(priv->dev, irq_info->local_virq,
					      irq_info);
				irq_info->vring_info = NULL;
			}
		}

		BUG_ON(vdev->ops->on_destroy == NULL);
		vdev->ops->on_destroy(vdev->dev);

		dev_info(priv->dev, "destroyed vdev%d\n", i);
		rproc_virtio_remove_vdev(vdev->dev);

		vdev->dev = NULL;
	}
	dev_info(priv->dev, "rproc vdev destroy done\n");
}

static irqreturn_t rproc_ctrl_irq_handler(int irq, void *data)
{
	struct rproc_remote_priv *priv = (struct rproc_remote_priv *)data;
	u32 peer_online = readl_relaxed(priv->reg_base + RPROC_REG_PEER_ONLINE);

	if (!peer_online)
		priv->need_release = true;
	complete(&priv->compl);
	return IRQ_HANDLED;
}

static void get_host_shm_base_addr(struct rproc_remote_priv *priv) {
	priv->host_shm_phys =
		readl_relaxed(priv->reg_base + RPROC_REG_SHM_BASE_LOW);
	priv->host_shm_phys |=
		(u64)readl_relaxed(priv->reg_base + RPROC_REG_SHM_BASE_HIGH)
		<< 32;
}

static int handle_idle(struct rproc_remote_priv *priv)
{
	u32 peer_online = readl_relaxed(priv->reg_base + RPROC_REG_PEER_ONLINE);

	if (peer_online && priv->ready) {
		get_host_shm_base_addr(priv);

		writel_relaxed(0, priv->reg_base + RPROC_REG_SET_READY);
		complete(&priv->compl);
		return CREATING_VDEV;
	}

	return IDLE;
}

static int handle_creating_vdev(struct rproc_remote_priv *priv)
{
	int ret = create_rproc_vdev(priv);

	if (ret == 0) {
		return VDEV_CREATED;
	} else {
		return IDLE;
	}
}

static int handle_vdev_created(struct rproc_remote_priv *priv)
{
	u32 peer_online = readl_relaxed(priv->reg_base + RPROC_REG_PEER_ONLINE);

	if (priv->force_offline)
		peer_online = false;

	if (!peer_online || !priv->ready) {
		writel_relaxed(0, priv->reg_base + RPROC_REG_CLEAR_READY);
		complete(&priv->compl);
		return DESTROYING_VDEV;
	}

	return VDEV_CREATED;
}

static int handle_destroying_vdev(struct rproc_remote_priv *priv)
{
	rproc_vdev_destroy(priv);
	return IDLE;
}

static int create_vdev(void *args)
{
	struct rproc_remote_priv *priv = (struct rproc_remote_priv *)args;
	int state, next_state;

	while (!kthread_should_stop()) {
		wait_for_completion_interruptible(&priv->compl);

		state = get_state(priv);
		switch (state) {
		case IDLE:
			next_state = handle_idle(priv);
			break;
		case CREATING_VDEV:
			next_state = handle_creating_vdev(priv);
			break;
		case VDEV_CREATED:
			next_state = handle_vdev_created(priv);
			break;
		case DESTROYING_VDEV:
			next_state = handle_destroying_vdev(priv);
			break;
		default:
			BUG();
		}

		set_state(priv, next_state);
	}
	return 0;
}

static ssize_t ready_show(struct device *dev, struct device_attribute *attr,
			  char *buf)
{
	struct rproc_remote_priv *priv = dev_get_drvdata(dev);
	return sprintf(buf, "%u\n", priv->ready);
}
static ssize_t ready_store(struct device *dev, struct device_attribute *attr,
			   const char *buf, size_t size)
{
	struct rproc_remote_priv *priv = dev_get_drvdata(dev);
	bool ready;
	int ret;

	ret = strtobool(buf, &ready);
	if (ret < 0)
		return ret;

	priv->ready = ready;
	complete(&priv->compl);
	return ret == 0 ? size : ret;
}
static DEVICE_ATTR_RW(ready);

static ssize_t state_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct rproc_remote_priv *priv = dev_get_drvdata(dev);
	return sprintf(buf, "%s\n", state_string[get_state(priv)]);
}
static DEVICE_ATTR_RO(state);

static ssize_t peer_vmid_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct rproc_remote_priv *priv = dev_get_drvdata(dev);
	return sprintf(buf, "%d\n", readl_relaxed(priv->reg_base + RPROC_REG_PEER_VMID));
}
static DEVICE_ATTR_RO(peer_vmid);

static ssize_t peer_online_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct rproc_remote_priv *priv = dev_get_drvdata(dev);
	return sprintf(buf, "%d\n", readl_relaxed(priv->reg_base + RPROC_REG_PEER_ONLINE));
}
static DEVICE_ATTR_RO(peer_online);

static ssize_t resource_table_show(struct device *dev,
				   struct device_attribute *attr, char *buf)
{
	struct rproc_remote_priv *priv = dev_get_drvdata(dev);
	int len, i, j;
	struct rproc_resource_table *rsc_table = priv->shm_base;

	len = snprintf(buf, PAGE_SIZE, "ver=0x%x, num=%u\n", rsc_table->ver,
		      rsc_table->num);
	if ((len >= PAGE_SIZE) || (len < 0))
		return -ENOSPC;
	for (i = 0; i < rsc_table->num; i++) {
		struct fw_rsc_vdev *vdev =
			(void *)rsc_table + rsc_table->offset[i];

		len += snprintf(
			buf + len, PAGE_SIZE - len,
			" id=0x%x, features=0x%x, status=0x%x, num_vrings=%d\n",
			vdev->id, vdev->gfeatures, vdev->status,
			vdev->num_of_vrings);
		if (len >= PAGE_SIZE)
			return -ENOSPC;

		for (j = 0; j < vdev->num_of_vrings; j++) {
			struct fw_rsc_vdev_vring *vring = &vdev->vring[j];

			len += snprintf(buf + len, PAGE_SIZE - len,
					"  vring%d, notifyid=%d, num=%d\n", j,
					vring->notifyid, vring->num);
			if (len >= PAGE_SIZE)
				return -ENOSPC;
		}
	}

	return len;
}
static DEVICE_ATTR_RO(resource_table);

static ssize_t force_offline_store(struct device *dev, struct device_attribute *attr,
			     const char *buf, size_t size)
{
	struct rproc_remote_priv *priv = dev_get_drvdata(dev);
	int ret = 0;
	bool force_offline;

	ret = strtobool(buf, &force_offline);
	if (ret < 0)
		return ret;

	priv->force_offline = force_offline;
	complete(&priv->compl);
	return ret == 0 ? size : ret;
}
static DEVICE_ATTR_WO(force_offline);

static struct attribute *rproc_dev_attrs[] = {
	&dev_attr_ready.attr,
	&dev_attr_state.attr,
	&dev_attr_peer_vmid.attr,
	&dev_attr_peer_online.attr,
	&dev_attr_resource_table.attr,
	&dev_attr_force_offline.attr,
	NULL,
};

static struct attribute_group rproc_dev_group = {
	.attrs = rproc_dev_attrs,
};

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
	struct rproc_resource_table *rsc_table;
	cpumask_t mask;

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
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
	shm_base = devm_memremap(dev, mem->start, shm_size, MEMREMAP_WB);
	if (!shm_base) {
		ret = -EINVAL;
		goto err_unmap_reg;
	}
	dev_info(dev, "shared memory @ %px, size %lx\n", shm_base, shm_size);

	priv->reg_base = reg_base;
	priv->shm_base = shm_base;
	priv->shm_size = shm_size;
	priv->rsc_table = priv->shm_base;
	priv->dev = &pdev->dev;
	priv->shm_io.paddr_to_vaddr = rproc_paddr_to_vaddr;
	priv->shm_io.vaddr_to_paddr = rproc_vaddr_to_paddr;
	mutex_init(&priv->rsc_table_mutex);

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

	// bind rproc irq to vcpu4
	cpumask_clear(&mask);
	cpumask_set_cpu(4, &mask);

	init_completion(&priv->compl);

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
	}

	rsc_table = priv->shm_base;
	rsc_table->ver = 1;
	priv->rsc_table_offset = sizeof(struct rproc_resource_table);
	INIT_LIST_HEAD(&priv->node);

	priv->state = IDLE;
	spin_lock_init(&priv->state_lock);

	ret = sysfs_create_group(&dev->kobj, &rproc_dev_group);
	WARN_ON(ret != 0);

	priv->thread = kthread_run(create_vdev, priv, "rproc_vdev_create");
	if (IS_ERR(priv->thread)) {
		dev_err(priv->dev, "ERROR: failed to start rproc_vdev_create\n");
		ret = PTR_ERR(priv->thread);
		goto err_unmap_reg;
	}

	mutex_lock(&rproc_devices_lock);
	list_add(&priv->node, &rproc_devices);
	mutex_unlock(&rproc_devices_lock);

	return 0;

err_unmap_reg:
	devm_iounmap(dev, reg_base);
err_free_priv:
	kfree(priv);
	return ret;
}

static const struct of_device_id rproc_remote_of_match[] = {
	{
		.compatible = "grt,rproc-remote",
	},
	{},
};

static struct platform_driver nebula_rproc_remote = {
	.probe = rproc_remote_probe,
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
