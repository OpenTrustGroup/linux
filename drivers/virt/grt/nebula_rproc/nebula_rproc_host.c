
// SPDX-License-Identifier: GPL-2.0-only
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
#include <uapi/linux/sched/types.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/completion.h>
#include <linux/random.h>
#include <linux/delay.h>
#include <linux/mm.h>
#include <linux/gfp.h>
#include <linux/version.h>

#if defined(CONFIG_DEBUG_KMEMLEAK)
#include <linux/kmemleak.h>
#endif

irqreturn_t rproc_vq_interrupt(struct rproc *rproc, int vq_id);

enum {
	RPROC_REG_SET_READY = 0x0,
	RPROC_REG_CLEAR_READY = 0x4,
	RPROC_REG_STATE = 0x8,
	RPROC_REG_KICK = 0xc,
	RPROC_REG_PEER_VMID = 0x10,
	RPROC_REG_PEER_ONLINE = 0x14,
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

#define NUM_STRESS_THREADS 15
#define RSC_TAB_SIZE 0x1000
#define NBL_RPROC_MAGIC 0x6E626C5F72656d6fULL

struct irq_info {
	int local_virq;
	int remote_hwirq;
	struct rproc *rproc;
	int notifyid;
	struct completion done;
	spinlock_t spinlock;
	struct mutex mutex;
	unsigned long irqflag;
	bool use_threaded_irq;
	bool dev_ready;
};

static inline void lock_irq_info(struct irq_info *info) {
	if (!info->use_threaded_irq) {
		spin_lock_irqsave(&info->spinlock, info->irqflag);
	} else {
		mutex_lock(&info->mutex);
	}
}

static inline void unlock_irq_info(struct irq_info *info) {
	if (!info->use_threaded_irq) {
		spin_unlock_irqrestore(&info->spinlock, info->irqflag);
	} else {
		mutex_unlock(&info->mutex);
	}
}

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
	struct task_struct **tasks;
	bool notify_with_phys_irq;
#if defined(CONFIG_ZONE_DEVICE)
	struct dev_pagemap pgmap;
#endif

	struct device *dev;
	struct list_head node;
	bool attached;
	bool irq_requested;

	struct task_struct *stress_threads[NUM_STRESS_THREADS];
};

LIST_HEAD(rproc_devices);
DEFINE_MUTEX(rproc_devices_lock);

struct device *nebula_rproc_get_alloc_device(struct virtio_device *vdev) {
	struct rproc_host_priv *priv;
	struct device *alloc_dev = NULL;

	mutex_lock(&rproc_devices_lock);

	list_for_each_entry(priv, &rproc_devices, node) {
		if (priv->dev == vdev->dev.parent->parent->parent) {
			alloc_dev = vdev->dev.parent;
			break;
		}
	}

	mutex_unlock(&rproc_devices_lock);

	return alloc_dev;
}
EXPORT_SYMBOL(nebula_rproc_get_alloc_device);

static int rproc_notify_thread(void *data) {
	struct irq_info *info = data;
	while (1) {
		wait_for_completion(&info->done);
		if (kthread_should_stop())
			break;

		lock_irq_info(info);
		if (!info->dev_ready) {
			dev_info(&info->rproc->dev,
				 "got virq%d while device is not ready\n",
				 info->local_virq);
			unlock_irq_info(info);
			continue;
		}

		if (rproc_vq_interrupt(info->rproc, info->notifyid) == IRQ_NONE)
			dev_dbg(&info->rproc->dev, "no message found in vq%d\n",
				info->notifyid);
		unlock_irq_info(info);
	}
	return 0;
}

static irqreturn_t rproc_notify_thread_waker(int irq, void *data)
{
	struct irq_info *info = data;

	complete(&info->done);
	return IRQ_HANDLED;
}

static irqreturn_t rproc_notify_irq_handler(int irq, void *data)
{
	struct irq_info *info = data;

	lock_irq_info(info);
	if (!info->dev_ready) {
		dev_info(&info->rproc->dev,
			 "got virq%d while device is not ready\n",
			 info->local_virq);
		unlock_irq_info(info);
		return IRQ_HANDLED;
	}

	if (rproc_vq_interrupt(info->rproc, info->notifyid) == IRQ_NONE)
		dev_dbg(&info->rproc->dev, "no message found in vq%d\n",
			info->notifyid);

	unlock_irq_info(info);
	return IRQ_HANDLED;
}

static irqreturn_t rproc_ctrl_irq_handler(int irq, void *data)
{
	struct rproc_host_priv *priv = (struct rproc_host_priv *)data;

	queue_work(priv->workq, &priv->attach_work);
	return IRQ_HANDLED;
}

static void change_irq_state(struct rproc *rproc, bool ready) {
	struct rproc_vdev *rvdev;
	struct rproc_host_priv *priv = rproc->priv;
	void *rsc_table = priv->shm_base;

	list_for_each_entry(rvdev, &rproc->rvdevs, node) {
		struct fw_rsc_vdev *rsc_vdev = rsc_table + rvdev->rsc_offset;
		int i;

		for (i = 0; i < rsc_vdev->num_of_vrings; i++) {
			int notifyid = rvdev->vring[i].notifyid;
			struct irq_info *irq_info = &priv->irq_info[notifyid];
			lock_irq_info(irq_info);
			irq_info->dev_ready = ready;
			unlock_irq_info(irq_info);
		}
	}
}

static void nebula_rproc_init_irq(struct rproc *rproc)
{
	struct rproc_vdev *rvdev;
	struct rproc_host_priv *priv = rproc->priv;
	void *rsc_table = priv->shm_base;
	struct platform_device *pdev =
		container_of(priv->dev, struct platform_device, dev);
	cpumask_t mask;

	// bind rproc irq to vcpu3
	cpumask_clear(&mask);
	cpumask_set_cpu(3, &mask);

	list_for_each_entry(rvdev, &rproc->rvdevs, node) {
		struct fw_rsc_vdev *rsc_vdev = rsc_table + rvdev->rsc_offset;
		int i, ret;
		bool use_threaded_irq = rsc_vdev->id == VIRTIO_ID_RPMSG;

		for (i = 0; i < rsc_vdev->num_of_vrings; i++) {
			int notifyid = rvdev->vring[i].notifyid;
			struct irq_info *irq_info = &priv->irq_info[notifyid];
			struct sched_param param = { .sched_priority = 99 };
			int virq = platform_get_irq(pdev, notifyid + 1);
			BUG_ON(virq < 0);

			spin_lock_init(&irq_info->spinlock);
			mutex_init(&irq_info->mutex);
			irq_info->use_threaded_irq = use_threaded_irq;
			irq_info->dev_ready = true;
			irq_info->local_virq = virq;
			irq_info->notifyid = notifyid;
			irq_info->rproc = rproc;
			if (priv->notify_with_phys_irq) {
				int hwirq;
				ret = of_property_read_u32_index(
					priv->dev->of_node, "remote_irqs",
					notifyid, &hwirq);
				BUG_ON(ret < 0);
				irq_info->remote_hwirq = hwirq;
			}

			if (use_threaded_irq) {
				init_completion(&irq_info->done);
				priv->tasks[notifyid] = kthread_create(
					rproc_notify_thread, irq_info,
					"rproc_rt-%d", notifyid);
				sched_setscheduler_nocheck(
					priv->tasks[notifyid], SCHED_FIFO,
					&param);
				set_cpus_allowed_ptr(priv->tasks[notifyid],
						     &mask);
				wake_up_process(priv->tasks[notifyid]);

				ret = devm_request_threaded_irq(
					&pdev->dev, virq,
					rproc_notify_thread_waker, NULL,
					IRQF_ONESHOT, dev_name(&pdev->dev),
					irq_info);
			} else {
				ret = devm_request_irq(&pdev->dev, virq,
						       rproc_notify_irq_handler,
						       IRQF_SHARED,
						       dev_name(&pdev->dev),
						       irq_info);
			}
			BUG_ON(ret < 0);
			irq_set_affinity_hint(virq, &mask);
		}
	}
}

static int nebula_rproc_attach(struct rproc *rproc)
{
	struct rproc_host_priv *priv = rproc->priv;

	if (priv->irq_requested) {
		change_irq_state(rproc, true);
		return 0;
	}

	nebula_rproc_init_irq(rproc);
	priv->irq_requested = true;
	return 0;
}

static int nebula_rproc_detach(struct rproc *rproc)
{
	change_irq_state(rproc, false);
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
	int ret;
	u32 state, peer_online;

	peer_online = readl_relaxed(priv->reg_base + RPROC_REG_PEER_ONLINE);
	if (!peer_online) {
		dev_info(&priv->rproc->dev, "peer is not online\n");
		if (priv->attached) {
			rproc_detach(priv->rproc);
			priv->attached = false;
		}
		return;
	}

	state = readl_relaxed(priv->reg_base + RPROC_REG_STATE);
	if (state == STATE_READY) {
		if (priv->attached) {
			dev_warn(
				&priv->rproc->dev,
				"got READY interrupt while already attached?\n");
			return;
		}

		ret = rproc_boot(priv->rproc);
		if (ret != 0) {
			dev_err(&priv->rproc->dev,
				"failed to attach nebula_rproc: ret=%d", ret);
		} else {
			priv->attached = true;
		}
	} else {
		if (priv->attached) {
			rproc_detach(priv->rproc);
			priv->attached = false;
		}
	}
}

static struct rproc_host_priv *to_priv(struct device *dev)
{
	struct rproc_host_priv *priv = dev_get_drvdata(dev);

	// request may comes from our grandchild
	if (priv->magic != NBL_RPROC_MAGIC) {
		dev = dev->parent->parent;
		priv = dev_get_drvdata(dev);
	}

	BUG_ON(priv->magic != NBL_RPROC_MAGIC);
	return priv;
}

#if defined(CONFIG_ZONE_DEVICE)

#if (KERNEL_VERSION(6, 6, 0) > LINUX_VERSION_CODE)
static void prep_compound_page(struct page *page, unsigned int order)
{
	int i;
	int nr_pages = 1 << order;

	set_compound_order(page, order);
	__SetPageHead(page);
	for (i = 1; i < nr_pages; i++) {
		struct page *p = page + i;
		set_page_count(p, 0);
		set_compound_head(p, page);
	}
}

static void destroy_compound_page(struct rproc_host_priv *priv,
				  struct page *page, unsigned int order)
{
	int i;
	int nr_pages = 1 << order;

	for (i = 1; i < nr_pages; i++)
	{
		struct page *p = page + i;

		p->pgmap = &priv->pgmap;
		set_page_count(p, 0);
	}

	set_compound_order(page, 0);
	set_page_count(page, 0);
	__ClearPageHead(page);
}
#else
/*
 * This will have no effect, other than possibly generating a warning, if the
 * caller passes in a non-large folio.
 */
static inline void folio_set_order(struct folio *folio, unsigned int order)
{
	if (WARN_ON_ONCE(!order || !folio_test_large(folio)))
		return;

	folio->_flags_1 = (folio->_flags_1 & ~0xffUL) | order;
#ifdef CONFIG_64BIT
	folio->_folio_nr_pages = 1U << order;
#endif
}

/*
 * Turn a non-refcounted page (->_refcount == 0) into refcounted with
 * a count of one.
 */
static inline void set_page_refcounted(struct page *page)
{
	VM_BUG_ON_PAGE(PageTail(page), page);
	VM_BUG_ON_PAGE(page_ref_count(page), page);
	set_page_count(page, 1);
}

/* used to demote non-gigantic_huge pages as well */
static void __destroy_compound_gigantic_folio(struct rproc_host_priv *priv,
					struct folio *folio, unsigned int order, bool demote)
{
	int i;
	int nr_pages = 1 << order;
	struct page *p;

	atomic_set(&folio->_entire_mapcount, 0);
	atomic_set(&folio->_nr_pages_mapped, 0);
	atomic_set(&folio->_pincount, 0);

	if (nr_pages > folio_nr_pages(folio)) {
		dev_err(&priv->rproc->dev, "nr_pages > folio_nr_pages(folio)\n");
	}

	for (i = 1; i < nr_pages; i++) {
		p = folio_page(folio, i);
		p->flags &= ~PAGE_FLAGS_CHECK_AT_FREE;
		p->mapping = NULL;
		if (!demote)
			set_page_refcounted(p);
		p->pgmap = &priv->pgmap;
		set_page_count(p, 0);
	}
	__folio_clear_head(folio);
	set_page_count(folio_page(folio, 0), 0);
}

static bool __prep_compound_gigantic_folio(struct folio *folio,
					unsigned int order, bool demote)
{
	int i, j;
	int nr_pages = 1 << order;
	struct page *p;

	__folio_clear_reserved(folio);
	for (i = 0; i < nr_pages; i++) {
		p = folio_page(folio, i);
		if (i != 0)
			set_page_count(p, 0);
		else
			set_page_count(p, 1);
		/*
		 * For gigantic hugepages allocated through bootmem at
		 * boot, it's safer to be consistent with the not-gigantic
		 * hugepages and clear the PG_reserved bit from all tail pages
		 * too.  Otherwise drivers using get_user_pages() to access tail
		 * pages may get the reference counting wrong if they see
		 * PG_reserved set on a tail page (despite the head page not
		 * having PG_reserved set).  Enforcing this consistency between
		 * head and tail pages allows drivers to optimize away a check
		 * on the head page when they need know if put_page() is needed
		 * after get_user_pages().
		 */
		if (i != 0)	/* head page cleared above */
			__ClearPageReserved(p);
		/*
		 * Subtle and very unlikely
		 *
		 * Gigantic 'page allocators' such as memblock or cma will
		 * return a set of pages with each page ref counted.  We need
		 * to turn this set of pages into a compound page with tail
		 * page ref counts set to zero.  Code such as speculative page
		 * cache adding could take a ref on a 'to be' tail page.
		 * We need to respect any increased ref count, and only set
		 * the ref count to zero if count is currently 1.  If count
		 * is not 1, we return an error.  An error return indicates
		 * the set of pages can not be converted to a gigantic page.
		 * The caller who allocated the pages should then discard the
		 * pages using the appropriate free interface.
		 *
		 * In the case of demote, the ref count will be zero.
		 */
		if (!demote) {
			if (!page_ref_freeze(p, 1)) {
				pr_warn("HugeTLB page can not be used due to unexpected inflated ref count\n");
				goto out_error;
			}
		} else {
			VM_BUG_ON_PAGE(page_count(p), p);
		}
		if (i != 0)
			set_compound_head(p, &folio->page);
	}
	__folio_set_head(folio);
	/* we rely on prep_new_hugetlb_folio to set the destructor */
	folio_set_order(folio, order);
	atomic_set(&folio->_entire_mapcount, -1);
	atomic_set(&folio->_nr_pages_mapped, 0);
	atomic_set(&folio->_pincount, 0);
	return true;

out_error:
	/* undo page modifications made above */
	for (j = 0; j < i; j++) {
		p = folio_page(folio, j);
		if (j != 0)
			clear_compound_head(p);
		set_page_refcounted(p);
	}
	/* need to clear PG_reserved on remaining tail pages  */
	for (; j < nr_pages; j++) {
		p = folio_page(folio, j);
		__ClearPageReserved(p);
	}
	return false;
}
#endif
#endif

static void *rproc_alloc_coherent(struct device *dev, size_t size,
				  dma_addr_t *dma_addr, gfp_t flag,
				  unsigned long attrs)
{
	void *ptr;
	struct rproc_host_priv *priv = to_priv(dev);
#if defined(CONFIG_ZONE_DEVICE)
	int order = get_order(size);

	size = 1 << (PAGE_SHIFT + order);
#endif
	ptr = gen_pool_dma_alloc(priv->dma_buf_pool, size, dma_addr);
	dev_dbg(dev,
		"rproc_alloc_coherent: addr=%px, size=%lx, dma_addr=%llx, attrs=%lx\n",
		ptr, size, *dma_addr, attrs);
	if (ptr == NULL) {
		dev_err(dev, "failed to allocate memory from shm pool\n");
		return ptr;
	}

#if defined(CONFIG_DEBUG_KMEMLEAK)
	kmemleak_alloc(ptr, size, 1, flag);
#endif

#if defined(CONFIG_ZONE_DEVICE)
#if (KERNEL_VERSION(6, 6, 0) > LINUX_VERSION_CODE)
	if (order)
		prep_compound_page(virt_to_page(ptr), order);
	set_page_count(virt_to_page(ptr), 1);
#else
	if (order)
		__prep_compound_gigantic_folio(virt_to_folio(ptr), order, true);
#endif
#endif
	return ptr;
}

static void rproc_free_coherent(struct device *dev, size_t size, void *vaddr,
				dma_addr_t dma_addr, unsigned long attrs)
{
	struct rproc_host_priv *priv = to_priv(dev);

#if defined(CONFIG_ZONE_DEVICE)
	int order = get_order(size);

	size = 1 << (PAGE_SHIFT + order);
	if (order)
#if (KERNEL_VERSION(6, 6, 0) > LINUX_VERSION_CODE)
		destroy_compound_page(priv, virt_to_page(vaddr), order);
#else
		__destroy_compound_gigantic_folio(priv, page_folio(virt_to_page(vaddr)), order, true);
#endif
#endif

	dev_dbg(dev, "rproc_free_coherent: addr=%llx size=%lx, attrs=%lx\n",
		dma_addr, size, attrs);
	gen_pool_free(priv->dma_buf_pool, (unsigned long)vaddr, size);

#if defined(CONFIG_DEBUG_KMEMLEAK)
	kmemleak_free(vaddr);
#endif
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

#if defined(CONFIG_ZONE_DEVICE)
static void rproc_shm_page_free(struct page *page) {
	struct device* dev = page->pgmap->owner;
	size_t size = (1UL << (PAGE_SHIFT + compound_order(page)));
	dma_addr_t dma_handle = page_to_phys(page);

	dev_dbg(dev, "page free: dma_addr: %llx, size: %lx\n",
		page_to_phys(page), size);
	dma_free_coherent(dev, size, page_to_virt(page), dma_handle);
}

struct dev_pagemap_ops pagemap_ops = {
	.page_free = rproc_shm_page_free,
};
#endif

static ssize_t peer_vmid_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct rproc_host_priv *priv = dev_get_drvdata(dev);
	return sprintf(buf, "%d\n", readl_relaxed(priv->reg_base + RPROC_REG_PEER_VMID));
}
static DEVICE_ATTR_RO(peer_vmid);

static ssize_t peer_online_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct rproc_host_priv *priv = dev_get_drvdata(dev);
	return sprintf(buf, "%d\n", readl_relaxed(priv->reg_base + RPROC_REG_PEER_ONLINE));
}
static DEVICE_ATTR_RO(peer_online);

static ssize_t peer_ready_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct rproc_host_priv *priv = dev_get_drvdata(dev);
	return sprintf(buf, "%d\n", readl_relaxed(priv->reg_base + RPROC_REG_STATE));
}
static DEVICE_ATTR_RO(peer_ready);

static int stress_thread_fn(void *data)
{
	struct rproc_host_priv *priv = data;

	while (!kthread_should_stop()) {
		void *buf;
		dma_addr_t dma_addr;
		u32 num_pages = get_random_u32() % 16;

		buf = dma_alloc_coherent(priv->dev, PAGE_SIZE * num_pages,
					 &dma_addr, GFP_KERNEL);
		msleep(100);

		if (buf)
			put_page(virt_to_page(buf));
	}

	return 0;
}

static void start_stress(struct rproc_host_priv *priv)
{
	int i;

	for (i = 0; i < NUM_STRESS_THREADS; i++) {
		priv->stress_threads[i] =
			kthread_create(stress_thread_fn, priv, "stress_%d", i);
		if (IS_ERR(priv->stress_threads[i])) {
			pr_err("Failed to create stress thread %d\n", i);
			priv->stress_threads[i] = NULL;
			continue;
		}
		wake_up_process(priv->stress_threads[i]);
	}
}

static void stop_stress(struct rproc_host_priv *priv)
{
	int i;

	for (i = 0; i < NUM_STRESS_THREADS; i++) {
		if (priv->stress_threads[i]) {
			kthread_stop(priv->stress_threads[i]);
			priv->stress_threads[i] = NULL;
		}
	}
}

static ssize_t stress_store(struct device *dev, struct device_attribute *attr,
			    const char *buf, size_t size)
{
	struct rproc_host_priv *priv = dev_get_drvdata(dev);
	int ret = 0;
	bool start;

	ret = strtobool(buf, &start);
	if (ret < 0)
		return ret;

	if (start) {
		start_stress(priv);
	} else {
		stop_stress(priv);
	}
	return ret == 0 ? size : ret;
}
static DEVICE_ATTR_WO(stress);

static struct attribute *rproc_dev_attrs[] = {
	&dev_attr_peer_vmid.attr,
	&dev_attr_peer_online.attr,
	&dev_attr_peer_ready.attr,
	&dev_attr_stress.attr,
	NULL,
};

static struct attribute_group rproc_dev_group = {
	.attrs = rproc_dev_attrs,
};

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
	int irq_count, remote_irq_count;
#if defined(CONFIG_ZONE_DEVICE)
	struct dev_pagemap *pgmap;
#endif

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

#if defined(CONFIG_ZONE_DEVICE)
	/*
	 * It's important not using MEMORY_DEVICE_GENERIC here. For device
	 * type other than MEMORY_DEVICE_PRIVATE and MEMORY_DEVICE_COHERENT,
	 * the page refcount will be reset to 1 after it has been freed (See
	 * free_zone_device_page). We have a race here since memory allocation
	 * can happen in parallel. Before page refcount reset to 1, the freed
	 * page may have been allocated again and referenced by other user(s).
	 * This will cause doulbe-free issue.
	 */
	pgmap = &priv->pgmap;
	pgmap->type = MEMORY_DEVICE_COHERENT;
	pgmap->range.start = shm_phys;
	pgmap->range.end = shm_phys + shm_size - 1;
	pgmap->nr_range = 1;
	pgmap->ops = &pagemap_ops;
	pgmap->owner = dev;
	shm_base = devm_memremap_pages(dev, pgmap);
#else
	shm_base = devm_memremap(dev, shm_phys, shm_size, MEMREMAP_WB);
#endif
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

#if defined(CONFIG_ZONE_DEVICE)
	priv->dma_buf_pool = gen_pool_create(PAGE_SHIFT, -1);
#else
	priv->dma_buf_pool = gen_pool_create(0, -1);
#endif
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

	virq = platform_get_irq(pdev, 0);
	ret = devm_request_irq(&pdev->dev, virq, rproc_ctrl_irq_handler,
			       IRQF_SHARED, dev_name(&pdev->dev), priv);
	BUG_ON(ret < 0);

	INIT_LIST_HEAD(&priv->node);
	priv->dev = dev;
	priv->num_queues = irq_count - 1;
	priv->irq_info =
		kzalloc(irq_count * sizeof(struct irq_info), GFP_KERNEL);
	if (!priv->irq_info)
		goto err_remove_rproc;

	priv->tasks = kzalloc(priv->num_queues * sizeof(struct task_struct*),
			GFP_KERNEL);
	if (!priv->tasks)
		goto err_remove_irq_info;

	platform_set_drvdata(pdev, priv);

	ret = sysfs_create_group(&dev->kobj, &rproc_dev_group);
	WARN_ON(ret != 0);

	mutex_lock(&rproc_devices_lock);
	list_add(&priv->node, &rproc_devices);
	mutex_unlock(&rproc_devices_lock);

	queue_work(priv->workq, &priv->attach_work);
	return 0;

err_remove_irq_info:
	kfree(priv->irq_info);
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
