/*
 * Copyright 2018 GoldenRiver Technologies Co., Ltd. All rights reserved.
 * Copyright (C) 2015 Google, Inc.
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

#include <linux/version.h>
#include <linux/aio.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/poll.h>
#include <linux/idr.h>
#include <linux/completion.h>
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 10, 0)
#include <linux/sched.h>
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
#include <linux/sched/signal.h>
#endif
#include <linux/compat.h>
#include <linux/uio.h>
#include <linux/spinlock.h>
#include <linux/kthread.h>

#include <linux/virtio.h>
#include <linux/virtio_config.h>

#include <linux/nebula/trusty.h>
#include <linux/nebula/trusty_ipc.h>
#include <linux/nebula/nebula_shm.h>
#include <linux/nebula/smcall.h>

#if defined(CONFIG_NEBULA_SECCAM_ION)
#include "trusty-ion.h"
#endif

#define VIRTIO_ID_TRUSTY_IPC	13
#define MAX_DEVICES			4

#define REPLY_TIMEOUT			5000
#define TXBUF_TIMEOUT			15000

#define MAX_SRV_NAME_LEN		256
#define MAX_DEV_NAME_LEN		32

#define DEFAULT_MSG_BUF_SIZE		PAGE_SIZE
#define DEFAULT_MSG_BUF_ALIGN		PAGE_SIZE

#define TIPC_CTRL_ADDR			53
#define TIPC_ANY_ADDR			0xFFFFFFFF

#define TIPC_MIN_LOCAL_ADDR		1024
#define TIPC_MAX_LOCAL_ADDR		0x7FFFFFFF

#define MAX_MEMREF_NUM			8
#define MEMREF_ALIGN			8
#define TIPC_MIN_MEMREF_ID		2048
#define TIPC_MAX_MEMREF_ID		10000
#define MAX_MREF_SIZE			(2 * 1024 * 1024)

#define TIPC_IOC_MAGIC			'r'
#define TIPC_IOC_CONNECT		_IOW(TIPC_IOC_MAGIC, 0x80, char *)

#define TIPC_MEMREF_PERM_RO		(0x0U << 0)
#define TIPC_MEMREF_PERM_RW		(0x1U << 0)

struct tipc_send_msg_req {
	__u64 msgiov;
	__u64 shmemv;
	__u32 msgiov_cnt;
	__u32 shmemv_cnt;
};

#define TIPC_IOC_SEND_MSG		_IOW(TIPC_IOC_MAGIC, 0x81, \
					     struct tipc_send_msg_req)

#if defined(CONFIG_COMPAT)
#define TIPC_IOC_CONNECT_COMPAT		_IOW(TIPC_IOC_MAGIC, 0x80, \
					     compat_uptr_t)

#endif

#if defined(CONFIG_NEBULA_SECCAM_ION)
#define TIPC_IOC_QUERY_ION_HANDLE		_IOW(TIPC_IOC_MAGIC, 0x82, \
					     struct tipc_query_ion_handle_req)
#endif

struct tipc_virtio_dev;

struct tipc_dev_config {
	u32 msg_buf_max_size;
	u32 msg_buf_alignment;
	char dev_name[MAX_DEV_NAME_LEN];
} __packed;

struct tipc_msg_hdr {
	u32 src;
	u32 dst;
	u32 reserved;
	u16 len;
	u16 flags;
	u8 data[];
} __packed;

struct tipc_msg_mref_hdr {
	u32 id;
	u32 flags;
	u32 size;
	u32 pg_inf_cnt;
	struct ns_mem_page_info pg_inf[];
} __packed;

enum tipc_ctrl_msg_types {
	TIPC_CTRL_MSGTYPE_GO_ONLINE = 1,
	TIPC_CTRL_MSGTYPE_GO_OFFLINE,
	TIPC_CTRL_MSGTYPE_CONN_REQ,
	TIPC_CTRL_MSGTYPE_CONN_RSP,
	TIPC_CTRL_MSGTYPE_DISC_REQ,
	TIPC_CTRL_MSGTYPE_MREF_RELEASE_REQ,
#if defined(CONFIG_NEBULA_SECCAM_ION)
	TIPC_CTRL_MSGTYPE_REGISTER_ION_BUFFER,
	TIPC_CTRL_MSGTYPE_DEREGISTER_ION_BUFFER,
#endif
};

struct tipc_ctrl_msg {
	u32 type;
	u32 body_len;
	u8  body[];
} __packed;

struct tipc_conn_req_body {
	char name[MAX_SRV_NAME_LEN];
} __packed;

struct tipc_conn_rsp_body {
	u32 target;
	u32 status;
	u32 remote;
	u32 max_msg_size;
	u32 max_msg_cnt;
} __packed;

struct tipc_disc_req_body {
	u32 target;
} __packed;

struct tipc_mref_release_req_body {
	u32 id;
} __packed;

#if defined(CONFIG_NEBULA_SECCAM_ION)
struct tipc_register_ion_buffer_req_body {
	u32 handle;
	u64 phys_addr;
	u32 size;
} __packed;

struct tipc_deregister_ion_buffer_req_body {
	u32 handle;
} __packed;
#endif

struct tipc_cdev_node {
	struct cdev cdev;
	struct device *dev;
	unsigned int minor;
};

enum tipc_device_state {
	VDS_OFFLINE = 0,
	VDS_ONLINE,
	VDS_DEAD,
};

enum {
	TIPC_VQ_RX = 0,
	TIPC_VQ_TX = 1,
	TIPC_VQ_MAX = 2,
};

struct tipc_virtio_dev {
	struct kref refcount;
	struct mutex lock; /* protects access to this device */
	struct virtio_device *vdev;
	struct virtqueue *rxvq;
	struct virtqueue *txvq;
	uint msg_buf_cnt;
	uint msg_buf_max_cnt;
	size_t msg_buf_sz;
	uint free_msg_buf_cnt;
	struct list_head free_buf_list;
	struct list_head stashed_buf_list;
	wait_queue_head_t sendq;
	struct idr addr_idr;
	struct idr mref_idr;
	struct mutex mref_lock; /* protects access to mref_idr */
	enum tipc_device_state state;
	struct tipc_cdev_node cdev_node;
	char   cdev_name[MAX_DEV_NAME_LEN];
	spinlock_t vq_lock[TIPC_VQ_MAX];
	struct kthread_worker kworker;
	struct task_struct *kworker_task;
};

enum tipc_chan_state {
	TIPC_DISCONNECTED = 0,
	TIPC_CONNECTING,
	TIPC_CONNECTED,
	TIPC_STALE,
};

struct tipc_chan {
	struct mutex lock; /* protects channel state  */
	struct kref refcount;
	enum tipc_chan_state state;
	struct tipc_virtio_dev *vds;
	const struct tipc_chan_ops *ops;
	void *ops_arg;
	struct list_head mref_list;
	wait_queue_head_t mrefq;
	u32 remote;
	u32 local;
	u32 max_msg_size;
	u32 max_msg_cnt;
	char srv_name[MAX_SRV_NAME_LEN];
};

struct tipc_memref {
	struct tipc_chan *chan;
	struct list_head node;
	unsigned int pg_num;
	unsigned int pg_pinned;
	struct page *pages[];
};

struct tipc_rxbuf {
	struct tipc_virtio_dev *vds;
	struct tipc_msg_buf *mb;
	size_t len;
	struct kthread_work work;
};

static struct class *tipc_class;
static unsigned int tipc_major = CONFIG_NEBULA_VTEE_IPC_DEV_MAJOR;

static struct virtio_device *default_vdev;
static ATOMIC_NOTIFIER_HEAD(ipc_notifier);

static DEFINE_IDR(tipc_devices);
static DEFINE_MUTEX(tipc_devices_lock);

static int  _tipc_send_msg(struct tipc_chan *chan, struct iov_iter *msg_iter,
			   struct tipc_shmem *shmv, uint shmv_cnt, bool user,
			   long timeout, bool intr);

static int _match_any(int id, void *p, void *data)
{
	return id;
}

static int _match_data(int id, void *p, void *data)
{
	return (p == data);
}

static void *_alloc_shareable_mem(size_t sz, phys_addr_t *ppa, gfp_t gfp)
{
	return nbl_shm_alloc(sz, gfp);
}

static void _free_shareable_mem(size_t sz, void *va, phys_addr_t pa)
{
	nbl_shm_free(va, sz);
}

static struct tipc_msg_buf *_alloc_msg_buf(size_t sz)
{
	struct tipc_msg_buf *mb;

	/* allocate tracking structure */
	mb = kzalloc(sizeof(struct tipc_msg_buf), GFP_KERNEL);
	if (!mb)
		return NULL;

	/* allocate buffer that can be shared with secure world */
	mb->buf_va = _alloc_shareable_mem(sz, &mb->buf_pa, GFP_KERNEL);
	if (!mb->buf_va)
		goto err_alloc;

	mb->buf_sz = sz;

	return mb;

err_alloc:
	kfree(mb);
	return NULL;
}

static void _free_msg_buf(struct tipc_msg_buf *mb)
{
	_free_shareable_mem(mb->buf_sz, mb->buf_va, mb->buf_pa);
	kfree(mb);
}

static void _free_msg_buf_list(struct list_head *list)
{
	struct tipc_msg_buf *mb = NULL;

	mb = list_first_entry_or_null(list, struct tipc_msg_buf, node);
	while (mb) {
		list_del(&mb->node);
		_free_msg_buf(mb);
		mb = list_first_entry_or_null(list, struct tipc_msg_buf, node);
	}
}

static inline void mb_reset(struct tipc_msg_buf *mb)
{
	mb->wpos = 0;
	mb->rpos = 0;
}

static inline void mb_reset_read(struct tipc_msg_buf *mb)
{
	mb->rpos = 0;
}

static inline void mb_align_read(struct tipc_msg_buf *mb, uint align)
{
	(void)mb_get_data(mb, ALIGN(mb->rpos, align) - mb->rpos);
}

static inline void mb_align_write(struct tipc_msg_buf *mb, uint align)
{
	size_t cb  = ALIGN(mb->wpos, align) - mb->wpos;

	memset(mb_put_data(mb, cb), 0, cb);
}

static void _free_vds(struct kref *kref)
{
	struct tipc_virtio_dev *vds =
		container_of(kref, struct tipc_virtio_dev, refcount);
	kfree(vds);
}

static void _free_chan(struct kref *kref)
{
	struct tipc_chan *ch = container_of(kref, struct tipc_chan, refcount);

	if (ch->ops && ch->ops->handle_release)
		ch->ops->handle_release(ch->ops_arg);

	kref_put(&ch->vds->refcount, _free_vds);
	kfree(ch);
}

static struct tipc_msg_buf *vds_alloc_msg_buf(struct tipc_virtio_dev *vds)
{
	return _alloc_msg_buf(vds->msg_buf_sz);
}

static void vds_free_msg_buf(struct tipc_virtio_dev *vds,
			     struct tipc_msg_buf *mb)
{
	_free_msg_buf(mb);
}

static bool _put_txbuf_locked(struct tipc_virtio_dev *vds,
			      struct tipc_msg_buf *mb)
{
	if (mb->buf_sz > vds->msg_buf_sz) {
		_free_msg_buf(mb);

		if (list_empty(&vds->stashed_buf_list)) {
			vds->msg_buf_cnt--;
			return true;
		}

		/* take buf out of stashed list and put it on free list */
		mb = list_first_entry(&vds->stashed_buf_list,
				      struct tipc_msg_buf, node);
		list_del(&mb->node);
	}
	list_add_tail(&mb->node, &vds->free_buf_list);
	return vds->free_msg_buf_cnt++ == 0;
}

static struct tipc_msg_buf *_get_txbuf_locked(struct tipc_virtio_dev *vds,
					      size_t sz)
{
	struct tipc_msg_buf *mb;

	if (vds->state != VDS_ONLINE)
		return  ERR_PTR(-ENODEV);

	if (sz < vds->msg_buf_sz)
		sz = vds->msg_buf_sz;

	if (vds->free_msg_buf_cnt) {
		/* peek head of free list */
		mb = list_first_entry(&vds->free_buf_list,
				      struct tipc_msg_buf, node);

		if (sz > vds->msg_buf_sz) {
			struct tipc_msg_buf *newmb;

			/* allocate new one */
			newmb = _alloc_msg_buf(sz);
			if (!newmb)
				return ERR_PTR(-ENOMEM);

			/* remove from free list and put it on shashed list */
			list_del(&mb->node);
			list_add_tail(&mb->node, &vds->stashed_buf_list);

			/* return a new one to caller */
			mb = newmb;
		} else {
			/* take it out of free list */
			list_del(&mb->node);
		}
		vds->free_msg_buf_cnt--;
	} else {
		if (vds->msg_buf_cnt >= vds->msg_buf_max_cnt)
			return ERR_PTR(-EAGAIN);

		/* try to allocate it */
		mb = _alloc_msg_buf(sz);
		if (!mb)
			return ERR_PTR(-ENOMEM);

		vds->msg_buf_cnt++;
	}
	return mb;
}

static struct tipc_msg_buf *_vds_get_txbuf(struct tipc_virtio_dev *vds,
					   size_t sz)
{
	struct tipc_msg_buf *mb;

	mutex_lock(&vds->lock);
	mb = _get_txbuf_locked(vds, sz);
	mutex_unlock(&vds->lock);

	return mb;
}

static void vds_put_txbuf_locked(struct tipc_virtio_dev *vds,
				 struct tipc_msg_buf *mb)
{
	if (_put_txbuf_locked(vds, mb))
		wake_up(&vds->sendq);
}

static void vds_put_txbuf(struct tipc_virtio_dev *vds, struct tipc_msg_buf *mb)
{
	mutex_lock(&vds->lock);
	vds_put_txbuf_locked(vds, mb);
	mutex_unlock(&vds->lock);
}

static struct tipc_msg_buf *vds_get_txbuf(struct tipc_virtio_dev *vds,
					  size_t sz, long timeout,
					  bool intr)
{
	struct tipc_msg_buf *mb;
	unsigned int mode = intr ? TASK_INTERRUPTIBLE : TASK_UNINTERRUPTIBLE;

	mb = _vds_get_txbuf(vds, sz);

	if ((PTR_ERR(mb) == -EAGAIN) && timeout) {
		DEFINE_WAIT_FUNC(wait, woken_wake_function);

		timeout = msecs_to_jiffies(timeout);
		add_wait_queue(&vds->sendq, &wait);
		for (;;) {
			timeout = wait_woken(&wait, mode, timeout);
			if (!timeout) {
				mb = ERR_PTR(-ETIMEDOUT);
				break;
			}

			if (intr) {
				if (signal_pending(current)) {
					mb = ERR_PTR(-ERESTARTSYS);
					break;
				}
			}

			mb = _vds_get_txbuf(vds, sz);
			if (PTR_ERR(mb) != -EAGAIN)
				break;
		}
		remove_wait_queue(&vds->sendq, &wait);
	}

	if (IS_ERR(mb))
		return mb;

	BUG_ON(!mb);

	/* reset and reserve space for message header */
	mb_reset(mb);
	mb_put_data(mb, sizeof(struct tipc_msg_hdr));

	return mb;
}

static int vds_queue_txbuf(struct tipc_virtio_dev *vds,
			   struct tipc_msg_buf *mb)
{
	int err;
	struct scatterlist sg;
	bool need_notify = false;

	mutex_lock(&vds->lock);
	if (vds->state == VDS_ONLINE) {
		sg_init_one(&sg, mb->buf_va, mb->wpos);
		err = virtqueue_add_outbuf(vds->txvq, &sg, 1, mb, GFP_KERNEL);
		need_notify = virtqueue_kick_prepare(vds->txvq);
	} else {
		err = -ENODEV;
	}
	mutex_unlock(&vds->lock);

	if (need_notify)
		virtqueue_notify(vds->txvq);

	return err;
}

static int vds_add_channel(struct tipc_virtio_dev *vds,
			   struct tipc_chan *chan)
{
	int ret;

	mutex_lock(&vds->lock);
	if (vds->state == VDS_ONLINE) {
		ret = idr_alloc_cyclic(&vds->addr_idr, chan,
				       TIPC_MIN_LOCAL_ADDR,
				       TIPC_MAX_LOCAL_ADDR,
				       GFP_KERNEL);
		if (ret > 0) {
			chan->local = ret;
			kref_get(&chan->refcount);
			ret = 0;
		}
	} else {
		ret = -EINVAL;
	}
	mutex_unlock(&vds->lock);

	return ret;
}

static void vds_del_channel(struct tipc_virtio_dev *vds,
			    struct tipc_chan *chan)
{
	mutex_lock(&vds->lock);
	if (chan->local) {
		idr_remove(&vds->addr_idr, chan->local);
		chan->local = 0;
		chan->remote = 0;
		kref_put(&chan->refcount, _free_chan);
	}
	mutex_unlock(&vds->lock);
}

static struct tipc_chan *vds_lookup_channel(struct tipc_virtio_dev *vds,
					    u32 addr)
{
	int id;
	struct tipc_chan *chan = NULL;

	mutex_lock(&vds->lock);
	if (addr == TIPC_ANY_ADDR) {
		id = idr_for_each(&vds->addr_idr, _match_any, NULL);
		if (id > 0)
			chan = idr_find(&vds->addr_idr, id);
	} else {
		chan = idr_find(&vds->addr_idr, addr);
	}
	if (chan)
		kref_get(&chan->refcount);
	mutex_unlock(&vds->lock);

	return chan;
}

static struct tipc_chan *vds_create_channel(struct tipc_virtio_dev *vds,
					    const struct tipc_chan_ops *ops,
					    void *ops_arg)
{
	int ret;
	struct tipc_chan *chan = NULL;

	if (!vds)
		return ERR_PTR(-ENOENT);

	if (!ops)
		return ERR_PTR(-EINVAL);

	chan = kzalloc(sizeof(*chan), GFP_KERNEL);
	if (!chan)
		return ERR_PTR(-ENOMEM);

	kref_get(&vds->refcount);
	chan->vds = vds;
	chan->ops = ops;
	chan->ops_arg = ops_arg;
	mutex_init(&chan->lock);
	kref_init(&chan->refcount);
	chan->state = TIPC_DISCONNECTED;
	INIT_LIST_HEAD(&chan->mref_list);
	init_waitqueue_head(&chan->mrefq);

	ret = vds_add_channel(vds, chan);
	if (ret) {
		kfree(chan);
		kref_put(&vds->refcount, _free_vds);
		return ERR_PTR(ret);
	}

	return chan;
}

static void fill_msg_hdr(struct tipc_msg_buf *mb, u32 src, u32 dst)
{
	struct tipc_msg_hdr *hdr = mb_get_data(mb, sizeof(*hdr));

	hdr->src = src;
	hdr->dst = dst;
	hdr->len = mb_avail_data(mb);
	hdr->flags = 0;
	hdr->reserved = 0;
}

/*****************************************************************************/

static int memref_preflight_check(struct tipc_shmem *shm)
{
	unsigned int i;

	if (!shm)
		return -EINVAL;

	for (i = 0; i < 3; i++) {
		/* size has to be page aligned */
		if (shm->size[i] & (PAGE_SIZE - 1))
			return -EINVAL;

		/* base address also has not be page aligned */
		if ((uintptr_t)shm->base[i] & (PAGE_SIZE - 1))
			return -EINVAL;
	}
	return 0;
}

static int memrefv_preflight_check(struct tipc_shmem *shmv, uint shmv_cnt)
{
	int ret;
	unsigned int i;

	if (shmv_cnt > MAX_MEMREF_NUM)
		return -EINVAL;

	for (i = 0; i < shmv_cnt; i++) {
		ret = memref_preflight_check(&shmv[i]);
		if (ret < 0)
			return ret;
	}
	return 0;
}

static unsigned int memref_count_pages(struct tipc_shmem *shm)
{
	unsigned int i;
	unsigned int pg_cnt = 0;

	for (i = 0; i < 3; i++)
		pg_cnt += shm->size[i] / PAGE_SIZE;
	return pg_cnt;
}

static void memref_release_pages(struct tipc_memref *mref, bool dirty)
{
	unsigned int i;

	/* if pages are pinned, unpin them */
	for (i = 0; i < mref->pg_pinned; i++) {
		if (dirty)
			set_page_dirty(mref->pages[i]);
		put_page(mref->pages[i]);
	}
	mref->pg_pinned = 0;
}

static void vds_memref_release_locked(struct tipc_virtio_dev *vds, u32 id)
{
	struct tipc_memref *mref = idr_find(&vds->mref_idr, id);

	if (WARN_ON(!mref)) {
		pr_err("%s: memref (id=%u) is not found\n", __func__, id);
		return;
	}

	pr_debug("%s: id=%u %u\n", __func__, id, mref->pg_pinned);

	/* remove id */
	idr_remove(&mref->chan->vds->mref_idr, id);

	/* dec refs */
	list_del(&mref->node);
	if (list_empty(&mref->chan->mref_list))
		wake_up_all(&mref->chan->mrefq);

	kref_put(&mref->chan->refcount, _free_chan);
	mref->chan = NULL;

	memref_release_pages(mref, true);
	kfree(mref);
}

static void vds_memref_release(struct tipc_virtio_dev *vds,
			       const u32 *ids, uint ids_num)
{
	uint i;
	mutex_lock(&vds->mref_lock);
	for (i = 0; i < ids_num; i++)
		vds_memref_release_locked(vds, ids[i]);
	mutex_unlock(&vds->mref_lock);
}

static int build_user_page_info(struct ns_mem_page_info *ns,
				struct vm_area_struct *vmas[],
				struct page *pages[], unsigned long pg_num)
{
	int ret;
	unsigned long i;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0)
	pgprot_t pgprot;
#endif

	for (i = 0; i < pg_num; i++, ns++) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
		ret = nebula_encode_page_info(ns, pages[i], PAGE_SHARED, true);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0)
		pgprot = vmas[i]->vm_page_prot;
		ret = nebula_encode_page_info(ns, pages[i], pgprot);
#else
		struct vm_area_struct *vma = vmas[i];
		ret = nebula_encode_page_info(ns, pages[i], vma->vm_page_prot,
					      !!(vma->vm_flags & VM_WRITE));
#endif
		if (ret < 0)
			return ret;
	}
	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0)
static int append_kernel_memref(struct tipc_msg_mref_hdr *hdr,
				struct tipc_memref *mref,
				struct tipc_shmem *shm)
{
	/* Implement me */
	return -EINVAL;
}
#else
static int build_kern_page_info(struct ns_mem_page_info *ns, struct page *pages,
				unsigned long pg_num)
{
	int ret;

	while (pg_num--) {
		ret = nebula_encode_page_info(ns++, pages++, PAGE_KERNEL, true);
		if (ret < 0)
			return ret;
	}
	return 0;
}

static int append_kernel_memref(struct tipc_msg_mref_hdr *hdr,
		struct tipc_memref *mref,
		struct tipc_shmem *shm)
{
	unsigned int i;
	unsigned int pg_num;
	unsigned long pg_phys;

	if (WARN_ON(shm->base[0]))
		return -EINVAL;
	if (WARN_ON(shm->size[0]))
		return -EINVAL;
	if (WARN_ON(!shm->size[1]))
		return -EINVAL;
	if (WARN_ON(!shm->base[1]))
		return -EINVAL;
	if (WARN_ON(shm->base[2]))
		return -EINVAL;
	if (WARN_ON(shm->size[2]))
		return -EINVAL;

	if (WARN_ON(!PAGE_ALIGNED(shm->base[1])))
		return -EINVAL;
	if (WARN_ON(!PAGE_ALIGNED(shm->size[1])))
		return -EINVAL;


	/* in shm case, we're interested in region 1 */
	pg_phys = virt_to_phys((void *)shm->base[1]);
	pg_num = shm->size[1] / PAGE_SIZE;

	/* fill pages of memref */
	for (i = 0; i < pg_num; i++, pg_phys += PAGE_SIZE) {
		mref->pages[i] = phys_to_page(pg_phys);
		if (WARN_ON(!mref->pages[i])) {
			return -EINVAL;
		}
	}

	hdr->id = 0; /* will be filled later */
	hdr->flags = shm->flags & TIPC_MEMREF_PERM_RW;
	hdr->size = shm->size[1];
	hdr->pg_inf_cnt = shm->size[1] / PAGE_SIZE;
	return build_kern_page_info(hdr->pg_inf, mref->pages[0], pg_num);
}
#endif

static int append_user_memref(struct tipc_msg_mref_hdr *hdr,
			      struct tipc_memref *mref,
			      struct tipc_shmem *shm)
{
	long ret;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0)
	bool write;
#else
	unsigned int gup_flags;
#endif
	unsigned int i;
	unsigned int pg_num;
	unsigned long pg_start;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0)
	struct vm_area_struct **vmas;

	vmas = kcalloc(mref->pg_num, sizeof(*vmas), GFP_KERNEL);
	if (!vmas)
		return -ENOMEM;
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0)
	write = !!(shm->flags & TIPC_MEMREF_PERM_RW);
#else
	gup_flags = (shm->flags & TIPC_MEMREF_PERM_RW) ? FOLL_WRITE : 0;
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
	down_read(&current->mm->mmap_sem);
#else
	down_read(&current->mm->mmap_lock);
#endif

	/* for all 3 regions */
	for (i = 0; i < 3; i++) {
		pg_num = shm->size[i] / PAGE_SIZE;
		pg_start = (unsigned long)shm->base[i];

		if (!pg_start || !pg_num)
			continue;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
		ret = get_user_pages(pg_start, pg_num, gup_flags, mref->pages + mref->pg_pinned);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0)
		ret = get_user_pages(current, current->mm,
				     pg_start, pg_num, write, 0,
				     mref->pages + mref->pg_pinned,
				     vmas + mref->pg_pinned);
#else
		ret = get_user_pages(pg_start, pg_num, gup_flags,
				     mref->pages + mref->pg_pinned,
				     vmas + mref->pg_pinned);
#endif

		if (ret < 0)
			goto err_pinned;

		mref->pg_pinned += (unsigned int)ret;

		if ((unsigned int)ret != pg_num) {
			/* partially succeeded */
			ret = -EINVAL;
			goto err_bad_cnt;
		}
	}

	hdr->id = 0; /* will be filled later */
	hdr->flags = shm->flags & TIPC_MEMREF_PERM_RW;
	hdr->size = mref->pg_pinned * PAGE_SIZE;
	hdr->pg_inf_cnt = mref->pg_pinned;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
	ret = build_user_page_info(hdr->pg_inf, NULL,
				   mref->pages, mref->pg_pinned);
#else
	ret = build_user_page_info(hdr->pg_inf, vmas,
				   mref->pages, mref->pg_pinned);
#endif
err_bad_cnt:
err_pinned:
	if (ret < 0)
		memref_release_pages(mref, false);
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
	up_read(&current->mm->mmap_sem);
#else
	up_read(&current->mm->mmap_lock);
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0)
	kfree(vmas);
#endif
	return ret;
}

static int append_memrefs(struct tipc_chan *chan, struct tipc_msg_buf *mb,
			  u32 *mr_ids, struct tipc_shmem *shmv, uint shmv_cnt,
			  bool user)
{
	uint i;
	int ret;
	size_t sz;
	unsigned int pg_num;
	struct tipc_memref *mref;
	struct tipc_msg_mref_hdr *hdr;
	struct tipc_virtio_dev *vds = chan->vds;

	/* align output buffer */
	mb_align_write(mb, MEMREF_ALIGN);

	/* for each memrefs */
	mutex_lock(&chan->vds->mref_lock);
	for (i = 0; i < shmv_cnt; i++) {
		/* create memref tracking obj */
		pg_num = memref_count_pages(&shmv[i]);
		if (!pg_num) {
			ret  = -EINVAL;
			goto err_create;
		}

		mref = kzalloc(sizeof(*mref) + pg_num * sizeof(struct page *),
			       GFP_KERNEL);
		if (!mref) {
			ret = -ENOMEM;
			goto err_create;
		}
		mref->pg_num = pg_num;

		/* reserve space for memref object */
		sz = sizeof(struct tipc_msg_mref_hdr) +
		     sizeof(struct ns_mem_page_info) * pg_num;
		hdr = mb_put_data(mb, sz);

		if (user)
			ret = append_user_memref(hdr, mref, &shmv[i]);
		else
			ret = append_kernel_memref(hdr, mref, &shmv[i]);
		if (ret)
			goto err_append;

		/* create memref id */
		ret = idr_alloc(&vds->mref_idr, mref,
				TIPC_MIN_MEMREF_ID, TIPC_MAX_MEMREF_ID,
				GFP_KERNEL);

		if (ret < 0)
			goto err_idr_alloc;

		hdr->id = ret;
		mr_ids[i] = ret;

		/* attach memref to chan object */
		kref_get(&chan->refcount);
		mref->chan = chan;
		list_add_tail(&mref->node, &chan->mref_list);
	}
	mutex_unlock(&chan->vds->mref_lock);

	return 0;

err_idr_alloc:
err_append:
	memref_release_pages(mref, false);
	kfree(mref);
err_create:
	while (i--)
		vds_memref_release_locked(vds, mr_ids[i]);
	mutex_unlock(&chan->vds->mref_lock);
	return ret;
}

/*****************************************************************************/

struct tipc_chan *nebula_tipc_create_channel(struct device *dev,
				      const struct tipc_chan_ops *ops,
				      void *ops_arg)
{
	struct virtio_device *vd;
	struct tipc_chan *chan;
	struct tipc_virtio_dev *vds;

	mutex_lock(&tipc_devices_lock);
	if (dev) {
		vd = container_of(dev, struct virtio_device, dev);
	} else {
		vd = default_vdev;
		if (!vd) {
			mutex_unlock(&tipc_devices_lock);
			return ERR_PTR(-ENOENT);
		}
	}
	vds = vd->priv;
	kref_get(&vds->refcount);
	mutex_unlock(&tipc_devices_lock);

	chan = vds_create_channel(vds, ops, ops_arg);
	kref_put(&vds->refcount, _free_vds);
	return chan;
}
EXPORT_SYMBOL(nebula_tipc_create_channel);

struct tipc_msg_buf *nebula_tipc_chan_get_rxbuf(struct tipc_chan *chan)
{
	return vds_alloc_msg_buf(chan->vds);
}
EXPORT_SYMBOL(nebula_tipc_chan_get_rxbuf);

void nebula_tipc_chan_put_rxbuf(struct tipc_chan *chan, struct tipc_msg_buf *mb)
{
	vds_free_msg_buf(chan->vds, mb);
}
EXPORT_SYMBOL(nebula_tipc_chan_put_rxbuf);

struct tipc_msg_buf *nebula_tipc_chan_get_txbuf_timeout(struct tipc_chan *chan,
						 long timeout)
{
	struct tipc_virtio_dev *vds = chan->vds;

	return vds_get_txbuf(vds, vds->msg_buf_sz, timeout, true);
}
EXPORT_SYMBOL(nebula_tipc_chan_get_txbuf_timeout);

void nebula_tipc_chan_put_txbuf(struct tipc_chan *chan, struct tipc_msg_buf *mb)
{
	vds_put_txbuf(chan->vds, mb);
}
EXPORT_SYMBOL(nebula_tipc_chan_put_txbuf);

int nebula_tipc_state_notifier_register(struct notifier_block *n)
{
	return atomic_notifier_chain_register(&ipc_notifier, n);
}
EXPORT_SYMBOL(nebula_tipc_state_notifier_register);

int nebula_tipc_state_notifier_unregister(struct notifier_block *n)
{
	return atomic_notifier_chain_unregister(&ipc_notifier, n);
}
EXPORT_SYMBOL(nebula_tipc_state_notifier_unregister);

static int _nebula_tipc_chan_queue_msg(struct tipc_chan *chan,
				struct tipc_msg_buf *mb,
				struct tipc_shmem *shmv, uint shmv_cnt,
				bool user)
{
	int err;
	u32 mr_ids[MAX_MEMREF_NUM];

	mutex_lock(&chan->lock);
	switch (chan->state) {
	case TIPC_CONNECTED:
		fill_msg_hdr(mb, chan->local, chan->remote);

		/* append memrefs if any */
		if (shmv_cnt) {
			err = append_memrefs(chan, mb, mr_ids,
					     shmv, shmv_cnt, user);
			if (err < 0) {
				pr_err("%s: failed to append memrefs (%d)\n",
				       __func__, err);
				break;
			}
		}

		/* queue message */
		err = vds_queue_txbuf(chan->vds, mb);
		if (err) {
			/* this should never happen */
			pr_err("%s: failed to queue tx buffer (%d)\n",
			       __func__, err);
			vds_memref_release(chan->vds, mr_ids, shmv_cnt);
		}
		break;
	case TIPC_DISCONNECTED:
	case TIPC_CONNECTING:
		err = -ENOTCONN;
		break;
	case TIPC_STALE:
		err = -ESHUTDOWN;
		break;
	default:
		err = -EBADFD;
		pr_err("%s: unexpected channel state %d\n",
		       __func__, chan->state);
	}
	mutex_unlock(&chan->lock);
	return err;
}

int nebula_tipc_chan_queue_msg(struct tipc_chan *chan, struct tipc_msg_buf *mb,
			struct tipc_shmem *shmv, uint shmv_cnt)
{
	return _nebula_tipc_chan_queue_msg(chan, mb, shmv, shmv_cnt, false);
}
EXPORT_SYMBOL(nebula_tipc_chan_queue_msg);


int nebula_tipc_chan_connect(struct tipc_chan *chan, const char *name)
{
	int err;
	struct tipc_ctrl_msg *msg;
	struct tipc_conn_req_body *body;
	struct tipc_msg_buf *txbuf;

	txbuf = nebula_tipc_chan_get_txbuf_timeout(chan, TXBUF_TIMEOUT);
	if (IS_ERR(txbuf))
		return PTR_ERR(txbuf);

	/* reserve space for connection request control message */
	msg = mb_put_data(txbuf, sizeof(*msg) + sizeof(*body));
	body = (struct tipc_conn_req_body *)msg->body;

	/* fill message */
	msg->type = TIPC_CTRL_MSGTYPE_CONN_REQ;
	msg->body_len  = sizeof(*body);

	strlcpy(body->name, name, sizeof(body->name));
	body->name[sizeof(body->name)-1] = '\0';

	mutex_lock(&chan->lock);
	switch (chan->state) {
	case TIPC_DISCONNECTED:
		/* save service name we are connecting to */
		strlcpy(chan->srv_name, body->name, sizeof(chan->srv_name));

		fill_msg_hdr(txbuf, chan->local, TIPC_CTRL_ADDR);
		err = vds_queue_txbuf(chan->vds, txbuf);
		if (err) {
			/* this should never happen */
			pr_err("%s: failed to queue tx buffer (%d)\n",
			       __func__, err);
		} else {
			chan->state = TIPC_CONNECTING;
			txbuf = NULL; /* prevents discarding buffer */
		}
		break;
	case TIPC_CONNECTED:
	case TIPC_CONNECTING:
		/* check if we are trying to connect to the same service */
		if (strcmp(chan->srv_name, body->name) == 0)
			err = 0;
		else
			if (chan->state == TIPC_CONNECTING)
				err = -EALREADY; /* in progress */
			else
				err = -EISCONN;  /* already connected */
		break;

	case TIPC_STALE:
		err = -ESHUTDOWN;
		break;
	default:
		err = -EBADFD;
		pr_err("%s: unexpected channel state %d\n",
		       __func__, chan->state);
		break;
	}
	mutex_unlock(&chan->lock);

	if (txbuf)
		nebula_tipc_chan_put_txbuf(chan, txbuf); /* discard it */

	return err;
}
EXPORT_SYMBOL(nebula_tipc_chan_connect);

static void wait_for_memrefs(struct tipc_chan *chan)
{
	DEFINE_WAIT_FUNC(wait, woken_wake_function);

	add_wait_queue(&chan->mrefq, &wait);
	for (;;) {
		mutex_lock(&chan->vds->mref_lock);
		if (list_empty(&chan->mref_list))
			break;
		mutex_unlock(&chan->vds->mref_lock);

		wait_woken(&wait, TASK_UNINTERRUPTIBLE, MAX_SCHEDULE_TIMEOUT);
	};
	mutex_unlock(&chan->vds->mref_lock);
	remove_wait_queue(&chan->mrefq, &wait);
}

int nebula_tipc_chan_shutdown(struct tipc_chan *chan)
{
	int err;
	struct tipc_ctrl_msg *msg;
	struct tipc_disc_req_body *body;
	struct tipc_msg_buf *txbuf = NULL;

	/* get tx buffer */
	txbuf = vds_get_txbuf(chan->vds, chan->vds->msg_buf_sz,
			      TXBUF_TIMEOUT, false);
	if (IS_ERR(txbuf))
		return PTR_ERR(txbuf);

	mutex_lock(&chan->lock);
	if (chan->state == TIPC_CONNECTED || chan->state == TIPC_CONNECTING) {
		/* reserve space for disconnect request control message */
		msg = mb_put_data(txbuf, sizeof(*msg) + sizeof(*body));
		body = (struct tipc_disc_req_body *)msg->body;

		msg->type = TIPC_CTRL_MSGTYPE_DISC_REQ;
		msg->body_len = sizeof(*body);
		body->target = chan->remote;

		fill_msg_hdr(txbuf, chan->local, TIPC_CTRL_ADDR);
		err = vds_queue_txbuf(chan->vds, txbuf);
		if (err) {
			/* this should never happen */
			pr_err("%s: failed to queue tx buffer (%d)\n",
			       __func__, err);
		}
	} else {
		err = -ENOTCONN;
	}
	chan->state = TIPC_STALE;
	mutex_unlock(&chan->lock);

	/* wait for all outstanding memref to be released by remote side */
	wait_for_memrefs(chan);

	if (err) {
		/* release buffer */
		nebula_tipc_chan_put_txbuf(chan, txbuf);
	}

	return err;
}
EXPORT_SYMBOL(nebula_tipc_chan_shutdown);

void nebula_tipc_chan_destroy(struct tipc_chan *chan)
{
	vds_del_channel(chan->vds, chan);
	kref_put(&chan->refcount, _free_chan);
}
EXPORT_SYMBOL(nebula_tipc_chan_destroy);

#if defined(CONFIG_NEBULA_SECCAM_ION)
static int tipc_send_ctrl_msg(enum tipc_ctrl_msg_types cmd_type, void* body, size_t body_len)
{
	int err;
	struct tipc_virtio_dev *vds;
	struct tipc_ctrl_msg *msg;
	struct tipc_msg_buf *txbuf = NULL;

	if (!default_vdev) {
		pr_err("%s: no default tipc device\n", __func__);
		return -ENOENT;
	}

	vds = default_vdev->priv;

	/* get tx buffer */
	txbuf = vds_get_txbuf(vds, vds->msg_buf_sz, TXBUF_TIMEOUT, false);
	if (IS_ERR(txbuf))
		return PTR_ERR(txbuf);

	msg = mb_put_data(txbuf, sizeof(*msg) + body_len);
	memcpy(msg->body, body, body_len);

	msg->type = cmd_type;
	msg->body_len = body_len;

	fill_msg_hdr(txbuf, TIPC_CTRL_ADDR, TIPC_CTRL_ADDR);
	err = vds_queue_txbuf(vds, txbuf);
	WARN_ON(err);

	return err;
}

int nebula_tipc_register_ion_buffer(uint32_t handle, uint64_t phys_addr, uint32_t size)
{
	struct tipc_register_ion_buffer_req_body body;

	body.handle = handle;
	body.phys_addr = phys_addr;
	body.size = size;
	return tipc_send_ctrl_msg(TIPC_CTRL_MSGTYPE_REGISTER_ION_BUFFER, &body, sizeof(body));
}
EXPORT_SYMBOL(nebula_tipc_register_ion_buffer);

int nebula_tipc_deregister_ion_buffer(uint32_t handle)
{
	struct tipc_deregister_ion_buffer_req_body body;

	body.handle = handle;
	return tipc_send_ctrl_msg(TIPC_CTRL_MSGTYPE_DEREGISTER_ION_BUFFER, &body, sizeof(body));
}
EXPORT_SYMBOL(tipc_deregister_ion_buffer);
#endif

/***************************************************************************/
struct mref_shm {
	unsigned long vm_start;
	uintptr_t vaddr;
	phys_addr_t paddr;
	size_t size;
	struct list_head node;
};

struct tipc_dn_chan {
	int state;
	struct mutex lock; /* protects rx_msg_queue list and channel state */
	struct tipc_chan *chan;
	wait_queue_head_t readq;
	struct completion reply_comp;
	struct list_head rx_msg_queue;
	struct list_head mref_shm_list; /* used in static shm allocation */
};

static int dn_wait_for_reply(struct tipc_dn_chan *dn, int timeout)
{
	int ret;

	ret = wait_for_completion_interruptible_timeout(&dn->reply_comp,
					msecs_to_jiffies(timeout));
	if (ret < 0)
		return ret;

	mutex_lock(&dn->lock);
	if (!ret) {
		/* no reply from remote */
		dn->state = TIPC_STALE;
		ret = -ETIMEDOUT;
	} else {
		/* got reply */
		if (dn->state == TIPC_CONNECTED)
			ret = 0;
		else if (dn->state == TIPC_DISCONNECTED)
			if (!list_empty(&dn->rx_msg_queue))
				ret = 0;
			else
				ret = -ENOTCONN;
		else
			ret = -EIO;
	}
	mutex_unlock(&dn->lock);

	return ret;
}

static struct tipc_msg_buf *dn_handle_msg(void *data, struct tipc_msg_buf *rxbuf)
{
	struct tipc_dn_chan *dn = data;
	struct tipc_msg_buf *newbuf = rxbuf;

	mutex_lock(&dn->lock);
	if (dn->state == TIPC_CONNECTED) {
		/* get new buffer */
		newbuf = nebula_tipc_chan_get_rxbuf(dn->chan);
		if (newbuf) {
			/* queue an old buffer and return a new one */
			list_add_tail(&rxbuf->node, &dn->rx_msg_queue);
			wake_up_interruptible(&dn->readq);
		} else {
			/*
			 * return an old buffer effectively discarding
			 * incoming message
			 */
			pr_err("%s: discard incoming message\n", __func__);
			newbuf = rxbuf;
		}
	}
	mutex_unlock(&dn->lock);

	return newbuf;
}

static void dn_connected(struct tipc_dn_chan *dn)
{
	mutex_lock(&dn->lock);
	dn->state = TIPC_CONNECTED;

	/* complete all pending  */
	complete(&dn->reply_comp);

	mutex_unlock(&dn->lock);
}

static void dn_disconnected(struct tipc_dn_chan *dn)
{
	mutex_lock(&dn->lock);
	dn->state = TIPC_DISCONNECTED;

	/* complete all pending  */
	complete(&dn->reply_comp);

	/* wakeup all readers */
	wake_up_interruptible_all(&dn->readq);

	mutex_unlock(&dn->lock);
}

static void dn_shutdown(struct tipc_dn_chan *dn)
{
	mutex_lock(&dn->lock);

	/* set state to STALE */
	dn->state = TIPC_STALE;

	/* complete all pending  */
	complete(&dn->reply_comp);

	/* wakeup all readers */
	wake_up_interruptible_all(&dn->readq);

	mutex_unlock(&dn->lock);
}

static void dn_handle_event(void *data, int event)
{
	struct tipc_dn_chan *dn = data;

	switch (event) {
	case TIPC_CHANNEL_SHUTDOWN:
		dn_shutdown(dn);
		break;

	case TIPC_CHANNEL_DISCONNECTED:
		dn_disconnected(dn);
		break;

	case TIPC_CHANNEL_CONNECTED:
		dn_connected(dn);
		break;

	default:
		pr_err("%s: unhandled event %d\n", __func__, event);
		break;
	}
}

static void dn_handle_release(void *data)
{
	kfree(data);
}

static struct tipc_chan_ops _dn_ops = {
	.handle_msg = dn_handle_msg,
	.handle_event = dn_handle_event,
	.handle_release = dn_handle_release,
};

#define cdev_to_cdn(c) container_of((c), struct tipc_cdev_node, cdev)
#define cdn_to_vds(cdn) container_of((cdn), struct tipc_virtio_dev, cdev_node)

static struct tipc_virtio_dev *_dn_lookup_vds(struct tipc_cdev_node *cdn)
{
	int ret;
	struct tipc_virtio_dev *vds = NULL;

	mutex_lock(&tipc_devices_lock);
	ret = idr_for_each(&tipc_devices, _match_data, cdn);
	if (ret) {
		vds = cdn_to_vds(cdn);
		kref_get(&vds->refcount);
	}
	mutex_unlock(&tipc_devices_lock);
	return vds;
}

static int tipc_open(struct inode *inode, struct file *filp)
{
	int ret;
	struct tipc_virtio_dev *vds;
	struct tipc_dn_chan *dn;
	struct tipc_cdev_node *cdn = cdev_to_cdn(inode->i_cdev);

	vds = _dn_lookup_vds(cdn);
	if (!vds) {
		ret = -ENOENT;
		goto err_vds_lookup;
	}

	dn = kzalloc(sizeof(*dn), GFP_KERNEL);
	if (!dn) {
		ret = -ENOMEM;
		goto err_alloc_chan;
	}

	mutex_init(&dn->lock);
	init_waitqueue_head(&dn->readq);
	init_completion(&dn->reply_comp);
	INIT_LIST_HEAD(&dn->rx_msg_queue);
	INIT_LIST_HEAD(&dn->mref_shm_list);

	dn->state = TIPC_DISCONNECTED;

	dn->chan = vds_create_channel(vds, &_dn_ops, dn);
	if (IS_ERR(dn->chan)) {
		ret = PTR_ERR(dn->chan);
		goto err_create_chan;
	}

	filp->private_data = dn;
	kref_put(&vds->refcount, _free_vds);
	return 0;

err_create_chan:
	kfree(dn);
err_alloc_chan:
	kref_put(&vds->refcount, _free_vds);
err_vds_lookup:
	return ret;
}


static int dn_connect_ioctl(struct tipc_dn_chan *dn, char __user *usr_name)
{
	int err;
	char name[MAX_SRV_NAME_LEN];

	/* copy in service name from user space */
	err = strncpy_from_user(name, usr_name, sizeof(name));
	if (err < 0) {
		pr_err("%s: copy_from_user (%p) failed (%d)\n",
		       __func__, usr_name, err);
		return err;
	}
	name[sizeof(name)-1] = '\0';

	/* send connect request */
	err = nebula_tipc_chan_connect(dn->chan, name);
	if (err)
		return err;

	/* and wait for reply */
	return dn_wait_for_reply(dn, REPLY_TIMEOUT);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
#if !defined(CONFIG_COMPAT)
struct compat_iovec;
static int compat_import_iovec(int type,
			       const struct compat_iovec __user *uvector,
			       unsigned int nr_segs, unsigned int fast_segs,
			       struct iovec **iov, struct iov_iter *i)
{
	return -EINVAL;
}
#endif
#endif

static long tipc_send_msg_ioctl(struct file *filp, unsigned long arg,
				bool compat)
{
	ssize_t ret;
	struct iov_iter msg_iter;
	struct iovec iovstack[12];
	struct tipc_send_msg_req req;
	struct tipc_shmem shmems[MAX_MEMREF_NUM];
	struct tipc_dn_chan *dn = filp->private_data;
	struct iovec *iov = iovstack;
	long timeout = (filp->f_flags & O_NONBLOCK) ? 0 : TXBUF_TIMEOUT;
	void __user *user_req;

#ifdef CONFIG_COMPAT
	if (compat == true) {
		user_req = compat_ptr(arg);
	} else {
		user_req = (void __user *)arg;
	}
#else
	user_req = (void __user *)arg;
#endif

	/* copy in request */
	if (copy_from_user(&req, user_req, sizeof(req)))
		return -EFAULT;

	if (req.shmemv_cnt > MAX_MEMREF_NUM) {
		pr_err("%s: too many memrefs %u\n", __func__, req.shmemv_cnt);
		return -EINVAL;
	}

	/* import message iovecs */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
	if (compat == true)
		ret = compat_import_iovec(READ,
					  (void *)(uintptr_t)req.msgiov,
					  req.msgiov_cnt,
					  ARRAY_SIZE(iovstack), &iov,
					  &msg_iter);
	else
		ret = import_iovec(READ,
				   (void *)(uintptr_t)req.msgiov,
				   req.msgiov_cnt,
				   ARRAY_SIZE(iovstack), &iov,
				   &msg_iter);
#else
	ret = import_iovec(WRITE,
				(void *)(uintptr_t)req.msgiov,
				req.msgiov_cnt,
				ARRAY_SIZE(iovstack), &iov,
				&msg_iter);
#endif
	if (ret < 0)
		return ret;

	if (req.shmemv_cnt) {
		/* import memref descriptors */
		if (copy_from_user(shmems, (const void __user *)req.shmemv,
				   req.shmemv_cnt * sizeof(shmems[0]))) {
			ret = -EFAULT;
			goto err_bad_descrs;
		}
	}

	ret = _tipc_send_msg(dn->chan, &msg_iter, shmems, req.shmemv_cnt,
			     true /*user*/, timeout, true /*intr*/);

err_bad_descrs:
	kfree(iov);
	return ret;
}

static long tipc_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	long ret = 0;
	struct tipc_dn_chan *dn = filp->private_data;

	if (_IOC_TYPE(cmd) != TIPC_IOC_MAGIC)
		return -EINVAL;

	switch (cmd) {
	case TIPC_IOC_CONNECT:
		ret = dn_connect_ioctl(dn, (char __user *)arg);
		break;
	case TIPC_IOC_SEND_MSG:
		ret = tipc_send_msg_ioctl(filp, arg, false);
		break;
#if defined(CONFIG_NEBULA_SECCAM_ION)
	case TIPC_IOC_QUERY_ION_HANDLE:
		ret = tipc_query_ion_handle(arg);
		break;
#endif
	default:
		pr_warn("%s: Unhandled ioctl cmd: 0x%x\n",
			__func__, cmd);
		ret = -EINVAL;
	}
	return ret;
}

#if defined(CONFIG_COMPAT)

static long tipc_compat_ioctl(struct file *filp,
			      unsigned int cmd, unsigned long arg)
{
	int ret;
	struct tipc_dn_chan *dn = filp->private_data;
	void __user *user_req = compat_ptr(arg);

	if (_IOC_TYPE(cmd) != TIPC_IOC_MAGIC)
		return -EINVAL;

	switch (cmd) {
	case TIPC_IOC_CONNECT_COMPAT:
		ret = dn_connect_ioctl(dn, user_req);
		break;
	case TIPC_IOC_SEND_MSG:
		ret = tipc_send_msg_ioctl(filp, arg, true);
		break;
#if defined(CONFIG_NEBULA_SECCAM_ION)
	case TIPC_IOC_QUERY_ION_HANDLE:
		ret = tipc_query_ion_handle(arg);
		break;
#endif
	default:
		pr_warn("%s: Unhandled ioctl cmd: 0x%x\n",
			__func__, cmd);
		ret = -EINVAL;
	}
	return ret;
}
#endif

static inline bool _got_rx(struct tipc_dn_chan *dn)
{
	if (dn->state != TIPC_CONNECTED)
		return true;

	if (!list_empty(&dn->rx_msg_queue))
		return true;

	return false;
}

static ssize_t tipc_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	ssize_t ret;
	size_t len;
	struct tipc_msg_buf *mb;
	struct file *filp = iocb->ki_filp;
	struct tipc_dn_chan *dn = filp->private_data;

	mutex_lock(&dn->lock);

	while (list_empty(&dn->rx_msg_queue)) {
		if (dn->state != TIPC_CONNECTED) {
			if (dn->state == TIPC_CONNECTING)
				ret = -ENOTCONN;
			else if (dn->state == TIPC_DISCONNECTED)
				ret = -ENOTCONN;
			else if (dn->state == TIPC_STALE)
				ret = -ESHUTDOWN;
			else
				ret = -EBADFD;
			goto out;
		}

		mutex_unlock(&dn->lock);

		if (filp->f_flags & O_NONBLOCK)
			return -EAGAIN;

		if (wait_event_interruptible(dn->readq, _got_rx(dn)))
			return -ERESTARTSYS;

		mutex_lock(&dn->lock);
	}

	mb = list_first_entry(&dn->rx_msg_queue, struct tipc_msg_buf, node);

	len = mb_avail_data(mb);
	if (len > iov_iter_count(iter)) {
		ret = -EMSGSIZE;
		goto out;
	}

	if (copy_to_iter(mb_get_data(mb, len), len, iter) != len) {
		ret = -EFAULT;
		goto out;
	}

	ret = len;
	list_del(&mb->node);
	nebula_tipc_chan_put_rxbuf(dn->chan, mb);

out:
	mutex_unlock(&dn->lock);
	return ret;
}

static size_t aux_data_len(struct tipc_shmem *shmv, uint shmv_cnt)
{
	uint i;
	size_t len;
	unsigned int pg_num;

	len = shmv_cnt * sizeof(struct tipc_msg_mref_hdr);
	for (i = 0; i < shmv_cnt; i++) {
		pg_num = memref_count_pages(&shmv[i]);
		len += pg_num * sizeof(struct ns_mem_page_info);
	}
	return len;
}

static int _tipc_send_msg(struct tipc_chan *chan, struct iov_iter *msg_iter,
			  struct tipc_shmem *shmv, uint shmv_cnt, bool user,
			  long timeout, bool intr)
{
	int ret;
	size_t len;
	struct tipc_msg_buf *txbuf;
	size_t aux_len = 0;

	/* pre flight check message length */
	len = iov_iter_count(msg_iter);
	if (len > (chan->vds->msg_buf_sz - sizeof(struct tipc_msg_hdr)))
		return -EMSGSIZE;

	if (shmv_cnt) {
		/* do memref parameters check */
		ret = memrefv_preflight_check(shmv, shmv_cnt);
		if (ret < 0)
			return ret;

		/* calculate aux data size and add alignment */
		aux_len = aux_data_len(shmv, shmv_cnt) +
			  ALIGN(len, MEMREF_ALIGN);
	}

	/* get or allocate tx buffer */
	txbuf = vds_get_txbuf(chan->vds,
			      sizeof(struct tipc_msg_hdr) + len + aux_len,
			      timeout, intr);
	if (IS_ERR(txbuf))
		return PTR_ERR(txbuf);

	/* copy in message data */
	if (copy_from_iter(mb_put_data(txbuf, len), len, msg_iter) != len) {
		ret = -EFAULT;
		goto err_out;
	}

	/* queue message */
	ret = _nebula_tipc_chan_queue_msg(chan, txbuf, shmv, shmv_cnt, user);
	if (ret)
		goto err_out;

	return len;

err_out:
	nebula_tipc_chan_put_txbuf(chan, txbuf);
	return ret;
}

static ssize_t tipc_write_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *filp = iocb->ki_filp;
	struct tipc_dn_chan *dn = filp->private_data;
	long timeout = (filp->f_flags & O_NONBLOCK) ? 0 : TXBUF_TIMEOUT;

	return _tipc_send_msg(dn->chan, iter, NULL, 0, true, timeout, true);
}

static unsigned int tipc_poll(struct file *filp, poll_table *wait)
{
	unsigned int mask = 0;
	struct tipc_dn_chan *dn = filp->private_data;

	mutex_lock(&dn->lock);

	poll_wait(filp, &dn->readq, wait);

	/* Writes always succeed for now */
	mask |= POLLOUT | POLLWRNORM;

	if (!list_empty(&dn->rx_msg_queue))
		mask |= POLLIN | POLLRDNORM;

	if (dn->state != TIPC_CONNECTED)
		mask |= POLLERR;

	mutex_unlock(&dn->lock);
	return mask;
}

#if 0
void tipc_mref_vma_close(struct vm_area_struct *vma)
{
	struct mref_shm *mshm, *mshmtmp;
	struct tipc_dn_chan *dn = vma->vm_private_data;
	bool found = false;

	mutex_lock(&dn->lock);

	list_for_each_entry_safe(mshm, mshmtmp, &dn->mref_shm_list, node) {
		if (mshm->vm_start == vma->vm_start) {
			pr_info("%s: uva %lx sz %zx fl %lx kva %lx kpa %llx\n",
					__func__, mshm->vm_start, mshm->size, vma->vm_flags,
					mshm->vaddr, mshm->paddr);
			_free_shareable_mem(mshm->size, (void *)mshm->vaddr, mshm->paddr);
			list_del(&mshm->node);
			kfree(mshm);
			found = true;
			break;
		}
	}

	WARN_ON(unlikely(!found));

	mutex_unlock(&dn->lock);
}

static struct vm_operations_struct mref_vma_ops = {
	.close = tipc_mref_vma_close,
};

static int tipc_mref_mmap(struct file *filp, struct vm_area_struct *vma)
{
	ulong offset, flags, pfn;
	void *vaddr;
	phys_addr_t paddr;
	struct tipc_dn_chan *dn = filp->private_data;
	size_t size;
	pgprot_t prot;
	struct mref_shm *mshm;

	if (!trusty_get_link_shbuf_device(0))
		return -ENODEV;

	flags = vma->vm_flags;

	if (WARN_ON((flags & VM_EXEC) && !(filp->f_mode & FMODE_EXEC)))
		return -EINVAL;

	/* Check the mmap request is within bounds. */
	size = vma->vm_end - vma->vm_start;
	if (WARN_ON(!PAGE_ALIGNED(size)))
		return -EINVAL;
	if (size > MAX_MREF_SIZE)
		return -ENOMEM;

	offset = vma->vm_pgoff << PAGE_SHIFT;
	if (WARN_ON(offset != 0))
		return -EINVAL;

	vaddr = _alloc_shareable_mem(size, NULL, GFP_KERNEL | __GFP_ZERO);
	if (WARN_ON(!vaddr))
		return -ENOMEM;
	paddr = nbl_shm_virt_to_phys(vaddr);

	mshm = kzalloc(sizeof(struct mref_shm), GFP_KERNEL);
	if (WARN_ON(!mshm))
		return -ENOMEM;

	mshm->vm_start = vma->vm_start;
	mshm->vaddr = (uintptr_t)vaddr;
	mshm->paddr = paddr;
	mshm->size = size;
	list_add_tail(&mshm->node, &dn->mref_shm_list);

	pfn = (paddr + offset) >> PAGE_SHIFT;
	prot = vm_get_page_prot(flags);

	vma->vm_ops = &mref_vma_ops;
	vma->vm_private_data = dn;

	pr_info("%s: uva %lx sz %zx fl %lx kva %lx kpa %llx\n",
			__func__, mshm->vm_start, mshm->size, vma->vm_flags,
			mshm->vaddr, mshm->paddr);

	return remap_pfn_range(vma, vma->vm_start, pfn, size, prot);
}
#endif

static int tipc_release(struct inode *inode, struct file *filp)
{
	struct tipc_dn_chan *dn = filp->private_data;

	dn_shutdown(dn);

	/* free all pending buffers */
	_free_msg_buf_list(&dn->rx_msg_queue);

	/* shutdown channel  */
	nebula_tipc_chan_shutdown(dn->chan);

	/* and destroy it */
	nebula_tipc_chan_destroy(dn->chan);

	return 0;
}

static const struct file_operations tipc_fops = {
	.open		= tipc_open,
	.release	= tipc_release,
	.unlocked_ioctl	= tipc_ioctl,
#if defined(CONFIG_COMPAT)
	.compat_ioctl	= tipc_compat_ioctl,
#endif
	.read_iter	= tipc_read_iter,
	.write_iter	= tipc_write_iter,
	.poll		= tipc_poll,
	// .mmap		= tipc_mref_mmap,
	.owner		= THIS_MODULE,
};

/*****************************************************************************/

static void chan_trigger_event(struct tipc_chan *chan, int event)
{
	if (!event)
		return;

	chan->ops->handle_event(chan->ops_arg, event);
}

static void _cleanup_vq(struct virtqueue *vq)
{
	struct tipc_msg_buf *mb;

	while ((mb = virtqueue_detach_unused_buf(vq)) != NULL)
		_free_msg_buf(mb);
}

static int _create_cdev_node(struct device *dev,
			     struct tipc_cdev_node *cdn,
			     const char *name)
{
	int ret;
	dev_t devt;

	if (!name) {
		dev_dbg(dev, "%s: cdev name has to be provided\n",
			__func__);
		return -EINVAL;
	}

	/* allocate minor */
	ret = idr_alloc(&tipc_devices, cdn, 0, MAX_DEVICES-1, GFP_KERNEL);
	if (ret < 0) {
		dev_dbg(dev, "%s: failed (%d) to get id\n",
			__func__, ret);
		return ret;
	}

	cdn->minor = ret;
	cdev_init(&cdn->cdev, &tipc_fops);
	cdn->cdev.owner = THIS_MODULE;

	/* Add character device */
	devt = MKDEV(tipc_major, cdn->minor);
	ret = cdev_add(&cdn->cdev, devt, 1);
	if (ret) {
		dev_dbg(dev, "%s: cdev_add failed (%d)\n",
			__func__, ret);
		goto err_add_cdev;
	}

	/* Create a device node */
	cdn->dev = device_create(tipc_class, dev,
				 devt, NULL, "trusty-ipc-%s", name);
	if (IS_ERR(cdn->dev)) {
		ret = PTR_ERR(cdn->dev);
		dev_dbg(dev, "%s: device_create failed: %d\n",
			__func__, ret);
		goto err_device_create;
	}

	return 0;

err_device_create:
	cdn->dev = NULL;
	cdev_del(&cdn->cdev);
err_add_cdev:
	idr_remove(&tipc_devices, cdn->minor);
	return ret;
}

static void create_cdev_node(struct tipc_virtio_dev *vds,
			     struct tipc_cdev_node *cdn)
{
	int err;

	mutex_lock(&tipc_devices_lock);

	if (!default_vdev) {
		kref_get(&vds->refcount);
		default_vdev = vds->vdev;
	}

	if (vds->cdev_name[0] && !cdn->dev) {
		kref_get(&vds->refcount);
		err = _create_cdev_node(&vds->vdev->dev, cdn, vds->cdev_name);
		if (err) {
			dev_err(&vds->vdev->dev,
				"failed (%d) to create cdev node\n", err);
			kref_put(&vds->refcount, _free_vds);
		}
	}
	mutex_unlock(&tipc_devices_lock);
}

static void destroy_cdev_node(struct tipc_virtio_dev *vds,
			      struct tipc_cdev_node *cdn)
{
	mutex_lock(&tipc_devices_lock);
	if (cdn->dev) {
		device_destroy(tipc_class, MKDEV(tipc_major, cdn->minor));
		cdev_del(&cdn->cdev);
		idr_remove(&tipc_devices, cdn->minor);
		cdn->dev = NULL;
		kref_put(&vds->refcount, _free_vds);
	}

	if (default_vdev == vds->vdev) {
		default_vdev = NULL;
		kref_put(&vds->refcount, _free_vds);
	}

	mutex_unlock(&tipc_devices_lock);
}

static void _go_online(struct tipc_virtio_dev *vds)
{
	mutex_lock(&vds->lock);
	if (vds->state == VDS_OFFLINE)
		vds->state = VDS_ONLINE;
	mutex_unlock(&vds->lock);

	create_cdev_node(vds, &vds->cdev_node);

	dev_info(&vds->vdev->dev, "is online\n");

	local_irq_disable();
	if (vds->vdev == default_vdev) {
		atomic_notifier_call_chain(&ipc_notifier, TIPC_STATE_ONLINE, NULL);
	}
	local_irq_enable();
}

static void _go_offline(struct tipc_virtio_dev *vds)
{
	struct tipc_chan *chan;

	/* change state to OFFLINE */
	mutex_lock(&vds->lock);
	if (vds->state != VDS_ONLINE) {
		mutex_unlock(&vds->lock);
		return;
	}
	vds->state = VDS_OFFLINE;
	mutex_unlock(&vds->lock);

	/* wakeup all waiters */
	wake_up_all(&vds->sendq);

	/* shutdown all channels */
	while ((chan = vds_lookup_channel(vds, TIPC_ANY_ADDR))) {
		mutex_lock(&chan->lock);
		chan->state = TIPC_STALE;
		chan->remote = 0;
		chan_trigger_event(chan, TIPC_CHANNEL_SHUTDOWN);
		mutex_unlock(&chan->lock);
		kref_put(&chan->refcount, _free_chan);
	}

	/* shutdown device node */
	destroy_cdev_node(vds, &vds->cdev_node);

	dev_info(&vds->vdev->dev, "is offline\n");

	local_irq_disable();
	if (vds->vdev == default_vdev) {
		atomic_notifier_call_chain(&ipc_notifier, TIPC_STATE_OFFLINE, NULL);
	}
	local_irq_enable();
}

static void _handle_conn_rsp(struct tipc_virtio_dev *vds,
			     struct tipc_conn_rsp_body *rsp, size_t len)
{
	struct tipc_chan *chan;

	if (sizeof(*rsp) != len) {
		dev_err(&vds->vdev->dev, "%s: Invalid response length %zd\n",
			__func__, len);
		return;
	}

	dev_dbg(&vds->vdev->dev,
		"%s: connection response: for addr 0x%x: "
		"status %d remote addr 0x%x\n",
		__func__, rsp->target, rsp->status, rsp->remote);

	/* Lookup channel */
	chan = vds_lookup_channel(vds, rsp->target);
	if (chan) {
		mutex_lock(&chan->lock);
		if (chan->state == TIPC_CONNECTING) {
			if (!rsp->status) {
				chan->state = TIPC_CONNECTED;
				chan->remote = rsp->remote;
				chan->max_msg_cnt = rsp->max_msg_cnt;
				chan->max_msg_size = rsp->max_msg_size;
				chan_trigger_event(chan,
						   TIPC_CHANNEL_CONNECTED);
			} else {
				chan->state = TIPC_DISCONNECTED;
				chan->remote = 0;
				chan_trigger_event(chan,
						   TIPC_CHANNEL_DISCONNECTED);
			}
		}
		mutex_unlock(&chan->lock);
		kref_put(&chan->refcount, _free_chan);
	}
}

static void _handle_disc_req(struct tipc_virtio_dev *vds,
			     struct tipc_disc_req_body *req, size_t len)
{
	struct tipc_chan *chan;

	if (sizeof(*req) != len) {
		dev_err(&vds->vdev->dev, "%s: Invalid request length %zd\n",
			__func__, len);
		return;
	}

	dev_dbg(&vds->vdev->dev, "%s: disconnect request: for addr 0x%x\n",
		__func__, req->target);

	chan = vds_lookup_channel(vds, req->target);
	if (chan) {
		mutex_lock(&chan->lock);
		if (chan->state == TIPC_CONNECTED ||
			chan->state == TIPC_CONNECTING) {
			chan->state = TIPC_DISCONNECTED;
			chan->remote = 0;
			chan_trigger_event(chan, TIPC_CHANNEL_DISCONNECTED);
		}
		mutex_unlock(&chan->lock);
		kref_put(&chan->refcount, _free_chan);
	}
}

static void _handle_mref_release_req(struct tipc_virtio_dev *vds,
				     struct tipc_mref_release_req_body *req,
				     size_t len)
{
	while (len >= sizeof(*req)) {
		if (req->id) {
			/* release memref with specified id */
			vds_memref_release(vds, &req->id, 1);
		}
		req++;
		len -= sizeof(*req);
	}
	WARN_ON(len);
}

static void _handle_ctrl_msg(struct tipc_virtio_dev *vds,
			     void *data, int len, u32 src)
{
	struct tipc_ctrl_msg *msg = data;

	if ((len < sizeof(*msg)) || (sizeof(*msg) + msg->body_len != len)) {
		dev_err(&vds->vdev->dev,
			"%s: Invalid message length ( %d vs. %d)\n",
			__func__, (int)(sizeof(*msg) + msg->body_len), len);
		return;
	}

	dev_dbg(&vds->vdev->dev,
		"%s: Incoming ctrl message: src 0x%x type %d len %d\n",
		__func__, src, msg->type, msg->body_len);

	switch (msg->type) {
	case TIPC_CTRL_MSGTYPE_GO_ONLINE:
		_go_online(vds);
	break;

	case TIPC_CTRL_MSGTYPE_GO_OFFLINE:
		_go_offline(vds);
	break;

	case TIPC_CTRL_MSGTYPE_CONN_RSP:
		_handle_conn_rsp(vds, (struct tipc_conn_rsp_body *)msg->body,
				 msg->body_len);
	break;

	case TIPC_CTRL_MSGTYPE_DISC_REQ:
		_handle_disc_req(vds, (struct tipc_disc_req_body *)msg->body,
				 msg->body_len);
	break;

	case TIPC_CTRL_MSGTYPE_MREF_RELEASE_REQ: {
		struct tipc_mref_release_req_body *req =
			      (struct tipc_mref_release_req_body *)msg->body;
		_handle_mref_release_req(vds, req, msg->body_len);
	} break;

	default:
		dev_warn(&vds->vdev->dev,
			 "%s: Unexpected message type: %d\n",
			 __func__, msg->type);
	}
}

static int _handle_rxbuf(struct tipc_virtio_dev *vds,
			 struct tipc_msg_buf *rxbuf, size_t rxlen)
{
	int err;
	struct scatterlist sg;
	struct tipc_msg_hdr *msg;
	struct device *dev = &vds->vdev->dev;

	/* message sanity check */
	if (rxlen > rxbuf->buf_sz) {
		dev_warn(dev, "inbound msg is too big: %zd\n", rxlen);
		goto drop_it;
	}

	if (rxlen < sizeof(*msg)) {
		dev_warn(dev, "inbound msg is too short: %zd\n", rxlen);
		goto drop_it;
	}

	/* reset buffer and put data  */
	mb_reset(rxbuf);
	mb_put_data(rxbuf, rxlen);

	/* get message header */
	msg = mb_get_data(rxbuf, sizeof(*msg));
	if (mb_avail_data(rxbuf) != msg->len) {
		dev_warn(dev, "inbound msg length mismatch: (%d vs. %d)\n",
			 (uint) mb_avail_data(rxbuf), (uint)msg->len);

		dev_warn(dev, "From: %d, To: %d, Len: %d, Flags: 0x%x, Reserved: %d\n",
			msg->src, msg->dst, msg->len, msg->flags, msg->reserved);
		goto drop_it;
	}

	dev_dbg(dev, "From: %d, To: %d, Len: %d, Flags: 0x%x, Reserved: %d\n",
		msg->src, msg->dst, msg->len, msg->flags, msg->reserved);

	/* message directed to control endpoint is a special case */
	if (msg->dst == TIPC_CTRL_ADDR) {
		_handle_ctrl_msg(vds, msg->data, msg->len, msg->src);
	} else {
		struct tipc_chan *chan = NULL;
		/* Lookup channel */
		chan = vds_lookup_channel(vds, msg->dst);
		if (chan) {
			/* handle it */
			rxbuf = chan->ops->handle_msg(chan->ops_arg, rxbuf);
			BUG_ON(!rxbuf);
			kref_put(&chan->refcount, _free_chan);
		}
	}

drop_it:
	/* add the buffer back to the virtqueue */
	sg_init_one(&sg, rxbuf->buf_va, rxbuf->buf_sz);
	err = virtqueue_add_inbuf(vds->rxvq, &sg, 1, rxbuf, GFP_KERNEL);
	if (err < 0) {
		dev_err(dev, "failed to add a virtqueue buffer: %d\n", err);
		return err;
	}

	return 0;
}

static void _handle_rxbuf_work_fn(struct kthread_work *work)
{
	struct tipc_rxbuf *rxbuf =
		container_of(work, struct tipc_rxbuf, work);
	int ret;

	ret = _handle_rxbuf(rxbuf->vds, rxbuf->mb, rxbuf->len);
	if (ret == 0) {
		/* tell the other size that we added rx buffers */
		virtqueue_kick(rxbuf->vds->rxvq);
	}
	kfree(rxbuf);
	return;
}

static int _add_rxbuf_to_work_queue(struct tipc_virtio_dev *vds,
			 struct tipc_msg_buf *mb, size_t len)
{
	struct tipc_rxbuf *rxbuf = kzalloc(sizeof(*rxbuf), GFP_ATOMIC);

	if (rxbuf == NULL) {
		pr_err("%s: failed to allocate tipc_rxbuf\n", __func__);
		return -ENOMEM;
	}

	rxbuf->vds = vds;
	rxbuf->mb = mb;
	rxbuf->len = len;

	kthread_init_work(&rxbuf->work, _handle_rxbuf_work_fn);
	kthread_queue_work(&vds->kworker, &rxbuf->work);
	return 0;
}

/* Called from virtio device, in IRQ context */
static void _rxvq_cb(struct virtqueue *rxvq)
{
	struct tipc_msg_buf *mb;
	struct tipc_virtio_dev *vds = rxvq->vdev->priv;
	spinlock_t *lock = &vds->vq_lock[TIPC_VQ_RX];
	unsigned long flags;
	unsigned int len;
	int ret;
	bool notify = false;

	spin_lock_irqsave(lock, flags);
	do {
		virtqueue_disable_cb(rxvq);
		while ((mb = virtqueue_get_buf(rxvq, &len)) != NULL) {
			ret = _add_rxbuf_to_work_queue(vds, mb, len);
			if (ret) {
				pr_err("failed to add rx buffer to wq, ret=%d\n", ret);
			}
		}
		if (unlikely(virtqueue_is_broken(rxvq)))
			break;
	} while (!virtqueue_enable_cb(rxvq));

	if (virtqueue_kick_prepare(rxvq))
		notify = true;

	spin_unlock_irqrestore(lock, flags);

	if (notify)
		virtqueue_notify(rxvq);
}

static void _discard_ctrl_msg(struct tipc_virtio_dev *vds,
			      struct tipc_msg_buf *mb)
{
	/* nothing to do for control messages */
}

static void _discard_chan_msg(struct tipc_virtio_dev *vds,
			      struct tipc_msg_hdr *msg,
			      struct tipc_msg_buf *mb)
{
	struct tipc_msg_mref_hdr *mhdr;

	/* skip message data */
	(void)mb_get_data(mb, msg->len);

	/* check if we have memrefs attached */
	if (!mb_avail_data(mb))
		return; /* no more data */

	/* align for proper boundary */
	mb_align_read(mb, MEMREF_ALIGN);

	/* discard all memrefs */
	while (mb_avail_data(mb)) {
		/* get memref */
		mhdr = mb_get_data(mb, sizeof(*mhdr));

		/* release mref_by id */
		vds_memref_release(vds, &mhdr->id, 1);

		/* skip to next memref hdr */
		(void)mb_get_data(mb,
				  mhdr->pg_inf_cnt * sizeof(mhdr->pg_inf[0]));
	}
}

/* Called from virtio device, in IRQ context */
static void _txvq_cb(struct virtqueue *txvq)
{
	unsigned int len;
	struct tipc_msg_buf *mb;
	bool need_wakeup = false;
	struct tipc_virtio_dev *vds = txvq->vdev->priv;
	spinlock_t *lock = &vds->vq_lock[TIPC_VQ_TX];
	unsigned long flags;

	dev_dbg(&txvq->vdev->dev, "%s\n", __func__);

	/* detach all buffers */
	spin_lock_irqsave(lock, flags);
	while ((mb = virtqueue_get_buf(txvq, &len)) != NULL) {
		if ((int)len < 0) {
			struct tipc_msg_hdr *msg;

			mb_reset_read(mb);
			msg = mb_get_data(mb, sizeof(*msg));
			if (msg->dst == TIPC_CTRL_ADDR)
				_discard_ctrl_msg(vds, mb);
			else
				_discard_chan_msg(vds, msg, mb);
		}
		need_wakeup |= _put_txbuf_locked(vds, mb);
	}
	spin_unlock_irqrestore(lock, flags);

	if (need_wakeup) {
		/* wake up potential senders waiting for a tx buffer */
		wake_up_all(&vds->sendq);
	}
}

static int tipc_virtio_probe(struct virtio_device *vdev)
{
	int err, i;
	struct tipc_virtio_dev *vds;
	struct tipc_dev_config config;
	struct virtqueue *vqs[TIPC_VQ_MAX];
	vq_callback_t *vq_cbs[] = {_rxvq_cb, _txvq_cb};
	const char *vq_names[] = { "rx", "tx" };
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
	bool *ctx = NULL;
#endif
	unsigned tmp_offset = 0;

	vds = kzalloc(sizeof(*vds), GFP_KERNEL);
	if (!vds)
		return -ENOMEM;

	vds->vdev = vdev;

	mutex_init(&vds->lock);
	kref_init(&vds->refcount);
	init_waitqueue_head(&vds->sendq);
	INIT_LIST_HEAD(&vds->free_buf_list);
	INIT_LIST_HEAD(&vds->stashed_buf_list);
	idr_init(&vds->addr_idr);
	idr_init(&vds->mref_idr);
	mutex_init(&vds->mref_lock);

	for (i = 0; i < TIPC_VQ_MAX; i++) {
		spin_lock_init(&vds->vq_lock[i]);
	}

	kthread_init_worker(&vds->kworker);
	vds->kworker_task = kthread_run(kthread_worker_fn, &vds->kworker,
					"tipc-virtio-rx-worker");
	if (IS_ERR(vds->kworker_task)) {
		dev_err(&vdev->dev, "failed to create tipc virtio rx worker task\n");
		err = PTR_ERR(vds->kworker_task);
		goto err_init_worker;
	}

	/* set default max message size and alignment */
	memset(&config, 0, sizeof(config));
	config.msg_buf_max_size  = DEFAULT_MSG_BUF_SIZE;
	config.msg_buf_alignment = DEFAULT_MSG_BUF_ALIGN;

	/* get configuration if present */
	do {
		unsigned read_length = sizeof(config) - tmp_offset;
		char *p = (char*)&config + tmp_offset;
		if (read_length > 8)
			read_length = 8;

		vdev->config->get(vdev, tmp_offset, p, read_length);
		tmp_offset += read_length;
	} while (tmp_offset < sizeof(config));

	/* copy dev name */
	strlcpy(vds->cdev_name, config.dev_name, sizeof(vds->cdev_name));
	vds->cdev_name[sizeof(vds->cdev_name)-1] = '\0';

	/* find tx virtqueues (rx and tx and in this order) */
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 10, 0)
	err = vdev->config->find_vqs(vdev, TIPC_VQ_MAX, vqs, vq_cbs, vq_names);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
	err = vdev->config->find_vqs(vdev, TIPC_VQ_MAX, vqs, vq_cbs, vq_names, ctx, NULL);
#endif
	if (err)
		goto err_find_vqs;

	vds->rxvq = vqs[0];
	vds->txvq = vqs[1];

	/* save max buffer size and count */
	vds->msg_buf_sz = config.msg_buf_max_size;
	vds->msg_buf_max_cnt = virtqueue_get_vring_size(vds->txvq);

	virtio_device_ready(vdev);

	/* set up the receive buffers */
	for (i = 0; i < virtqueue_get_vring_size(vds->rxvq); i++) {
		struct scatterlist sg;
		struct tipc_msg_buf *rxbuf;

		rxbuf = _alloc_msg_buf(vds->msg_buf_sz);
		if (!rxbuf) {
			dev_err(&vdev->dev, "failed to allocate rx buffer\n");
			err = -ENOMEM;
			goto err_free_rx_buffers;
		}
		sg_init_one(&sg, rxbuf->buf_va, rxbuf->buf_sz);
		err = virtqueue_add_inbuf(vds->rxvq, &sg, 1, rxbuf, GFP_KERNEL);
		WARN_ON(err); /* sanity check; this can't really happen */
	}

	virtqueue_kick(vds->rxvq);

	vdev->priv = vds;
	vds->state = VDS_OFFLINE;

	_go_online(vds);
	dev_dbg(&vdev->dev, "%s: done\n", __func__);
	return 0;

err_free_rx_buffers:
	_cleanup_vq(vds->rxvq);
err_find_vqs:
	kthread_flush_worker(&vds->kworker);
	kthread_stop(vds->kworker_task);
err_init_worker:
	kref_put(&vds->refcount, _free_vds);
	return err;
}

static void tipc_virtio_remove(struct virtio_device *vdev)
{
	struct tipc_virtio_dev *vds = vdev->priv;

	_go_offline(vds);

	mutex_lock(&vds->lock);
	vds->state = VDS_DEAD;
	vds->vdev = NULL;
	mutex_unlock(&vds->lock);

	vdev->config->reset(vdev);

	idr_destroy(&vds->mref_idr);
	idr_destroy(&vds->addr_idr);

	_cleanup_vq(vds->rxvq);
	_cleanup_vq(vds->txvq);
	_free_msg_buf_list(&vds->free_buf_list);
	_free_msg_buf_list(&vds->stashed_buf_list);

	vdev->config->del_vqs(vds->vdev);

	kthread_flush_worker(&vds->kworker);
	kthread_stop(vds->kworker_task);

	kref_put(&vds->refcount, _free_vds);
}

static struct virtio_device_id tipc_virtio_id_table[] = {
	{ VIRTIO_ID_TRUSTY_IPC, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static unsigned int features[] = {
	0,
};

static struct virtio_driver virtio_tipc_driver = {
	.feature_table	= features,
	.feature_table_size = ARRAY_SIZE(features),
	.driver.name	= KBUILD_MODNAME,
	.driver.owner	= THIS_MODULE,
	.id_table	= tipc_virtio_id_table,
	.probe		= tipc_virtio_probe,
	.remove		= tipc_virtio_remove,
};

static int __init tipc_init(void)
{
	int ret;
	dev_t dev;

	if (tipc_major) {
		ret = register_chrdev_region(MKDEV(tipc_major, 0), 1,
					     KBUILD_MODNAME);
		if (ret < 0) {
			pr_err("%s: register_chrdev_region failed: %d\n",
			       __func__, ret);
			return ret;
		}
	} else {
		ret = alloc_chrdev_region(&dev, 0, MAX_DEVICES, KBUILD_MODNAME);
		if (ret) {
			pr_err("%s: alloc_chrdev_region failed: %d\n", __func__,
			       ret);
			return ret;
		}
		tipc_major = MAJOR(dev);
	}
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
	tipc_class = class_create(THIS_MODULE, KBUILD_MODNAME);
#else
	tipc_class = class_create(KBUILD_MODNAME);
#endif
	if (IS_ERR(tipc_class)) {
		ret = PTR_ERR(tipc_class);
		pr_err("%s: class_create failed: %d\n", __func__, ret);
		goto err_class_create;
	}

	ret = register_virtio_driver(&virtio_tipc_driver);
	if (ret) {
		pr_err("failed to register virtio driver: %d\n", ret);
		goto err_register_virtio_drv;
	}

	return 0;

err_register_virtio_drv:
	class_destroy(tipc_class);

err_class_create:
	unregister_chrdev_region(dev, MAX_DEVICES);
	return ret;
}

static void __exit tipc_exit(void)
{
	unregister_virtio_driver(&virtio_tipc_driver);
	class_destroy(tipc_class);
	unregister_chrdev_region(MKDEV(tipc_major, 0), MAX_DEVICES);
}

/* We need to init this early */
subsys_initcall(tipc_init);
module_exit(tipc_exit);

MODULE_DEVICE_TABLE(tipc, tipc_virtio_id_table);
MODULE_DESCRIPTION("vTEE IPC forwarding driver");
MODULE_LICENSE("GPL v2");
