// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2009 Red Hat, Inc.
 * Author: Michael S. Tsirkin <mst@redhat.com>
 *
 * virtio-net server in host kernel.
 */

#include <linux/compat.h>
#include <linux/eventfd.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/workqueue.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/sched/clock.h>
#include <linux/sched/signal.h>
#include <linux/vmalloc.h>

#include <linux/net.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <linux/if_macvlan.h>
#include <linux/if_tap.h>
#include <linux/if_vlan.h>
#include <linux/skb_array.h>
#include <linux/skbuff.h>

#include <net/sock.h>
#include <net/xdp.h>

#include "nebula_rproc_remote.h"
#include "remoteproc_virtio.h"
#include "virtqueue.h"
#include "virtio.h"
#include "virtio_vnet.h"
#include "if_tun.h"

#define CREATE_TRACE_POINTS
#include "trace.h"

#define RPROC_NET_MINOR 254

/* Resource table entries */
#define	VRING_ALIGN 0x1000
#define	VRING_SIZE 256

static int experimental_zcopytx = 0;
module_param(experimental_zcopytx, int, 0444);
MODULE_PARM_DESC(experimental_zcopytx, "Enable Zero Copy TX;"
		                       " 1 -Enable; 0 - Disable");

/* Max number of bytes transferred before requeueing the job.
 * Using this limit prevents one virtqueue from starving others. */
#define VHOST_NET_WEIGHT 0x80000

/* Max number of packets transferred before requeueing the job.
 * Using this limit prevents one virtqueue from starving others with small
 * pkts.
 */
#define VHOST_NET_PKT_WEIGHT 256

/* MAX number of TX used buffers for outstanding zerocopy */
#define VHOST_MAX_PEND 128
#define VHOST_GOODCOPY_LEN 256

/*
 * For transmit, used buffer len is unused; we override it to track buffer
 * status internally; used for zerocopy tx only.
 */
/* Lower device DMA failed */
#define VHOST_DMA_FAILED_LEN	((__force __virtio32)3)
/* Lower device DMA done */
#define VHOST_DMA_DONE_LEN	((__force __virtio32)2)
/* Lower device DMA in progress */
#define VHOST_DMA_IN_PROGRESS	((__force __virtio32)1)
/* Buffer unused */
#define VHOST_DMA_CLEAR_LEN	((__force __virtio32)0)

#define VHOST_DMA_IS_DONE(len) ((__force u32)(len) >= (__force u32)VHOST_DMA_DONE_LEN)

#define VHOST_NET_F_VIRTIO_NET_HDR 27

enum {
	VHOST_NET_FEATURES =
			 (1ULL << VHOST_NET_F_VIRTIO_NET_HDR) |
			 (1ULL << VIRTIO_NET_F_MRG_RXBUF)
};

enum {
	VHOST_NET_VQ_RX = 0,
	VHOST_NET_VQ_TX = 1,
	VHOST_NET_VQ_MAX = 2,
};

struct vhost_net_device_descriptor {
	struct fw_rsc_vdev vdev;
	struct fw_rsc_vdev_vring vrings[VHOST_NET_VQ_MAX];
	struct virtio_net_config config;
} __packed;

static const struct vhost_net_device_descriptor vhost_net_vdev_desc = {
	.vdev = {
		.type = RSC_VDEV,
		.id = VIRTIO_ID_NETWORK,
		.dfeatures = VHOST_NET_FEATURES,
		.config_len = sizeof(struct virtio_net_config),
		.num_of_vrings = VHOST_NET_VQ_MAX,
	},
	.vrings = {
		[VHOST_NET_VQ_RX] = {
			.da = FW_RSC_U32_ADDR_ANY,
			.align = VRING_ALIGN,
			.num = VRING_SIZE,
		},
		[VHOST_NET_VQ_TX] = {
			.da = FW_RSC_U32_ADDR_ANY,
			.align = VRING_ALIGN,
			.num = VRING_SIZE,
		},
	},
};

struct vhost_net_ubuf_ref {
	/* refcount follows semantics similar to kref:
	 *  0: object is released
	 *  1: no outstanding ubufs
	 * >1: outstanding ubufs
	 */
	atomic_t refcount;
	wait_queue_head_t wait;
	struct virtqueue *vq;
};

#define VHOST_NET_BATCH 64
struct vhost_net_buf {
	void **queue;
	int tail;
	int head;
};

struct vhost_net_virtqueue {
	struct virtqueue *vq;
	size_t vhost_hlen;
	size_t sock_hlen;
	/* vhost zerocopy support fields below: */
	/* last used idx for outstanding DMA zerocopy buffers */
	int upend_idx;
	/* For TX, first used idx for DMA done zerocopy buffers
	 * For RX, number of batched heads
	 */
	int done_idx;
	/* Number of XDP frames batched */
	int batched_xdp;
	/* an array of userspace buffers info */
	struct ubuf_info_msgzc *ubuf_info;
	/* Reference counting for outstanding ubufs.
	 * Protected by vq mutex. Writers must also take device mutex. */
	struct vhost_net_ubuf_ref *ubufs;
	struct ptr_ring *rx_ring;
	struct vhost_net_buf rxq;
	/* Batched XDP buffs */
	struct xdp_buff *xdp;
};

struct vhost_net;
struct vhost_poll {
	poll_table		table;
	wait_queue_head_t	*wqh;
	wait_queue_entry_t	wait;
	struct work_struct	work;
	__poll_t		mask;
	struct workqueue_struct	*workq;
	struct vhost_net       *net;
};

struct vhost_net {
	struct vhost_net_virtqueue vqs[VHOST_NET_VQ_MAX];
	struct vhost_poll poll[VHOST_NET_VQ_MAX];
	/* Number of TX recently submitted.
	 * Protected by tx vq lock. */
	unsigned tx_packets;
	/* Number of times zerocopy TX recently failed.
	 * Protected by tx vq lock. */
	unsigned tx_zcopy_err;
	/* Flush in progress. Protected by tx vq lock. */
	bool tx_flush;
	/* Private page frag */
	struct page_frag page_frag;
	/* Refcount bias of page frag */
	int refcnt_bias;

	struct workqueue_struct* workq;
	struct mutex mutex;

	atomic_t pending_work_count;
	int weight;
	int byte_weight;
};

static void vhost_work_queue(struct vhost_net *net, struct work_struct *work)
{
	if (queue_work(net->workq, work)) {
		atomic_inc(&net->pending_work_count);
	}
}

static int vhost_poll_wakeup(wait_queue_entry_t *wait, unsigned mode, int sync,
			     void *key)
{
	struct vhost_poll *poll = container_of(wait, struct vhost_poll, wait);

	if (!(key_to_poll(key) & poll->mask))
		return 0;

	vhost_work_queue(poll->net, &poll->work);
	return 0;
}

static void vhost_poll_func(struct file *file, wait_queue_head_t *wqh,
			    poll_table *pt)
{
	struct vhost_poll *poll;

	poll = container_of(pt, struct vhost_poll, table);
	poll->wqh = wqh;
	add_wait_queue(wqh, &poll->wait);
}

static void vhost_poll_init(struct vhost_poll *poll, work_func_t fn,
		     __poll_t mask, struct vhost_net *net)
{
	init_waitqueue_func_entry(&poll->wait, vhost_poll_wakeup);
	init_poll_funcptr(&poll->table, vhost_poll_func);
	poll->mask = mask;
	poll->wqh = NULL;
	poll->net = net;
	poll->workq = net->workq;

	INIT_WORK(&poll->work, fn);
}


/* Stop polling a file. After this function returns, it becomes safe to drop the
 * file reference. You must also flush afterwards. */
static void vhost_poll_stop(struct vhost_poll *poll)
{
	if (poll->wqh) {
		remove_wait_queue(poll->wqh, &poll->wait);
		poll->wqh = NULL;
	}
}

/* Start polling a file. We add ourselves to file's wait queue. The caller must
 * keep a reference to a file until after vhost_poll_stop is called. */
static int vhost_poll_start(struct vhost_poll *poll, struct file *file)
{
	__poll_t mask;

	if (poll->wqh)
		return 0;

	mask = vfs_poll(file, &poll->table);
	if (mask)
		vhost_poll_wakeup(&poll->wait, 0, 0, poll_to_key(mask));
	if (mask & EPOLLERR) {
		vhost_poll_stop(poll);
		return -EINVAL;
	}

	return 0;
}

/* A lockless hint for busy polling code to exit the loop */
static bool vhost_has_work(struct vhost_net *net)
{
	return atomic_read(&net->pending_work_count) != 0;
}

static void vhost_poll_queue(struct vhost_poll *poll)
{
	vhost_work_queue(poll->net, &poll->work);
}

static bool vhost_exceeds_weight(struct vhost_net *net, struct virtqueue *vq,
				 int pkts, int total_len)
{
	if ((net->byte_weight && total_len >= net->byte_weight) ||
	    pkts >= net->weight) {
		vhost_poll_queue(vq->poll);
		return true;
	}

	return false;
}

static void vhost_dev_flush(struct vhost_net *n) {
	drain_workqueue(n->workq);
}

static void vhost_dev_stop(struct vhost_net *n)
{
	int i;

	for (i = 0; i < VHOST_NET_VQ_MAX; ++i) {
		vhost_poll_stop(&n->poll[i]);
	}

	vhost_dev_flush(n);
}

static unsigned vhost_net_zcopy_mask __read_mostly;

static inline size_t kvec_length(const struct kvec* iov, unsigned long nr_segs)
{
	unsigned long seg;
	size_t ret = 0;

	for (seg = 0; seg < nr_segs; seg++)
		ret += iov[seg].iov_len;
	return ret;
}

static struct socket *s_backend_socks[VHOST_NET_VQ_MAX];

static void *vhost_net_buf_get_ptr(struct vhost_net_buf *rxq)
{
	if (rxq->tail != rxq->head)
		return rxq->queue[rxq->head];
	else
		return NULL;
}

static int vhost_net_buf_get_size(struct vhost_net_buf *rxq)
{
	return rxq->tail - rxq->head;
}

static int vhost_net_buf_is_empty(struct vhost_net_buf *rxq)
{
	return rxq->tail == rxq->head;
}

static void *vhost_net_buf_consume(struct vhost_net_buf *rxq)
{
	void *ret = vhost_net_buf_get_ptr(rxq);
	++rxq->head;
	return ret;
}

static int vhost_net_buf_produce(struct vhost_net_virtqueue *nvq)
{
	struct vhost_net_buf *rxq = &nvq->rxq;

	rxq->head = 0;
	rxq->tail = ptr_ring_consume_batched(nvq->rx_ring, rxq->queue,
					      VHOST_NET_BATCH);
	return rxq->tail;
}

static void vhost_net_buf_unproduce(struct vhost_net_virtqueue *nvq)
{
	struct vhost_net_buf *rxq = &nvq->rxq;

	if (nvq->rx_ring && !vhost_net_buf_is_empty(rxq)) {
		ptr_ring_unconsume(nvq->rx_ring, rxq->queue + rxq->head,
				   vhost_net_buf_get_size(rxq),
				   tun_ptr_free);
		rxq->head = rxq->tail = 0;
	}
}

static int vhost_net_buf_peek_len(void *ptr)
{
	if (tun_is_xdp_frame(ptr)) {
		struct xdp_frame *xdpf = tun_ptr_to_xdp(ptr);

		return xdpf->len;
	}

	return __skb_array_len_with_tag(ptr);
}

static int vhost_net_buf_peek(struct vhost_net_virtqueue *nvq)
{
	struct vhost_net_buf *rxq = &nvq->rxq;

	if (!vhost_net_buf_is_empty(rxq))
		goto out;

	if (!vhost_net_buf_produce(nvq))
		return 0;

out:
	return vhost_net_buf_peek_len(vhost_net_buf_get_ptr(rxq));
}

static void vhost_net_buf_init(struct vhost_net_buf *rxq)
{
	rxq->head = rxq->tail = 0;
}

static void vhost_net_enable_zcopy(int vq)
{
	vhost_net_zcopy_mask |= 0x1 << vq;
}

static struct vhost_net_ubuf_ref *
vhost_net_ubuf_alloc(struct virtqueue *vq, bool zcopy)
{
	struct vhost_net_ubuf_ref *ubufs;
	/* No zero copy backend? Nothing to count. */
	if (!zcopy)
		return NULL;
	ubufs = kmalloc(sizeof(*ubufs), GFP_KERNEL);
	if (!ubufs)
		return ERR_PTR(-ENOMEM);
	atomic_set(&ubufs->refcount, 1);
	init_waitqueue_head(&ubufs->wait);
	ubufs->vq = vq;
	return ubufs;
}

static int vhost_net_ubuf_put(struct vhost_net_ubuf_ref *ubufs)
{
	int r = atomic_sub_return(1, &ubufs->refcount);
	if (unlikely(!r))
		wake_up(&ubufs->wait);
	return r;
}

static void vhost_net_ubuf_put_and_wait(struct vhost_net_ubuf_ref *ubufs)
{
	vhost_net_ubuf_put(ubufs);
	wait_event(ubufs->wait, !atomic_read(&ubufs->refcount));
}

static void vhost_net_ubuf_put_wait_and_free(struct vhost_net_ubuf_ref *ubufs)
{
	vhost_net_ubuf_put_and_wait(ubufs);
	kfree(ubufs);
}

static void vhost_net_clear_ubuf_info(struct vhost_net *n)
{
	int i;

	for (i = 0; i < VHOST_NET_VQ_MAX; ++i) {
		kfree(n->vqs[i].ubuf_info);
		n->vqs[i].ubuf_info = NULL;
	}
}

static int vhost_net_set_ubuf_info(struct vhost_net *n)
{
	bool zcopy;
	int i;

	for (i = 0; i < VHOST_NET_VQ_MAX; ++i) {
		zcopy = vhost_net_zcopy_mask & (0x1 << i);
		if (!zcopy)
			continue;
		n->vqs[i].ubuf_info =
			kmalloc_array(UIO_MAXIOV,
				      sizeof(*n->vqs[i].ubuf_info),
				      GFP_KERNEL);
		if  (!n->vqs[i].ubuf_info)
			goto err;
	}
	return 0;

err:
	vhost_net_clear_ubuf_info(n);
	return -ENOMEM;
}

static void vhost_net_vq_reset(struct vhost_net *n)
{
	int i;

	vhost_net_clear_ubuf_info(n);

	for (i = 0; i < VHOST_NET_VQ_MAX; i++) {
		n->vqs[i].done_idx = 0;
		n->vqs[i].upend_idx = 0;
		n->vqs[i].ubufs = NULL;
		n->vqs[i].vhost_hlen = 0;
		n->vqs[i].sock_hlen = 0;
		vhost_net_buf_init(&n->vqs[i].rxq);
	}

}

static void vhost_net_tx_packet(struct vhost_net *net)
{
	++net->tx_packets;
	if (net->tx_packets < 1024)
		return;
	net->tx_packets = 0;
	net->tx_zcopy_err = 0;
}

static void vhost_net_tx_err(struct vhost_net *net)
{
	++net->tx_zcopy_err;
}

static bool vhost_net_tx_select_zcopy(struct vhost_net *net)
{
	/* TX flush waits for outstanding DMAs to be done.
	 * Don't start new DMAs.
	 */
	return !net->tx_flush &&
		net->tx_packets / 64 >= net->tx_zcopy_err;
}

static bool vhost_sock_zcopy(struct socket *sock)
{
	return unlikely(experimental_zcopytx) &&
		sock_flag(sock->sk, SOCK_ZEROCOPY);
}

static bool vhost_sock_xdp(struct socket *sock)
{
	return sock_flag(sock->sk, SOCK_XDP);
}

/* In case of DMA done not in order in lower device driver for some reason.
 * upend_idx is used to track end of used idx, done_idx is used to track head
 * of used idx. Once lower device DMA done contiguously, we will signal KVM
 * guest used idx.
 */
static void vhost_zerocopy_signal_used(struct vhost_net *net,
				       struct vhost_net_virtqueue *nvq)
{
	struct virtqueue *vq = nvq->vq;
	int i, add;
	int j = 0;

	for (i = nvq->done_idx; i != nvq->upend_idx; i = (i + 1) % UIO_MAXIOV) {
		if (vq->heads[i].len == VHOST_DMA_FAILED_LEN)
			vhost_net_tx_err(net);
		if (VHOST_DMA_IS_DONE(vq->heads[i].len)) {
			vq->heads[i].len = VHOST_DMA_CLEAR_LEN;
			++j;
		} else
			break;
	}
	while (j) {
		add = min(UIO_MAXIOV - nvq->done_idx, j);
		virtqueue_add_used_and_signal_n(vq, &vq->heads[nvq->done_idx],
						add);
		nvq->done_idx = (nvq->done_idx + add) % UIO_MAXIOV;
		j -= add;
	}
}

static void vhost_zerocopy_callback(struct sk_buff *skb,
				    struct ubuf_info *ubuf_base, bool success)
{
	struct ubuf_info_msgzc *ubuf = uarg_to_msgzc(ubuf_base);
	struct vhost_net_ubuf_ref *ubufs = ubuf->ctx;
	struct virtqueue *vq = ubufs->vq;
	int cnt;

	rcu_read_lock_bh();

	/* set len to mark this desc buffers done DMA */
	vq->heads[ubuf->desc].len = success ?
		VHOST_DMA_DONE_LEN : VHOST_DMA_FAILED_LEN;
	cnt = vhost_net_ubuf_put(ubufs);

	/*
	 * Trigger polling thread if guest stopped submitting new buffers:
	 * in this case, the refcount after decrement will eventually reach 1.
	 * We also trigger polling periodically after each 16 packets
	 * (the value 16 here is more or less arbitrary, it's tuned to trigger
	 * less than 10% of times).
	 */
	if (cnt <= 1 || !(cnt % 16))
		vhost_poll_queue(vq->poll);

	rcu_read_unlock_bh();
}

static inline unsigned long busy_clock(void)
{
	return local_clock() >> 10;
}

static bool vhost_can_busy_poll(unsigned long endtime)
{
	return likely(!need_resched() && !time_after(busy_clock(), endtime) &&
		      !signal_pending(current));
}

static void vhost_net_disable_vq(struct vhost_net *n,
				 struct vhost_net_virtqueue *nvq)
{
	struct vhost_poll *poll = n->poll + (nvq - n->vqs);
	if (!nvq->vq->priv)
		return;
	vhost_poll_stop(poll);
}

static int vhost_net_enable_vq(struct vhost_net *n,
				struct vhost_net_virtqueue *nvq)
{
	struct vhost_poll *poll = n->poll + (nvq - n->vqs);
	struct socket *sock;

	sock = nvq->vq->priv;
	if (!sock)
		return 0;
	return vhost_poll_start(poll, sock->file);
}

static void vhost_net_signal_used(struct vhost_net_virtqueue *nvq)
{
	struct virtqueue *vq = nvq->vq;

	if (!nvq->done_idx)
		return;

	virtqueue_add_used_and_signal_n(vq, vq->heads, nvq->done_idx);
	nvq->done_idx = 0;
}

static void vhost_tx_batch(struct vhost_net *net,
			   struct vhost_net_virtqueue *nvq,
			   struct socket *sock,
			   struct msghdr *msghdr)
{
	struct tun_msg_ctl ctl = {
		.type = TUN_MSG_PTR,
		.num = nvq->batched_xdp,
		.ptr = nvq->xdp,
	};
	int i, err;

	TRACE_FUNC_BEGIN();
	if (nvq->batched_xdp == 0)
		goto signal_used;

	msghdr->msg_control = &ctl;
	msghdr->msg_controllen = sizeof(ctl);
	err = sock->ops->sendmsg(sock, msghdr, 0);
	if (unlikely(err < 0)) {
		pr_err("Fail to batch sending packets\n");

		/* free pages owned by XDP; since this is an unlikely error path,
		 * keep it simple and avoid more complex bulk update for the
		 * used pages
		 */
		for (i = 0; i < nvq->batched_xdp; ++i)
			put_page(virt_to_head_page(nvq->xdp[i].data));
		nvq->batched_xdp = 0;
		nvq->done_idx = 0;
		return;
	}

signal_used:
	vhost_net_signal_used(nvq);
	nvq->batched_xdp = 0;
	TRACE_FUNC_END();
}

static int sock_has_rx_data(struct socket *sock)
{
	if (unlikely(!sock))
		return 0;

	if (sock->ops->peek_len)
		return sock->ops->peek_len(sock);

	return skb_queue_empty(&sock->sk->sk_receive_queue);
}

static void vhost_net_busy_poll_try_queue(struct vhost_net *net,
					  struct virtqueue *vq)
{
	if (!virtqueue_avail_empty(vq)) {
		vhost_poll_queue(vq->poll);
	} else if (unlikely(virtqueue_enable_cb(vq))) {
		virtqueue_disable_cb(vq);
		vhost_poll_queue(vq->poll);
	}
}

static void vhost_net_busy_poll(struct vhost_net *net,
				struct virtqueue *rvq,
				struct virtqueue *tvq,
				bool *busyloop_intr,
				bool poll_rx)
{
	unsigned long busyloop_timeout;
	unsigned long endtime;
	struct socket *sock;
	struct virtqueue *vq = poll_rx ? tvq : rvq;

	/* Try to hold the vq mutex of the paired virtqueue. We can't
	 * use mutex_lock() here since we could not guarantee a
	 * consistenet lock ordering.
	 */
	if (!mutex_trylock(&vq->mutex))
		return;

	virtqueue_disable_cb(vq);
	sock = rvq->priv;

	busyloop_timeout = poll_rx ? rvq->busyloop_timeout:
				     tvq->busyloop_timeout;

	preempt_disable();
	endtime = busy_clock() + busyloop_timeout;

	while (vhost_can_busy_poll(endtime)) {
		if (vhost_has_work(net)) {
			*busyloop_intr = true;
			break;
		}

		if ((sock_has_rx_data(sock) &&
		     !virtqueue_avail_empty(rvq)) ||
		     !virtqueue_avail_empty(tvq))
			break;

		cpu_relax();
	}

	preempt_enable();

	if (poll_rx || sock_has_rx_data(sock))
		vhost_net_busy_poll_try_queue(net, vq);
	else if (!poll_rx) /* On tx here, sock has no rx data. */
		virtqueue_enable_cb(rvq);

	mutex_unlock(&vq->mutex);
}

static int vhost_net_tx_get_vq_desc(struct vhost_net *net,
				    struct vhost_net_virtqueue *tnvq,
				    unsigned int *out_num, unsigned int *in_num,
				    struct msghdr *msghdr, bool *busyloop_intr)
{
	struct vhost_net_virtqueue *rnvq = &net->vqs[VHOST_NET_VQ_RX];
	struct virtqueue *rvq = rnvq->vq;
	struct virtqueue *tvq = tnvq->vq;
	struct socket *sock = tvq->priv;

	int r = virtqueue_get_vq_desc(tvq, tvq->iov, ARRAY_SIZE(tvq->iov),
				      out_num, in_num);

	if (r == ERROR_VRING_NO_BUFF && tvq->busyloop_timeout) {
		/* Flush batched packets first */
		if (!vhost_sock_zcopy(sock))
			vhost_tx_batch(net, tnvq,
				       sock,
				       msghdr);

		vhost_net_busy_poll(net, rvq, tvq, busyloop_intr, false);

		r = virtqueue_get_vq_desc(tvq, tvq->iov, ARRAY_SIZE(tvq->iov),
					  out_num, in_num);
	}

	if (r == ERROR_VRING_NO_BUFF)
		r = tvq->vq_nentries;

	return r;
}

static bool vhost_exceeds_maxpend(struct vhost_net *net)
{
	struct vhost_net_virtqueue *nvq = &net->vqs[VHOST_NET_VQ_TX];
	struct virtqueue *vq = nvq->vq;

	return (nvq->upend_idx + UIO_MAXIOV - nvq->done_idx) % UIO_MAXIOV >
	       min_t(unsigned int, VHOST_MAX_PEND, vq->vq_nentries >> 2);
}

static size_t init_iov_iter(struct virtqueue *vq, struct kvec *iov,
			    struct iov_iter *iter, size_t hdr_size, int out)
{
	/* Skip header. TODO: support TSO. */
	size_t len = kvec_length(iov, out);

	iov_iter_kvec(iter, ITER_SOURCE, iov, out, len);
	iov_iter_advance(iter, hdr_size);

	return iov_iter_count(iter);
}

static int get_tx_bufs(struct vhost_net *net,
		       struct vhost_net_virtqueue *nvq,
		       struct msghdr *msg,
		       unsigned int *out, unsigned int *in,
		       size_t *len, bool *busyloop_intr)
{
	struct virtqueue *vq = nvq->vq;
	int ret;

	ret = vhost_net_tx_get_vq_desc(net, nvq, out, in, msg, busyloop_intr);

	if (ret < 0 || ret == vq->vq_nentries)
		return ret;

	if (*in) {
		pr_err("Unexpected descriptor format for TX: out %d, int %d\n",
			*out, *in);
		return -EFAULT;
	}

	/* Sanity check */
	*len = init_iov_iter(vq, vq->iov, &msg->msg_iter, nvq->vhost_hlen, *out);
	if (*len == 0) {
		pr_err("Unexpected header len for TX: %zd expected %zd\n",
			*len, nvq->vhost_hlen);
		return -EFAULT;
	}

	return ret;
}

static bool tx_can_batch(struct virtqueue *vq, size_t total_len)
{
	return total_len < VHOST_NET_WEIGHT &&
	       !virtqueue_avail_empty(vq);
}

static bool vhost_net_page_frag_refill(struct vhost_net *net, unsigned int sz,
				       struct page_frag *pfrag, gfp_t gfp)
{
	if (pfrag->page) {
		if (pfrag->offset + sz <= pfrag->size)
			return true;
		__page_frag_cache_drain(pfrag->page, net->refcnt_bias);
	}

	pfrag->offset = 0;
	net->refcnt_bias = 0;
	if (SKB_FRAG_PAGE_ORDER) {
		/* Avoid direct reclaim but allow kswapd to wake */
		pfrag->page = alloc_pages((gfp & ~__GFP_DIRECT_RECLAIM) |
					  __GFP_COMP | __GFP_NOWARN |
					  __GFP_NORETRY,
					  SKB_FRAG_PAGE_ORDER);
		if (likely(pfrag->page)) {
			pfrag->size = PAGE_SIZE << SKB_FRAG_PAGE_ORDER;
			goto done;
		}
	}
	pfrag->page = alloc_page(gfp);
	if (likely(pfrag->page)) {
		pfrag->size = PAGE_SIZE;
		goto done;
	}
	return false;

done:
	net->refcnt_bias = USHRT_MAX;
	page_ref_add(pfrag->page, USHRT_MAX - 1);
	return true;
}

#define VHOST_NET_RX_PAD (NET_IP_ALIGN + NET_SKB_PAD)

static int vhost_net_build_xdp(struct vhost_net_virtqueue *nvq,
			       struct iov_iter *from)
{
	struct virtqueue *vq = nvq->vq;
	struct virtio_device *vdev = vq->vq_dev;
	struct vhost_net *net = vdev->priv;
	struct socket *sock = vq->priv;
	struct page_frag *alloc_frag = &net->page_frag;
	struct virtio_net_hdr *gso;
	struct xdp_buff *xdp = &nvq->xdp[nvq->batched_xdp];
	struct tun_xdp_hdr *hdr;
	size_t len = iov_iter_count(from);
	int headroom = vhost_sock_xdp(sock) ? XDP_PACKET_HEADROOM : 0;
	int buflen = SKB_DATA_ALIGN(sizeof(struct skb_shared_info));
	int pad = SKB_DATA_ALIGN(VHOST_NET_RX_PAD + headroom + nvq->sock_hlen);
	int sock_hlen = nvq->sock_hlen;
	void *buf;
	int copied;

	if (unlikely(len < nvq->sock_hlen))
		return -EFAULT;

	if (SKB_DATA_ALIGN(len + pad) +
	    SKB_DATA_ALIGN(sizeof(struct skb_shared_info)) > PAGE_SIZE)
		return -ENOSPC;

	buflen += SKB_DATA_ALIGN(len + pad);
	alloc_frag->offset = ALIGN((u64)alloc_frag->offset, SMP_CACHE_BYTES);
	if (unlikely(!vhost_net_page_frag_refill(net, buflen,
						 alloc_frag, GFP_KERNEL)))
		return -ENOMEM;

	buf = (char *)page_address(alloc_frag->page) + alloc_frag->offset;
	copied = copy_page_from_iter(alloc_frag->page,
				     alloc_frag->offset +
				     offsetof(struct tun_xdp_hdr, gso),
				     sock_hlen, from);
	if (copied != sock_hlen)
		return -EFAULT;

	hdr = buf;
	gso = &hdr->gso;

	if ((gso->flags & VIRTIO_NET_HDR_F_NEEDS_CSUM) &&
	    le16_to_cpu(gso->csum_start) +
	    le16_to_cpu(gso->csum_offset) + 2 >
	    le16_to_cpu(gso->hdr_len)) {
		gso->hdr_len = cpu_to_le16(
			       le16_to_cpu(gso->csum_start) +
			       le16_to_cpu(gso->csum_offset) + 2);

		if (le16_to_cpu(gso->hdr_len) > len)
			return -EINVAL;
	}

	len -= sock_hlen;
	copied = copy_page_from_iter(alloc_frag->page,
				     alloc_frag->offset + pad,
				     len, from);
	if (copied != len)
		return -EFAULT;

	xdp_init_buff(xdp, buflen, NULL);
	xdp_prepare_buff(xdp, buf, pad, len, true);
	hdr->buflen = buflen;

	--net->refcnt_bias;
	alloc_frag->offset += buflen;

	++nvq->batched_xdp;

	return 0;
}

static void handle_tx_copy(struct vhost_net *net, struct socket *sock)
{
	struct vhost_net_virtqueue *nvq = &net->vqs[VHOST_NET_VQ_TX];
	struct virtqueue *vq = nvq->vq;
	unsigned out, in;
	int head;
	struct msghdr msg = {
		.msg_name = NULL,
		.msg_namelen = 0,
		.msg_control = NULL,
		.msg_controllen = 0,
		.msg_flags = MSG_DONTWAIT,
	};
	size_t len, total_len = 0;
	int err;
	int sent_pkts = 0;
	bool sock_can_batch = (sock->sk->sk_sndbuf == INT_MAX);

	do {
		bool busyloop_intr = false;

		if (nvq->done_idx == VHOST_NET_BATCH)
			vhost_tx_batch(net, nvq, sock, &msg);

		head = get_tx_bufs(net, nvq, &msg, &out, &in, &len,
				   &busyloop_intr);
		/* On error, stop handling until the next kick. */
		if (unlikely(head < 0))
			break;
		/* Nothing new?  Wait for eventfd to tell us they refilled. */
		if (head == vq->vq_nentries) {
			if (unlikely(busyloop_intr)) {
				vhost_poll_queue(vq->poll);
			} else if (unlikely(virtqueue_enable_cb(vq))) {
				virtqueue_disable_cb(vq);
				continue;
			}
			break;
		}

		total_len += len;

		/* For simplicity, TX batching is only enabled if
		 * sndbuf is unlimited.
		 */
		if (sock_can_batch) {
			TRACE_BEGIN("build_xdp");
			err = vhost_net_build_xdp(nvq, &msg.msg_iter);
			TRACE_END("build_xdp");
			if (!err) {
				goto done;
			} else if (unlikely(err != -ENOSPC)) {
				vhost_tx_batch(net, nvq, sock, &msg);
				virtqueue_discard_vq_desc(vq, 1);
				vhost_net_enable_vq(net, nvq);
				break;
			}

			/* We can't build XDP buff, go for single
			 * packet path but let's flush batched
			 * packets.
			 */
			vhost_tx_batch(net, nvq, sock, &msg);
			msg.msg_control = NULL;
		} else {
			if (tx_can_batch(vq, total_len))
				msg.msg_flags |= MSG_MORE;
			else
				msg.msg_flags &= ~MSG_MORE;
		}

		err = sock->ops->sendmsg(sock, &msg, len);
		if (unlikely(err < 0)) {
			if (err == -EAGAIN || err == -ENOMEM || err == -ENOBUFS) {
				virtqueue_discard_vq_desc(vq, 1);
				vhost_net_enable_vq(net, nvq);
				break;
			}
			pr_debug("Fail to send packet: err %d", err);
		} else if (unlikely(err != len))
			pr_debug("Truncated TX packet: len %d != %zd\n",
				 err, len);
done:
		vq->heads[nvq->done_idx].id = cpu_to_le32(head);
		vq->heads[nvq->done_idx].len = 0;
		++nvq->done_idx;
	} while (likely(!vhost_exceeds_weight(net, vq, ++sent_pkts, total_len)));

	vhost_tx_batch(net, nvq, sock, &msg);
}

static void handle_tx_zerocopy(struct vhost_net *net, struct socket *sock)
{
	struct vhost_net_virtqueue *nvq = &net->vqs[VHOST_NET_VQ_TX];
	struct virtqueue *vq = nvq->vq;
	unsigned out, in;
	int head;
	struct msghdr msg = {
		.msg_name = NULL,
		.msg_namelen = 0,
		.msg_control = NULL,
		.msg_controllen = 0,
		.msg_flags = MSG_DONTWAIT,
	};
	struct tun_msg_ctl ctl;
	size_t len, total_len = 0;
	int err;
	struct vhost_net_ubuf_ref *ubufs;
	struct ubuf_info_msgzc *ubuf;
	bool zcopy_used;
	int sent_pkts = 0;

	do {
		bool busyloop_intr;

		/* Release DMAs done buffers first */
		vhost_zerocopy_signal_used(net, nvq);

		busyloop_intr = false;
		head = get_tx_bufs(net, nvq, &msg, &out, &in, &len,
				   &busyloop_intr);
		/* On error, stop handling until the next kick. */
		if (unlikely(head < 0))
			break;
		/* Nothing new?  Wait for eventfd to tell us they refilled. */
		if (head == vq->vq_nentries) {
			if (unlikely(busyloop_intr)) {
				vhost_poll_queue(vq->poll);
			} else if (unlikely(virtqueue_enable_cb(vq))) {
				virtqueue_disable_cb(vq);
				continue;
			}
			break;
		}

		zcopy_used = len >= VHOST_GOODCOPY_LEN
			     && !vhost_exceeds_maxpend(net)
			     && vhost_net_tx_select_zcopy(net);

		/* use msg_control to pass vhost zerocopy ubuf info to skb */
		if (zcopy_used) {
			ubuf = nvq->ubuf_info + nvq->upend_idx;
			vq->heads[nvq->upend_idx].id = cpu_to_le32(head);
			vq->heads[nvq->upend_idx].len = VHOST_DMA_IN_PROGRESS;
			ubuf->ctx = nvq->ubufs;
			ubuf->desc = nvq->upend_idx;
			ubuf->ubuf.callback = vhost_zerocopy_callback;
			ubuf->ubuf.flags = SKBFL_ZEROCOPY_FRAG;
			refcount_set(&ubuf->ubuf.refcnt, 1);
			msg.msg_control = &ctl;
			ctl.type = TUN_MSG_UBUF;
			ctl.ptr = &ubuf->ubuf;
			msg.msg_controllen = sizeof(ctl);
			ubufs = nvq->ubufs;
			atomic_inc(&ubufs->refcount);
			nvq->upend_idx = (nvq->upend_idx + 1) % UIO_MAXIOV;
		} else {
			msg.msg_control = NULL;
			ubufs = NULL;
		}
		total_len += len;
		if (tx_can_batch(vq, total_len) &&
		    likely(!vhost_exceeds_maxpend(net))) {
			msg.msg_flags |= MSG_MORE;
		} else {
			msg.msg_flags &= ~MSG_MORE;
		}

		err = sock->ops->sendmsg(sock, &msg, len);
		if (unlikely(err < 0)) {
			bool retry = err == -EAGAIN || err == -ENOMEM || err == -ENOBUFS;

			if (zcopy_used) {
				if (vq->heads[ubuf->desc].len == VHOST_DMA_IN_PROGRESS)
					vhost_net_ubuf_put(ubufs);
				if (retry)
					nvq->upend_idx = ((unsigned)nvq->upend_idx - 1)
						% UIO_MAXIOV;
				else
					vq->heads[ubuf->desc].len = VHOST_DMA_DONE_LEN;
			}
			if (retry) {
				virtqueue_discard_vq_desc(vq, 1);
				vhost_net_enable_vq(net, nvq);
				break;
			}
			pr_debug("Fail to send packet: err %d", err);
		} else if (unlikely(err != len))
			pr_debug("Truncated TX packet: "
				 " len %d != %zd\n", err, len);
		if (!zcopy_used)
			virtqueue_add_used_and_signal(vq, head, 0);
		else
			vhost_zerocopy_signal_used(net, nvq);
		vhost_net_tx_packet(net);
	} while (likely(!vhost_exceeds_weight(net, vq, ++sent_pkts, total_len)));
}

/* Expects to be always run from workqueue - which acts as
 * read-size critical section for our kind of RCU. */
static void handle_tx(struct vhost_net *net)
{
	struct vhost_net_virtqueue *nvq = &net->vqs[VHOST_NET_VQ_TX];
	struct virtqueue *vq = nvq->vq;
	struct socket *sock;

	TRACE_FUNC_BEGIN();
	mutex_lock_nested(&vq->mutex, VHOST_NET_VQ_TX);
	sock = vq->priv;
	if (!sock)
		goto out;

	virtqueue_disable_cb(vq);
	vhost_net_disable_vq(net, nvq);

	if (vhost_sock_zcopy(sock))
		handle_tx_zerocopy(net, sock);
	else
		handle_tx_copy(net, sock);

out:
	mutex_unlock(&vq->mutex);
	TRACE_FUNC_END();
}

static int peek_head_len(struct vhost_net_virtqueue *rvq, struct sock *sk)
{
	struct sk_buff *head;
	int len = 0;
	unsigned long flags;

	if (rvq->rx_ring)
		return vhost_net_buf_peek(rvq);

	spin_lock_irqsave(&sk->sk_receive_queue.lock, flags);
	head = skb_peek(&sk->sk_receive_queue);
	if (likely(head)) {
		len = head->len;
		if (skb_vlan_tag_present(head))
			len += VLAN_HLEN;
	}

	spin_unlock_irqrestore(&sk->sk_receive_queue.lock, flags);
	return len;
}

static int vhost_net_rx_peek_head_len(struct vhost_net *net, struct sock *sk,
				      bool *busyloop_intr)
{
	struct vhost_net_virtqueue *rnvq = &net->vqs[VHOST_NET_VQ_RX];
	struct vhost_net_virtqueue *tnvq = &net->vqs[VHOST_NET_VQ_TX];
	struct virtqueue *rvq = rnvq->vq;
	struct virtqueue *tvq = tnvq->vq;
	int len = peek_head_len(rnvq, sk);

	if (!len && rvq->busyloop_timeout) {
		/* Flush batched heads first */
		vhost_net_signal_used(rnvq);
		/* Both tx vq and rx socket were polled here */
		vhost_net_busy_poll(net, rvq, tvq, busyloop_intr, true);

		len = peek_head_len(rnvq, sk);
	}

	return len;
}

/* This is a multi-buffer version of vhost_get_desc, that works if
 *	vq has read descriptors only.
 * @vq		- the relevant virtqueue
 * @datalen	- data length we'll be reading
 * @iovcount	- returned count of io vectors we fill
 * @quota       - headcount quota, 1 for big buffer
 *	returns number of buffer heads allocated, negative on error
 */
static int get_rx_bufs(struct virtqueue *vq,
		       struct vring_used_elem *heads,
		       int datalen,
		       unsigned *iovcount,
		       unsigned int quota)
{
	unsigned int out, in;
	int seg = 0;
	int headcount = 0;
	unsigned d;
	int r;
	/* len is always initialized before use since we are always called with
	 * datalen > 0.
	 */
	u32 len;

	while (datalen > 0 && headcount < quota) {
		if (unlikely(seg >= UIO_MAXIOV)) {
			r = -ENOBUFS;
			goto err;
		}
		r = virtqueue_get_vq_desc(vq, vq->iov + seg,
					  ARRAY_SIZE(vq->iov) - seg, &out,
					  &in);
		d = r;
		if (d == ERROR_VRING_NO_BUFF) {
			r = 0;
			goto err;
		}
		if (unlikely(r < 0))
			goto err;
		if (unlikely(out || in <= 0)) {
			pr_err("unexpected descriptor format for RX: "
				"out %d, in %d\n", out, in);
			r = -EINVAL;
			goto err;
		}
		heads[headcount].id = cpu_to_le32(d);
		len = kvec_length(vq->iov + seg, in);
		heads[headcount].len = cpu_to_le32(len);
		datalen -= len;
		++headcount;
		seg += in;
	}
	heads[headcount - 1].len = cpu_to_le32(len + datalen);
	*iovcount = seg;

	/* Detect overrun */
	if (unlikely(datalen > 0)) {
		r = UIO_MAXIOV + 1;
		goto err;
	}
	return headcount;
err:
	virtqueue_discard_vq_desc(vq, headcount);
	return r;
}

/* Expects to be always run from workqueue - which acts as
 * read-size critical section for our kind of RCU. */
static void handle_rx(struct vhost_net *net)
{
	struct vhost_net_virtqueue *nvq = &net->vqs[VHOST_NET_VQ_RX];
	struct virtqueue *vq = nvq->vq;
	unsigned in;
	struct msghdr msg = {
		.msg_name = NULL,
		.msg_namelen = 0,
		.msg_control = NULL, /* FIXME: get and handle RX aux data. */
		.msg_controllen = 0,
		.msg_flags = MSG_DONTWAIT,
	};
	struct virtio_net_hdr hdr = {
		.flags = 0,
		.gso_type = VIRTIO_NET_HDR_GSO_NONE
	};
	size_t total_len = 0;
	int err, mergeable;
	s16 headcount;
	size_t vhost_hlen, sock_hlen;
	size_t vhost_len, sock_len;
	bool busyloop_intr = false;
	struct socket *sock;
	struct iov_iter fixup;
	__virtio16 num_buffers;
	int recv_pkts = 0;

	TRACE_FUNC_BEGIN();
	mutex_lock_nested(&vq->mutex, VHOST_NET_VQ_RX);
	sock = vq->priv;
	if (!sock)
		goto out;

	virtqueue_disable_cb(vq);
	vhost_net_disable_vq(net, nvq);

	vhost_hlen = nvq->vhost_hlen;
	sock_hlen = nvq->sock_hlen;

	mergeable = virtqueue_has_feature(vq, VIRTIO_NET_F_MRG_RXBUF);

	do {
		sock_len = vhost_net_rx_peek_head_len(net, sock->sk,
						      &busyloop_intr);
		if (!sock_len)
			break;
		sock_len += sock_hlen;
		vhost_len = sock_len + vhost_hlen;
		headcount = get_rx_bufs(vq, vq->heads + nvq->done_idx,
					vhost_len, &in,
					likely(mergeable) ? UIO_MAXIOV : 1);
		/* On error, stop handling until the next kick. */
		if (unlikely(headcount < 0))
			goto out;
		/* OK, now we need to know about added descriptors. */
		if (!headcount) {
			if (unlikely(busyloop_intr)) {
				vhost_poll_queue(vq->poll);
			} else if (unlikely(virtqueue_enable_cb(vq))) {
				/* They have slipped one in as we were
				 * doing that: check again. */
				virtqueue_disable_cb(vq);
				continue;
			}
			/* Nothing new?  Wait for eventfd to tell us
			 * they refilled. */
			goto out;
		}
		busyloop_intr = false;
		if (nvq->rx_ring)
			msg.msg_control = vhost_net_buf_consume(&nvq->rxq);
		/* On overrun, truncate and discard */
		if (unlikely(headcount > UIO_MAXIOV)) {
			iov_iter_kvec(&msg.msg_iter, ITER_DEST, vq->iov, 1, 1);
			err = sock->ops->recvmsg(sock, &msg,
						 1, MSG_DONTWAIT | MSG_TRUNC);
			pr_debug("Discarded rx packet: len %zd\n", sock_len);
			continue;
		}
		/* We don't need to be notified again. */
		iov_iter_kvec(&msg.msg_iter, ITER_DEST, vq->iov, in, vhost_len);
		fixup = msg.msg_iter;
		if (unlikely((vhost_hlen))) {
			/* We will supply the header ourselves
			 * TODO: support TSO.
			 */
			iov_iter_advance(&msg.msg_iter, vhost_hlen);
		}
		err = sock->ops->recvmsg(sock, &msg,
					 sock_len, MSG_DONTWAIT | MSG_TRUNC);
		/* Userspace might have consumed the packet meanwhile:
		 * it's not supposed to do this usually, but might be hard
		 * to prevent. Discard data we got (if any) and keep going. */
		if (unlikely(err != sock_len)) {
			pr_debug("Discarded rx packet: "
				 " len %d, expected %zd\n", err, sock_len);
			virtqueue_discard_vq_desc(vq, headcount);
			continue;
		}
		/* Supply virtio_net_hdr if VHOST_NET_F_VIRTIO_NET_HDR */
		if (unlikely(vhost_hlen)) {
			if (copy_to_iter(&hdr, sizeof(hdr),
					 &fixup) != sizeof(hdr)) {
				pr_err("Unable to write vnet_hdr "
				       "at addr %p\n", vq->iov->iov_base);
				goto out;
			}
		} else {
			/* Header came from socket; we'll need to patch
			 * ->num_buffers over if VIRTIO_NET_F_MRG_RXBUF
			 */
			iov_iter_advance(&fixup, sizeof(hdr));
		}
		/* TODO: Should check and handle checksum. */

		num_buffers = cpu_to_le16(headcount);
		if (likely(mergeable) &&
		    copy_to_iter(&num_buffers, sizeof num_buffers,
				 &fixup) != sizeof num_buffers) {
			pr_err("Failed num_buffers write");
			virtqueue_discard_vq_desc(vq, headcount);
			goto out;
		}
		nvq->done_idx += headcount;
		if (nvq->done_idx > VHOST_NET_BATCH)
			vhost_net_signal_used(nvq);
		total_len += vhost_len;
	} while (likely(!vhost_exceeds_weight(net, vq, ++recv_pkts, total_len)));

	if (unlikely(busyloop_intr))
		vhost_poll_queue(vq->poll);
	if (!sock_len)
		vhost_net_enable_vq(net, nvq);
out:
	vhost_net_signal_used(nvq);
	mutex_unlock(&vq->mutex);
	TRACE_FUNC_END();
}

static void handle_tx_kick(struct virtqueue *vq)
{
	struct virtio_device *vdev = vq->vq_dev;
	struct vhost_net *net = vdev->priv;

	TRACE_FUNC_BEGIN();
	vhost_work_queue(net, &net->poll[VHOST_NET_VQ_TX].work);
	TRACE_FUNC_END();
}

static void handle_rx_kick(struct virtqueue *vq)
{
	struct virtio_device *vdev = vq->vq_dev;
	struct vhost_net *net = vdev->priv;

	TRACE_FUNC_BEGIN();
	vhost_work_queue(net, &net->poll[VHOST_NET_VQ_RX].work);
	TRACE_FUNC_END();
}

static void handle_tx_net(struct work_struct *work)
{
	struct vhost_net *net = container_of(work, struct vhost_net,
					     poll[VHOST_NET_VQ_TX].work);

	atomic_dec(&net->pending_work_count);
	TRACE_FUNC_BEGIN();
	handle_tx(net);
	TRACE_FUNC_END();
}

static void handle_rx_net(struct work_struct *work)
{
	struct vhost_net *net = container_of(work, struct vhost_net,
					     poll[VHOST_NET_VQ_RX].work);

	atomic_dec(&net->pending_work_count);
	TRACE_FUNC_BEGIN();
	handle_rx(net);
	TRACE_FUNC_END();
}

static int vhost_net_open(struct inode *inode, struct file *f)
{
	return 0;
}

static struct socket *vhost_net_stop_vq(struct vhost_net *n,
					struct vhost_net_virtqueue *nvq)
{
	struct socket *sock;
	struct virtqueue *vq = nvq->vq;

	mutex_lock(&vq->mutex);
	sock = vq->priv;
	vhost_net_disable_vq(n, nvq);
	vq->priv = NULL;
	vhost_net_buf_unproduce(nvq);
	nvq->rx_ring = NULL;
	mutex_unlock(&vq->mutex);
	return sock;
}

static void vhost_net_stop(struct vhost_net *n, struct socket **tx_sock,
			   struct socket **rx_sock)
{
	*tx_sock = vhost_net_stop_vq(n, &n->vqs[VHOST_NET_VQ_TX]);
	*rx_sock = vhost_net_stop_vq(n, &n->vqs[VHOST_NET_VQ_RX]);
}

static void vhost_net_flush(struct vhost_net *n)
{
	vhost_dev_flush(n);
	if (n->vqs[VHOST_NET_VQ_TX].ubufs) {
		mutex_lock(&n->vqs[VHOST_NET_VQ_TX].vq->mutex);
		n->tx_flush = true;
		mutex_unlock(&n->vqs[VHOST_NET_VQ_TX].vq->mutex);
		/* Wait for all lower device DMAs done. */
		vhost_net_ubuf_put_and_wait(n->vqs[VHOST_NET_VQ_TX].ubufs);
		mutex_lock(&n->vqs[VHOST_NET_VQ_TX].vq->mutex);
		n->tx_flush = false;
		atomic_set(&n->vqs[VHOST_NET_VQ_TX].ubufs->refcount, 1);
		mutex_unlock(&n->vqs[VHOST_NET_VQ_TX].vq->mutex);
	}
}

static int vhost_net_release(struct inode *inode, struct file *f)
{
	return 0;
}

static struct socket *get_raw_socket(int fd)
{
	int r;
	struct socket *sock = sockfd_lookup(fd, &r);

	if (!sock)
		return ERR_PTR(-ENOTSOCK);

	/* Parameter checking */
	if (sock->sk->sk_type != SOCK_RAW) {
		r = -ESOCKTNOSUPPORT;
		goto err;
	}

	if (sock->sk->sk_family != AF_PACKET) {
		r = -EPFNOSUPPORT;
		goto err;
	}
	return sock;
err:
	sockfd_put(sock);
	return ERR_PTR(r);
}

static struct ptr_ring *get_tap_ptr_ring(struct file *file)
{
	struct ptr_ring *ring;
	ring = tun_get_tx_ring(file);
	if (!IS_ERR(ring))
		goto out;
	ring = tap_get_ptr_ring(file);
	if (!IS_ERR(ring))
		goto out;
	ring = NULL;
out:
	return ring;
}

static struct socket *get_tap_socket(int fd)
{
	struct file *file = fget(fd);
	struct socket *sock;

	if (!file)
		return ERR_PTR(-EBADF);
	sock = tun_get_socket(file);
	if (!IS_ERR(sock))
		return sock;
	sock = tap_get_socket(file);
	if (IS_ERR(sock))
		fput(file);
	return sock;
}

static struct socket *get_socket(int fd)
{
	struct socket *sock;

	/* special case to disable backend */
	if (fd == -1)
		return NULL;
	sock = get_raw_socket(fd);
	if (!IS_ERR(sock))
		return sock;
	sock = get_tap_socket(fd);
	if (!IS_ERR(sock))
		return sock;
	return ERR_PTR(-ENOTSOCK);
}

static long vhost_net_set_backend(struct vhost_net *n, int index, struct socket *sock)
{
	struct socket *oldsock;
	struct virtqueue *vq;
	struct vhost_net_virtqueue *nvq;
	struct vhost_net_ubuf_ref *ubufs, *oldubufs = NULL;
	int r;

	mutex_lock(&n->mutex);

	if (index >= VHOST_NET_VQ_MAX) {
		r = -ENOBUFS;
		goto err;
	}
	vq = n->vqs[index].vq;
	nvq = &n->vqs[index];
	mutex_lock(&vq->mutex);

	/* start polling new socket */
	oldsock = vq->priv;
	if (sock != oldsock) {
		ubufs = vhost_net_ubuf_alloc(vq,
					     sock && vhost_sock_zcopy(sock));
		if (IS_ERR(ubufs)) {
			r = PTR_ERR(ubufs);
			goto err_ubufs;
		}

		vhost_net_disable_vq(n, nvq);
		vq->priv = sock;
		vhost_net_buf_unproduce(nvq);

		r = vhost_net_enable_vq(n, nvq);
		if (r)
			goto err_used;
		if (index == VHOST_NET_VQ_RX) {
			if (sock)
				nvq->rx_ring = get_tap_ptr_ring(sock->file);
			else
				nvq->rx_ring = NULL;
		}

		oldubufs = nvq->ubufs;
		nvq->ubufs = ubufs;

		n->tx_packets = 0;
		n->tx_zcopy_err = 0;
		n->tx_flush = false;
	}

	mutex_unlock(&vq->mutex);

	if (oldubufs) {
		vhost_net_ubuf_put_wait_and_free(oldubufs);
		mutex_lock(&vq->mutex);
		vhost_zerocopy_signal_used(n, nvq);
		mutex_unlock(&vq->mutex);
	}

	if (oldsock) {
		vhost_dev_flush(n);
		sockfd_put(oldsock);
	}

	mutex_unlock(&n->mutex);
	return 0;

err_used:
	vq->priv = oldsock;
	vhost_net_enable_vq(n, nvq);
	if (ubufs)
		vhost_net_ubuf_put_wait_and_free(ubufs);
err_ubufs:
	if (sock)
		sockfd_put(sock);
	mutex_unlock(&vq->mutex);
err:
	mutex_unlock(&n->mutex);
	return r;
}

static int vhost_net_set_features(struct vhost_net *n, u64 features)
{
	size_t vhost_hlen, sock_hlen, hdr_len;
	int i;

	hdr_len = features & (1ULL << VIRTIO_NET_F_MRG_RXBUF) ?
			sizeof(struct virtio_net_hdr_mrg_rxbuf) :
			sizeof(struct virtio_net_hdr);
	if (features & (1 << VHOST_NET_F_VIRTIO_NET_HDR)) {
		/* vhost provides vnet_hdr */
		vhost_hlen = hdr_len;
		sock_hlen = 0;
	} else {
		/* socket provides vnet_hdr */
		vhost_hlen = 0;
		sock_hlen = hdr_len;
	}
	mutex_lock(&n->mutex);

	for (i = 0; i < VHOST_NET_VQ_MAX; ++i) {
		mutex_lock(&n->vqs[i].vq->mutex);
		// n->vqs[i].vq.acked_features = features;
		n->vqs[i].vhost_hlen = vhost_hlen;
		n->vqs[i].sock_hlen = sock_hlen;
		mutex_unlock(&n->vqs[i].vq->mutex);
	}
	mutex_unlock(&n->mutex);
	return 0;
}

struct vhost_vring_file {
	unsigned int index;
	int fd; /* Pass -1 to unbind from file. */

};

#define VHOST_VIRTIO 0xAF
#define VHOST_NET_SET_BACKEND _IOW(VHOST_VIRTIO, 0x30, struct vhost_vring_file)

static long vhost_net_ioctl(struct file *f, unsigned int ioctl,
			    unsigned long arg)
{
	void __user *argp = (void __user *)arg;
	struct vhost_vring_file backend;
	struct socket *sock;

	switch (ioctl) {
	case VHOST_NET_SET_BACKEND:
		if (copy_from_user(&backend, argp, sizeof backend))
			return -EFAULT;

		if (backend.index > VHOST_NET_VQ_MAX)
			return -EINVAL;
		sock = get_socket(backend.fd);
		if (IS_ERR(sock)) {
			pr_err("failed to get socket, ret=%ld\n", PTR_ERR(sock));
			return PTR_ERR(sock);
		}
		s_backend_socks[backend.index] = sock;
		return 0;
	default:
		return -ENOIOCTLCMD;
	}
}

static const struct file_operations vhost_net_fops = {
	.owner          = THIS_MODULE,
	.release        = vhost_net_release,
	.unlocked_ioctl = vhost_net_ioctl,
	.compat_ioctl   = compat_ptr_ioctl,
	.open           = vhost_net_open,
};

static struct miscdevice vhost_net_misc = {
	.minor = RPROC_NET_MINOR,
	.name = "rproc-net",
	.fops = &vhost_net_fops,
};

#define WAIT_STATE_TIMEOUT_MSEC 60000

static bool wait_for_backend_socks(void)
{
	unsigned long timeout =
	    jiffies + msecs_to_jiffies(WAIT_STATE_TIMEOUT_MSEC);

	do
	{
		if (s_backend_socks[VHOST_NET_VQ_RX] != NULL &&
		    s_backend_socks[VHOST_NET_VQ_TX] != NULL)
			return false;

		mdelay(1);
	} while (time_before(jiffies, timeout));

	return true;
}

static int vhost_net_device_create(struct virtio_device *vdev,
			    	   struct metal_io_region *shm_io) {
	struct vhost_net *n;
	void **queue;
	struct xdp_buff *xdp;
	int i, ret, vq_err;
	const char *vq_names[VHOST_NET_VQ_MAX];
	vq_callback callback[VHOST_NET_VQ_MAX];
	bool timeout;

	timeout = wait_for_backend_socks();
	if (timeout) {
		pr_err("timeout waiting for backend socks\n");
		return -EINVAL;
	}

	n = kvmalloc(sizeof *n, GFP_KERNEL | __GFP_RETRY_MAYFAIL);
	if (!n)
		return -ENOMEM;

	queue = kmalloc_array(VHOST_NET_BATCH, sizeof(void *),
			      GFP_KERNEL);
	if (!queue) {
		kvfree(n);
		return -ENOMEM;
	}
	n->vqs[VHOST_NET_VQ_RX].rxq.queue = queue;

	xdp = kmalloc_array(VHOST_NET_BATCH, sizeof(*xdp), GFP_KERNEL);
	if (!xdp) {
		kvfree(n);
		kfree(queue);
		return -ENOMEM;
	}
	n->vqs[VHOST_NET_VQ_TX].xdp = xdp;

	n->workq = alloc_workqueue("rproc_net",
				    WQ_MEM_RECLAIM | WQ_HIGHPRI | WQ_UNBOUND, 1);
	if (!n->workq) {
		ret = -ENOMEM;
		goto err_free_vhost_net;
	}

	vq_names[0] = "rx_vq";
	vq_names[1] = "tx_vq";
	callback[0] = handle_rx_kick;
	callback[1] = handle_tx_kick;
	vq_err = virtio_create_virtqueues(vdev, 0, VHOST_NET_VQ_MAX, vq_names,
					  callback, NULL);
	if (vq_err != VQUEUE_SUCCESS) {
		pr_err("failed to create virtqueue, err=%d\n", vq_err);
		ret = -EIO;
		goto err_destroy_workq;
	}

	ret = vhost_net_set_ubuf_info(n);
	if (ret) {
		goto err_release_virtqueues;
	}

	for (i = 0; i < VHOST_NET_VQ_MAX; i++) {
		struct virtqueue *vq = vdev->vrings_info[i].vq;
		vq->shm_io = shm_io;
		vq->poll = &n->poll[i];
		n->vqs[i].vq = vq;

		n->vqs[i].ubufs = NULL;
		n->vqs[i].ubuf_info = NULL;
		n->vqs[i].upend_idx = 0;
		n->vqs[i].done_idx = 0;
		n->vqs[i].batched_xdp = 0;
		n->vqs[i].vhost_hlen = 0;
		n->vqs[i].sock_hlen = 0;
		n->vqs[i].rx_ring = NULL;
		vhost_net_buf_init(&n->vqs[i].rxq);
	}

	vhost_poll_init(n->poll + VHOST_NET_VQ_TX, handle_tx_net, EPOLLOUT, n);
	vhost_poll_init(n->poll + VHOST_NET_VQ_RX, handle_rx_net, EPOLLIN, n);
	mutex_init(&n->mutex);

	n->page_frag.page = NULL;
	n->refcnt_bias = 0;
	n->byte_weight = VHOST_NET_WEIGHT;
	n->weight = VHOST_NET_PKT_WEIGHT;
	atomic_set(&n->pending_work_count, 0);

	vdev->priv = n;

	vhost_net_set_backend(n, VHOST_NET_VQ_TX, s_backend_socks[VHOST_NET_VQ_TX]);
	vhost_net_set_backend(n, VHOST_NET_VQ_RX, s_backend_socks[VHOST_NET_VQ_RX]);
	vhost_net_set_features(n, vdev->features);

	return 0;

err_release_virtqueues:
	virtio_delete_virtqueues(vdev);
err_destroy_workq:
	destroy_workqueue(n->workq);
err_free_vhost_net:
	kvfree(n);
	kfree(queue);

	return ret;
}

static void vhost_net_device_destroy(struct virtio_device *vdev)
{
	struct vhost_net *n = vdev->priv;
	struct socket *tx_sock;
	struct socket *rx_sock;

	vhost_net_stop(n, &tx_sock, &rx_sock);
	vhost_net_flush(n);
	vhost_dev_stop(n);
	vhost_net_vq_reset(n);

	/* Make sure no callbacks are outstanding */
	synchronize_rcu();
	/* We do an extra flush before freeing memory,
	 * since jobs can re-queue themselves. */
	vhost_net_flush(n);
	kfree(n->vqs[VHOST_NET_VQ_RX].rxq.queue);
	kfree(n->vqs[VHOST_NET_VQ_TX].xdp);
	if (n->page_frag.page)
		__page_frag_cache_drain(n->page_frag.page, n->refcnt_bias);
	kvfree(n);
}

static void vhost_net_device_reset(struct virtio_device *vdev)
{
}

static struct nebula_rproc_vdev_ops vhost_net_vdev_ops = {
	.on_create = vhost_net_device_create,
	.on_destroy = vhost_net_device_destroy,
	.on_reset = vhost_net_device_reset,
};

static int __init vhost_net_init(void)
{
	int ret;

	if (experimental_zcopytx)
		vhost_net_enable_zcopy(VHOST_NET_VQ_TX);

	ret = misc_register(&vhost_net_misc);
	if (ret)
		return ret;

	nebula_rproc_register_device(&vhost_net_vdev_desc,
				     sizeof(vhost_net_vdev_desc),
				     &vhost_net_vdev_ops);
	return 0;
}
module_init(vhost_net_init);

MODULE_VERSION("0.0.1");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Michael S. Tsirkin");
MODULE_DESCRIPTION("Host kernel accelerator for virtio net");
MODULE_ALIAS_MISCDEV(RPROC_NET_MINOR);
MODULE_ALIAS("devname:vhost-net");
