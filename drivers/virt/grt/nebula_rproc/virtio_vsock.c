// SPDX-License-Identifier: GPL-2.0-only
/*
 * vhost transport for vsock
 *
 * Copyright (C) 2013-2015 Red Hat, Inc.
 * Author: Asias He <asias@redhat.com>
 *         Stefan Hajnoczi <stefanha@redhat.com>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "../af_vsockx/rename_symbols.h"

#include <linux/module.h>
#include <linux/of_platform.h>
#include <linux/delay.h>
#include <linux/sched/clock.h>

#include "nebula_rproc_remote.h"
#include "remoteproc_virtio.h"
#include "virtqueue.h"
#include "virtio.h"
#include "virtio_vsock.h"

#define VIRTIO_ID_VSOCKX 0x81

#define VHOST_VSOCK_DEFAULT_HOST_CID 2

/* Resource table entries */
#define VRING_ALIGN 0x1000
#define VRING_SIZE  256

static void vsock_tx_callback(struct virtqueue *vq);

static inline size_t kvec_length(const struct kvec *iov, unsigned long nr_segs)
{
	unsigned long seg;
	size_t ret = 0;

	for (seg = 0; seg < nr_segs; seg++)
		ret += iov[seg].iov_len;
	return ret;
}

struct virtio_vsock_config {
	__le64 guest_cid;
} __packed;

struct vsock_device_descriptor {
	struct fw_rsc_vdev vdev;
	struct fw_rsc_vdev_vring vrings[VSOCK_VQ_MAX];
	struct virtio_vsock_config config;
} __packed;

static const struct vsock_device_descriptor vsock_vdev_desc = {
	.vdev		= {
		.type		= RSC_VDEV,
		.id		= VIRTIO_ID_VSOCKX,
		.dfeatures	= 0,
		.config_len	= sizeof(struct virtio_vsock_config),
		.num_of_vrings	= VSOCK_VQ_MAX,
	},
	.vrings	= {
		[VSOCK_VQ_RX]	= {
			.da		= FW_RSC_U32_ADDR_ANY,
			.align		= VRING_ALIGN,
			.num		= VRING_SIZE,
		},
		[VSOCK_VQ_TX]	= {
			.da		= FW_RSC_U32_ADDR_ANY,
			.align		= VRING_ALIGN,
			.num		= VRING_SIZE,
		},
	},
	.config = {
		.guest_cid = 4,
	}
};

/* Used to track all the vhost_vsock instances on the system. */
static DEFINE_MUTEX(vhost_vsock_mutex);
static DEFINE_READ_MOSTLY_HASHTABLE(vhost_vsock_hash, 8);

struct vhost_vsock {
	struct virtqueue *vqs[VSOCK_VQ_MAX];

	/* Link to global vhost_vsock_hash, writes use vhost_vsock_mutex */
	struct hlist_node hash;

	struct work_struct send_pkt_work;
	spinlock_t send_pkt_list_lock;
	struct sk_buff_head send_pkt_queue; /* host->guest pending packets */

	atomic_t queued_replies;

	u32 guest_cid;
	bool seqpacket_allow;

	struct workqueue_struct *workq;
};

static u32 vhost_transport_get_local_cid(void)
{
	return VHOST_VSOCK_DEFAULT_HOST_CID;
}

/* Callers that dereference the return value must hold vhost_vsock_mutex or the
 * RCU read lock.
 */
static struct vhost_vsock *vhost_vsock_get(u32 guest_cid)
{
	struct vhost_vsock *vsock;

	hash_for_each_possible_rcu(vhost_vsock_hash, vsock, hash, guest_cid) {
		u32 other_cid = vsock->guest_cid;

		/* Skip instances that have no CID yet */
		if (other_cid == 0)
			continue;

		if (other_cid == guest_cid)
			return vsock;
	}

	return NULL;
}

static void vhost_transport_do_send_pkt(struct vhost_vsock *vsock,
					struct virtqueue *vq)
{
	struct virtqueue *tx_vq = vsock->vqs[VSOCK_VQ_TX];
	int total_len = 0;
	bool added = false;
	bool restart_tx = false;

	mutex_lock(&vq->mutex);

	/* Avoid further vmexits, we're already processing the virtqueue */
	virtqueue_disable_cb(vq);

	do {
		struct virtio_vsock_hdr *hdr;
		size_t iov_len, payload_len;
		struct iov_iter iov_iter;
		u32 flags_to_restore = 0;
		struct sk_buff *skb;
		unsigned out, in;
		size_t nbytes;
		int head;
		struct kvec iov[8];

		skb = virtio_vsock_skb_dequeue(&vsock->send_pkt_queue);

		if (!skb) {
			virtqueue_enable_cb(vq);
			break;
		}

		head = virtqueue_get_vq_desc(vq, iov, ARRAY_SIZE(iov), &out,
					     &in);
		if (head == ERROR_VRING_NO_BUFF) {
			virtio_vsock_skb_queue_head(&vsock->send_pkt_queue,
						    skb);
			/* We cannot finish yet if more buffers snuck in while
			 * re-enabling notify.
			 */
			if (unlikely(virtqueue_enable_cb(vq))) {
				virtqueue_disable_cb(vq);
				continue;
			}
			break;
		}

		if (head < 0) {
			pr_err("RX_VQ: failed to get ring desc: %d\n", head);
			virtio_vsock_skb_queue_head(&vsock->send_pkt_queue,
						    skb);
			break;
		}

		pr_debug("RX_VQ: head=%d, out=%d,in=%d\n", head, out, in);
		if (out) {
			kfree_skb(skb);
			pr_err("Expected 0 output buffers, got %u\n", out);
			break;
		}

		iov_len = kvec_length(&iov[out], in);
		if (iov_len < sizeof(*hdr)) {
			kfree_skb(skb);
			pr_err("Buffer len [%zu] too small\n", iov_len);
			break;
		}

		iov_iter_kvec(&iov_iter, ITER_DEST, &iov[out], in, iov_len);
		payload_len = skb->len;
		hdr = virtio_vsock_hdr(skb);

		/* If the packet is greater than the space available in the
		 * buffer, we split it using multiple buffers.
		 */
		if (payload_len > iov_len - sizeof(*hdr)) {
			payload_len = iov_len - sizeof(*hdr);

			/* As we are copying pieces of large packet's buffer to
			 * small rx buffers, headers of packets in rx queue are
			 * created dynamically and are initialized with header
			 * of current packet(except length). But in case of
			 * SOCK_SEQPACKET, we also must clear message delimeter
			 * bit (VIRTIO_VSOCK_SEQ_EOM) and MSG_EOR bit
			 * (VIRTIO_VSOCK_SEQ_EOR) if set. Otherwise,
			 * there will be sequence of packets with these
			 * bits set. After initialized header will be copied to
			 * rx buffer, these required bits will be restored.
			 */
			if (le32_to_cpu(hdr->flags) & VIRTIO_VSOCK_SEQ_EOM) {
				hdr->flags &=
					~cpu_to_le32(VIRTIO_VSOCK_SEQ_EOM);
				flags_to_restore |= VIRTIO_VSOCK_SEQ_EOM;

				if (le32_to_cpu(hdr->flags) &
				    VIRTIO_VSOCK_SEQ_EOR) {
					hdr->flags &= ~cpu_to_le32(
						VIRTIO_VSOCK_SEQ_EOR);
					flags_to_restore |=
						VIRTIO_VSOCK_SEQ_EOR;
				}
			}
		}

		/* Set the correct length in the header */
		hdr->len = cpu_to_le32(payload_len);

		nbytes = copy_to_iter(hdr, sizeof(*hdr), &iov_iter);
		if (nbytes != sizeof(*hdr)) {
			kfree_skb(skb);
			pr_err("Faulted on copying pkt hdr\n");
			break;
		}

		nbytes = copy_to_iter(skb->data, payload_len, &iov_iter);
		if (nbytes != payload_len) {
			kfree_skb(skb);
			pr_err("Faulted on copying pkt buf\n");
			break;
		}

		/* Deliver to monitoring devices all packets that we
		 * will transmit.
		 */
		virtio_transport_deliver_tap_pkt(skb);

		pr_debug("sent %ld bytes\n", sizeof(*hdr) + payload_len);
		virtqueue_add_consumed_buffer(vq, head,
					      sizeof(*hdr) + payload_len);
		added = true;

		skb_pull(skb, payload_len);
		total_len += payload_len;

		/* If we didn't send all the payload we can requeue the packet
		 * to send it with the next available buffer.
		 */
		if (skb->len > 0) {
			hdr->flags |= cpu_to_le32(flags_to_restore);

			/* We are queueing the same skb to handle
			 * the remaining bytes, and we want to deliver it
			 * to monitoring devices in the next iteration.
			 */
			virtio_vsock_skb_clear_tap_delivered(skb);
			virtio_vsock_skb_queue_head(&vsock->send_pkt_queue,
						    skb);
		} else {
			if (virtio_vsock_skb_reply(skb)) {
				int val;

				val = atomic_dec_return(&vsock->queued_replies);

				/* Do we have resources to resume tx
				 * processing?
				 */
				if (val + 1 == tx_vq->vq_nentries) {
					pr_debug("need to restart tx\n");
					restart_tx = true;
				}
			}

			consume_skb(skb);
		}
	} while (true);
	if (added)
		virtqueue_kick(vq);

	mutex_unlock(&vq->mutex);

	if (restart_tx)
		vsock_tx_callback(tx_vq);
}

static void vhost_transport_send_pkt_work(struct work_struct *work)
{
	struct virtqueue *vq;
	struct vhost_vsock *vsock;

	vsock = container_of(work, struct vhost_vsock, send_pkt_work);
	vq = vsock->vqs[VSOCK_VQ_RX];

	vhost_transport_do_send_pkt(vsock, vq);
}

static int vhost_transport_send_pkt(struct sk_buff *skb)
{
	struct virtio_vsock_hdr *hdr = virtio_vsock_hdr(skb);
	struct vhost_vsock *vsock;
	int len = skb->len;

	rcu_read_lock();

	/* Find the vhost_vsock according to guest context id  */
	vsock = vhost_vsock_get(le64_to_cpu(hdr->dst_cid));
	if (!vsock) {
		rcu_read_unlock();
		kfree_skb(skb);
		return -ENODEV;
	}

	if (virtio_vsock_skb_reply(skb))
		atomic_inc(&vsock->queued_replies);

	virtio_vsock_skb_queue_tail(&vsock->send_pkt_queue, skb);
	queue_work(vsock->workq, &vsock->send_pkt_work);

	rcu_read_unlock();
	return len;
}

static int vhost_transport_cancel_pkt(struct vsock_sock *vsk)
{
	struct vhost_vsock *vsock;
	int cnt = 0;
	int ret = -ENODEV;

	rcu_read_lock();

	/* Find the vhost_vsock according to guest context id  */
	vsock = vhost_vsock_get(vsk->remote_addr.svm_cid);
	if (!vsock)
		goto out;

	cnt = virtio_transport_purge_skbs(vsk, &vsock->send_pkt_queue);

	if (cnt) {
		struct virtqueue *tx_vq = vsock->vqs[VSOCK_VQ_TX];
		int new_cnt;

		new_cnt = atomic_sub_return(cnt, &vsock->queued_replies);
		if (new_cnt + cnt >= tx_vq->vq_nentries && new_cnt < tx_vq->vq_nentries)
			// vhost_poll_queue(&tx_vq->poll);
			queue_work(vsock->workq, &vsock->send_pkt_work);
	}

	ret = 0;
out:
	rcu_read_unlock();
	return ret;
}

static struct sk_buff *vhost_vsock_alloc_skb(struct virtqueue *vq,
					     struct kvec *iov,
					     unsigned int out, unsigned int in)
{
	struct virtio_vsock_hdr *hdr;
	struct iov_iter iov_iter;
	struct sk_buff *skb;
	size_t payload_len;
	size_t nbytes;
	size_t len;

	if (in != 0) {
		pr_err("Expected 0 input buffers, got %u\n", in);
		return NULL;
	}

	len = kvec_length(iov, out);

	/* len contains both payload and hdr */
	skb = virtio_vsock_alloc_skb(len, GFP_KERNEL);
	if (!skb)
		return NULL;

	iov_iter_kvec(&iov_iter, ITER_SOURCE, iov, out, len);

	hdr = virtio_vsock_hdr(skb);
	nbytes = copy_from_iter(hdr, sizeof(*hdr), &iov_iter);
	if (nbytes != sizeof(*hdr)) {
		pr_err("Expected %zu bytes for pkt->hdr, got %zu bytes\n",
		       sizeof(*hdr), nbytes);
		kfree_skb(skb);
		return NULL;
	}

	payload_len = le32_to_cpu(hdr->len);

	/* No payload */
	if (!payload_len)
		return skb;

	/* The pkt is too big or the length in the header is invalid */
	if (payload_len > VIRTIO_VSOCK_MAX_PKT_BUF_SIZE ||
	    payload_len + sizeof(*hdr) > len) {
		kfree_skb(skb);
		return NULL;
	}

	virtio_vsock_skb_rx_put(skb);

	nbytes = copy_from_iter(skb->data, payload_len, &iov_iter);
	if (nbytes != payload_len) {
		pr_err("Expected %zu byte payload, got %zu bytes\n",
		       payload_len, nbytes);
		kfree_skb(skb);
		return NULL;
	}

	return skb;
}

/* Is there space left for replies to rx packets? */
static bool vhost_vsock_more_replies(struct vhost_vsock *vsock)
{
	struct virtqueue *vq = vsock->vqs[VSOCK_VQ_TX];
	int val;

	smp_rmb(); /* paired with atomic_inc() and atomic_dec_return() */
	val = atomic_read(&vsock->queued_replies);

	return val < vq->vq_nentries;
}

static bool vhost_transport_seqpacket_allow(u32 remote_cid);

static struct virtio_transport vhost_transport = {
	.transport = {
		.module                   = THIS_MODULE,

		.get_local_cid            = vhost_transport_get_local_cid,

		.init                     = virtio_transport_do_socket_init,
		.destruct                 = virtio_transport_destruct,
		.release                  = virtio_transport_release,
		.connect                  = virtio_transport_connect,
		.shutdown                 = virtio_transport_shutdown,
		.cancel_pkt               = vhost_transport_cancel_pkt,

		.dgram_enqueue            = virtio_transport_dgram_enqueue,
		.dgram_dequeue            = virtio_transport_dgram_dequeue,
		.dgram_bind               = virtio_transport_dgram_bind,
		.dgram_allow              = virtio_transport_dgram_allow,

		.stream_enqueue           = virtio_transport_stream_enqueue,
		.stream_dequeue           = virtio_transport_stream_dequeue,
		.stream_has_data          = virtio_transport_stream_has_data,
		.stream_has_space         = virtio_transport_stream_has_space,
		.stream_rcvhiwat          = virtio_transport_stream_rcvhiwat,
		.stream_is_active         = virtio_transport_stream_is_active,
		.stream_allow             = virtio_transport_stream_allow,

		.seqpacket_dequeue        = virtio_transport_seqpacket_dequeue,
		.seqpacket_enqueue        = virtio_transport_seqpacket_enqueue,
		.seqpacket_allow          = vhost_transport_seqpacket_allow,
		.seqpacket_has_data       = virtio_transport_seqpacket_has_data,

		.notify_poll_in           = virtio_transport_notify_poll_in,
		.notify_poll_out          = virtio_transport_notify_poll_out,
		.notify_recv_init         = virtio_transport_notify_recv_init,
		.notify_recv_pre_block    = virtio_transport_notify_recv_pre_block,
		.notify_recv_pre_dequeue  = virtio_transport_notify_recv_pre_dequeue,
		.notify_recv_post_dequeue = virtio_transport_notify_recv_post_dequeue,
		.notify_send_init         = virtio_transport_notify_send_init,
		.notify_send_pre_block    = virtio_transport_notify_send_pre_block,
		.notify_send_pre_enqueue  = virtio_transport_notify_send_pre_enqueue,
		.notify_send_post_enqueue = virtio_transport_notify_send_post_enqueue,
		.notify_buffer_size       = virtio_transport_notify_buffer_size,
		.notify_set_rcvlowat      = virtio_transport_notify_set_rcvlowat,

		.read_skb = virtio_transport_read_skb,
	},

	.send_pkt = vhost_transport_send_pkt,
};

static bool vhost_transport_seqpacket_allow(u32 remote_cid)
{
	struct vhost_vsock *vsock;
	bool seqpacket_allow = false;

	rcu_read_lock();
	vsock = vhost_vsock_get(remote_cid);

	if (vsock)
		seqpacket_allow = vsock->seqpacket_allow;

	rcu_read_unlock();

	return seqpacket_allow;
}

static void vsock_tx_callback(struct virtqueue *vq)
{
	struct vhost_vsock *vsock = vq->priv;
	int head, total_len = 0;
	unsigned int out, in;
	struct sk_buff *skb;
	bool added = false;

	// mutex_lock(&vq->mutex);

	virtqueue_disable_cb(vq);
	do {
		struct virtio_vsock_hdr *hdr;
		struct kvec iov[8];

		if (!vhost_vsock_more_replies(vsock)) {
			/* Stop tx until the device processes already
			 * pending replies.  Leave tx virtqueue
			 * callbacks disabled.
			 */
			goto no_more_replies;
		}

		head = virtqueue_get_vq_desc(vq, iov, ARRAY_SIZE(iov), &out,
					     &in);
		if (head == ERROR_VRING_NO_BUFF) {
			if (unlikely(virtqueue_enable_cb(vq))) {
				virtqueue_disable_cb(vq);
				continue;
			}
			break;
		}

		if (head < 0) {
			pr_err("TX_VQ: failed to get ring desc: %d\n", head);
			break;
		}

		pr_debug("TX_VQ: head=%d, out=%d,in=%d\n", head, out, in);
		skb = vhost_vsock_alloc_skb(vq, iov, out, in);
		if (!skb) {
			pr_err("Faulted on pkt\n");
			continue;
		}

		total_len += sizeof(*hdr) + skb->len;

		/* Deliver to monitoring devices all received packets */
		virtio_transport_deliver_tap_pkt(skb);

		hdr = virtio_vsock_hdr(skb);

		/* Only accept correctly addressed packets */
		if (le64_to_cpu(hdr->src_cid) == vsock->guest_cid &&
		    le64_to_cpu(hdr->dst_cid) ==
			    vhost_transport_get_local_cid())
			virtio_transport_recv_pkt(&vhost_transport, skb);
		else
			kfree_skb(skb);

		virtqueue_add_consumed_buffer(vq, head, 0);
		added = true;
	} while (true);

no_more_replies:
	if (added)
		virtqueue_kick(vq);

	// mutex_unlock(&vq->mutex);
}

static void vsock_rx_callback(struct virtqueue *vq)
{
	struct vhost_vsock *vsock = vq->priv;

	vhost_transport_do_send_pkt(vsock, vq);
}

static int vhost_vsock_set_cid(struct vhost_vsock *vsock, u64 guest_cid)
{
	struct vhost_vsock *other;

	/* Refuse reserved CIDs */
	if (guest_cid <= VMADDR_CID_HOST || guest_cid == U32_MAX)
		return -EINVAL;

	/* 64-bit CIDs are not yet supported */
	if (guest_cid > U32_MAX)
		return -EINVAL;

	/* Refuse if CID is assigned to the guest->host transport (i.e. nested
	 * VM), to make the loopback work.
	 */
	if (vsock_find_cid(guest_cid))
		return -EADDRINUSE;

	/* Refuse if CID is already in use */
	mutex_lock(&vhost_vsock_mutex);
	other = vhost_vsock_get(guest_cid);
	if (other && other != vsock) {
		mutex_unlock(&vhost_vsock_mutex);
		return -EADDRINUSE;
	}

	if (vsock->guest_cid)
		hash_del_rcu(&vsock->hash);

	vsock->guest_cid = guest_cid;
	hash_add_rcu(vhost_vsock_hash, &vsock->hash, vsock->guest_cid);
	mutex_unlock(&vhost_vsock_mutex);

	return 0;
}

int vsock_device_create(struct virtio_device *vdev,
			struct metal_io_region *shm_io)
{
	const char *vq_names[VSOCK_VQ_MAX];
	vq_callback callback[VSOCK_VQ_MAX];
	int vq_err, ret;
	unsigned int i;

	struct vhost_vsock *vsock =
		kzalloc(sizeof(struct vhost_vsock), GFP_KERNEL);
	if (!vsock)
		return -ENOMEM;

	vsock->workq = alloc_workqueue("virtio_vsock", WQ_MEM_RECLAIM|WQ_HIGHPRI, 1);
	if (!vsock->workq) {
		ret = -ENOMEM;
		goto err_free_vsock;
	}

	vq_names[0] = "rx_vq";
	vq_names[1] = "tx_vq";
	callback[0] = vsock_rx_callback;
	callback[1] = vsock_tx_callback;

	/* Create virtqueues for remote device */
	vq_err = virtio_create_virtqueues(vdev, 0, VSOCK_VQ_MAX, vq_names,
					  callback, NULL);
	if (vq_err != VQUEUE_SUCCESS) {
		pr_err("failed to create virtqueue, err=%d\n", vq_err);
		ret = -EIO;
		goto err_release_workq;
	}

	vsock->guest_cid = vsock_vdev_desc.config.guest_cid;
	ret = vhost_vsock_set_cid(vsock, vsock->guest_cid);
	if (ret) {
		goto err_release_virtqueues;
	}

	for (i = 0; i < VSOCK_VQ_MAX; i++) {
		struct virtqueue *vq;

		vq = vdev->vrings_info[i].vq;
		vq->shm_io = shm_io;
		vq->priv = vsock;

		vsock->vqs[i] = vq;
	}

	atomic_set(&vsock->queued_replies, 0);

	spin_lock_init(&vsock->send_pkt_list_lock);
	skb_queue_head_init(&vsock->send_pkt_queue);
	INIT_WORK(&vsock->send_pkt_work, vhost_transport_send_pkt_work);

	vdev->priv = vsock;

	/* Some packets may have been queued before the device was started,
	 * let's kick the send worker to send them.
	 */
	queue_work(vsock->workq, &vsock->send_pkt_work);

	return 0;

err_release_virtqueues:
	virtio_delete_virtqueues(vdev);
err_release_workq:
	destroy_workqueue(vsock->workq);
err_free_vsock:
	kfree(vsock);
	return ret;
}

static void vhost_vsock_reset_orphans(struct sock *sk)
{
	struct vsock_sock *vsk = vsock_sk(sk);

	/* vmci_transport.c doesn't take sk_lock here either.  At least we're
	 * under vsock_table_lock so the sock cannot disappear while we're
	 * executing.
	 */

	/* If the peer is still valid, no need to reset connection */
	if (vhost_vsock_get(vsk->remote_addr.svm_cid))
		return;

	/* If the close timeout is pending, let it expire.  This avoids races
	 * with the timeout callback.
	 */
	if (vsk->close_work_scheduled)
		return;

	sock_set_flag(sk, SOCK_DONE);
	vsk->peer_shutdown = SHUTDOWN_MASK;
	sk->sk_state = SS_UNCONNECTED;
	sk->sk_err = ECONNRESET;
	sk_error_report(sk);
}

void vsock_device_destroy(struct virtio_device *vdev)
{
	struct vhost_vsock *vsock = vdev->priv;

	mutex_lock(&vhost_vsock_mutex);
	if (vsock->guest_cid)
		hash_del_rcu(&vsock->hash);
	mutex_unlock(&vhost_vsock_mutex);

	/* Wait for other CPUs to finish using vsock */
	synchronize_rcu();

	/* Iterating over all connections for all CIDs to find orphans is
	 * inefficient.  Room for improvement here. */
	vsock_for_each_connected_socket(&vhost_transport.transport,
					vhost_vsock_reset_orphans);

	virtio_vsock_skb_queue_purge(&vsock->send_pkt_queue);

	destroy_workqueue(vsock->workq);
	virtio_delete_virtqueues(vdev);
	kfree(vsock);
}

static void vsock_device_reset(struct virtio_device *vdev)
{
	pr_debug("vsock vdev reset\n");
}

static struct nebula_rproc_vdev_ops vsock_vdev_ops = {
	.on_create = vsock_device_create,
	.on_destroy = vsock_device_destroy,
	.on_reset = vsock_device_reset,
};

static int __init nebula_virtio_vsocket_init(void)
{
	int ret = vsock_core_register(&vhost_transport.transport,
					VSOCK_TRANSPORT_F_H2G);
	if (ret < 0)
		return ret;

	ret = nebula_rproc_register_device(
		&vsock_vdev_desc, sizeof(vsock_vdev_desc), &vsock_vdev_ops);
	if (ret) {
		vsock_core_unregister(&vhost_transport.transport);
		return ret;
	}
	return 0;
}

module_init(nebula_virtio_vsocket_init);
MODULE_AUTHOR("Asias He");
MODULE_DESCRIPTION("vhost transport for vsock");
MODULE_LICENSE("Dual BSD/GPL");
