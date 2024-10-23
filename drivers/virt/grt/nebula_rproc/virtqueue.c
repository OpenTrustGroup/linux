/*-
 * Copyright (c) 2011, Bryan Venteicher <bryanv@FreeBSD.org>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/string.h>
#include <linux/mod_devicetable.h>

#include "virtio.h"
#include "virtqueue.h"

/* Prototype for internal functions. */
static void vq_ring_init(struct virtqueue *, void *, int);
static void vq_ring_update_avail(struct virtqueue *, uint16_t);
static uint16_t vq_ring_add_buffer(struct virtqueue *, struct vring_desc *,
				   uint16_t, struct virtqueue_buf *, int, int);
static int vq_ring_enable_interrupt(struct virtqueue *, uint16_t);
static void vq_ring_free_chain(struct virtqueue *, uint16_t);
static int vq_ring_must_notify(struct virtqueue *vq);
static void vq_ring_notify(struct virtqueue *vq);
static int virtqueue_navail(struct virtqueue *vq);

/* Default implementation of P2V based on libmetal */
static inline void *virtqueue_phys_to_virt(struct virtqueue *vq,
					   phys_addr_t phys)
{
	struct metal_io_region *io = vq->shm_io;

	return io->paddr_to_vaddr(vq, phys);
}

/* Default implementation of V2P based on libmetal */
static inline phys_addr_t virtqueue_virt_to_phys(struct virtqueue *vq,
						       void *buf)
{
	struct metal_io_region *io = vq->shm_io;

	return io->vaddr_to_paddr(vq, buf);
}

static int virtqueue_alloc_buffers(struct virtqueue *vq)
{
	vq->indirect = kmalloc_array(UIO_MAXIOV,
			sizeof(struct vring_desc), GFP_KERNEL);

	vq->heads = kmalloc_array(UIO_MAXIOV, sizeof(*vq->heads),
			  GFP_KERNEL);
	if (!vq->indirect || !vq->heads)
		goto err_free_mem;

	return VQUEUE_SUCCESS;

err_free_mem:
	kfree(vq->indirect);
	vq->indirect = NULL;
	kfree(vq->heads);
	vq->heads = NULL;

	return ERROR_NO_MEM;
}

int virtqueue_create(struct virtio_device *virt_dev, unsigned short id,
		     const char *name, struct vring_alloc_info *ring,
		     void (*callback)(struct virtqueue *vq),
		     void (*notify)(struct virtqueue *vq),
		     struct virtqueue *vq)
{
	int status = VQUEUE_SUCCESS;

	VQ_PARAM_CHK(ring == NULL, status, ERROR_VQUEUE_INVLD_PARAM);
	VQ_PARAM_CHK(ring->num_descs == 0, status, ERROR_VQUEUE_INVLD_PARAM);
	VQ_PARAM_CHK(ring->num_descs & (ring->num_descs - 1), status,
		     ERROR_VRING_ALIGN);
	VQ_PARAM_CHK(vq == NULL, status, ERROR_NO_MEM);

	if (status == VQUEUE_SUCCESS) {
		vq->vq_dev = virt_dev;
		vq->vq_name = name;
		vq->vq_queue_index = id;
		vq->vq_nentries = ring->num_descs;
		vq->vq_free_cnt = vq->vq_nentries;
		vq->callback = callback;
		vq->notify = notify;
		mutex_init(&vq->mutex);

		status = virtqueue_alloc_buffers(vq);
		if (status != VQUEUE_SUCCESS)
			return status;

		/* Initialize vring control block in virtqueue. */
		vq_ring_init(vq, ring->vaddr, ring->align);
	}

	/*
	 * CACHE: nothing to be done here. Only desc.next is setup at this
	 * stage but that is only written by driver, so no need to flush it.
	 */

	return status;
}
EXPORT_SYMBOL(virtqueue_create);

int virtqueue_add_buffer(struct virtqueue *vq, struct virtqueue_buf *buf_list,
			 int readable, int writable, void *cookie)
{
	struct vq_desc_extra *dxp = NULL;
	int status = VQUEUE_SUCCESS;
	uint16_t head_idx;
	uint16_t idx;
	int needed;

	needed = readable + writable;

	VQ_PARAM_CHK(vq == NULL, status, ERROR_VQUEUE_INVLD_PARAM);
	VQ_PARAM_CHK(needed < 1, status, ERROR_VQUEUE_INVLD_PARAM);
	VQ_PARAM_CHK(vq->vq_free_cnt < needed, status, ERROR_VRING_FULL);

	VQUEUE_BUSY(vq);

	if (status == VQUEUE_SUCCESS) {
		VQASSERT(vq, cookie != NULL, "enqueuing with no cookie");

		head_idx = vq->vq_desc_head_idx;
		VQ_RING_ASSERT_VALID_IDX(vq, head_idx);
		dxp = &vq->vq_descx[head_idx];

		VQASSERT(vq, dxp->cookie == NULL,
			 "cookie already exists for index");

		dxp->cookie = cookie;
		dxp->ndescs = needed;

		/* Enqueue buffer onto the ring. */
		idx = vq_ring_add_buffer(vq, vq->vq_ring.desc, head_idx,
					 buf_list, readable, writable);

		vq->vq_desc_head_idx = idx;
		vq->vq_free_cnt -= needed;

		if (vq->vq_free_cnt == 0) {
			VQ_RING_ASSERT_CHAIN_TERM(vq);
		} else {
			VQ_RING_ASSERT_VALID_IDX(vq, idx);
		}

		/*
		 * Update vring_avail control block fields so that other
		 * side can get buffer using it.
		 */
		vq_ring_update_avail(vq, head_idx);
	}

	VQUEUE_IDLE(vq);

	return status;
}
EXPORT_SYMBOL(virtqueue_add_buffer);

void *virtqueue_get_buffer(struct virtqueue *vq, uint32_t *len, uint16_t *idx)
{
	struct vring_used_elem *uep;
	void *cookie;
	uint16_t used_idx, desc_idx;

	/* Used.idx is updated by the virtio device, so we need to invalidate */
	VRING_INVALIDATE(&vq->vq_ring.used->idx, sizeof(vq->vq_ring.used->idx));

	if (!vq || vq->vq_used_cons_idx == vq->vq_ring.used->idx)
		return NULL;

	VQUEUE_BUSY(vq);

	used_idx = vq->vq_used_cons_idx++ & (vq->vq_nentries - 1);
	uep = &vq->vq_ring.used->ring[used_idx];

	smp_wmb();

	/* Used.ring is written by remote, invalidate it */
	VRING_INVALIDATE(&vq->vq_ring.used->ring[used_idx],
			 sizeof(vq->vq_ring.used->ring[used_idx]));

	desc_idx = (uint16_t)uep->id;
	if (len)
		*len = uep->len;

	vq_ring_free_chain(vq, desc_idx);

	cookie = vq->vq_descx[desc_idx].cookie;
	vq->vq_descx[desc_idx].cookie = NULL;

	if (idx)
		*idx = used_idx;
	VQUEUE_IDLE(vq);

	return cookie;
}
EXPORT_SYMBOL(virtqueue_get_buffer);

uint32_t virtqueue_get_buffer_length(struct virtqueue *vq, uint16_t idx)
{
	VRING_INVALIDATE(&vq->vq_ring.desc[idx].len,
			 sizeof(vq->vq_ring.desc[idx].len));
	return vq->vq_ring.desc[idx].len;
}
EXPORT_SYMBOL(virtqueue_get_buffer_length);

void *virtqueue_get_buffer_addr(struct virtqueue *vq, uint16_t idx)
{
	VRING_INVALIDATE(&vq->vq_ring.desc[idx].addr,
			 sizeof(vq->vq_ring.desc[idx].addr));
	return virtqueue_phys_to_virt(vq, vq->vq_ring.desc[idx].addr);
}
EXPORT_SYMBOL(virtqueue_get_buffer_addr);

static unsigned next_desc(struct vring_desc *desc)
{
	unsigned int next;

	/* If this descriptor says it doesn't chain, we're done. */
	if (!(desc->flags & VRING_DESC_F_NEXT))
		return -1U;

	/* Check they're not leading us off end of descriptors. */
	next = READ_ONCE(desc->next);
	return next;
}

int virtqueue_get_vq_desc(struct virtqueue *vq, struct kvec iov[],
			  unsigned int iov_size, unsigned int *out_num,
			  unsigned int *in_num)
{
	struct vring_desc *descp, desc;
	int i, idx = 0;
	bool write_only = false;
	uint16_t head, head_idx;
	bool indirect;

	/* Avail.idx is updated by driver, invalidate it */
	if (vq->vq_available_idx == vq->vq_ring.avail->idx) {
		return ERROR_VRING_NO_BUFF;
	}

	smp_mb();

	head_idx = vq->vq_available_idx & (vq->vq_nentries - 1);
	head = vq->vq_ring.avail->ring[head_idx];

	indirect = !!(vq->vq_ring.desc[head].flags & VRING_DESC_F_INDIRECT);
	if (indirect) {
		void *va;
		BUG_ON(!vq->indirect);
		descp = &vq->vq_ring.desc[head];
		if (descp->len > UIO_MAXIOV * sizeof(struct vring_desc)) {
			pr_err("count of descriptor exceed max limit!\n");
			return ERROR_VRING_MAX_DESC;
		}
		va = virtqueue_phys_to_virt(vq, descp->addr);
		memcpy(vq->indirect, va, descp->len);
	}

	/* When we start there are none of either input nor output. */
	*out_num = *in_num = 0;

	i = indirect ? 0 : head;
	do {
		if (indirect)
			descp = &vq->indirect[i];
		else {
			desc = vq->vq_ring.desc[i];
			descp = &desc;
		}

		write_only = !!(descp->flags & VRING_DESC_F_WRITE);

		iov[idx].iov_base = virtqueue_phys_to_virt(vq, descp->addr);
		iov[idx].iov_len = descp->len;
		pr_debug("iov[%d] iov_base=%px iov_len=%lx\n", idx,
			 iov[idx].iov_base, iov[idx].iov_len);

		if (write_only) {
			/* If this is an input descriptor,
			 * increment that count. */
			(*in_num)++;
		} else {
			/* If it's an output descriptor, they're all supposed
			 * to come before any input descriptors. */
			if (unlikely(*in_num)) {
				pr_err("Descriptor has out after in: "
				       "idx %d\n",
				       i);
				return ERROR_VQUEUE_INVLD_PARAM;
			}
			(*out_num)++;
		}

		idx++;
	} while ((i = next_desc(descp)) != -1);

	vq->vq_available_idx++;
	return head;
}
EXPORT_SYMBOL(virtqueue_get_vq_desc);

/* return true if we're sure that avaiable ring is empty */
bool virtqueue_avail_empty(struct virtqueue *vq)
{
	return (vq->vq_available_idx == vq->vq_ring.avail->idx);
}
EXPORT_SYMBOL_GPL(virtqueue_avail_empty);

/* Reverse the effect of vhost_get_vq_desc. Useful for error handling. */
void virtqueue_discard_vq_desc(struct virtqueue *vq, int n)
{
	vq->vq_available_idx -= n;
}
EXPORT_SYMBOL_GPL(virtqueue_discard_vq_desc);

/* And here's the combo meal deal.  Supersize me! */
void virtqueue_add_used_and_signal(struct virtqueue *vq,
				   unsigned int head, int len)
{
	virtqueue_add_consumed_buffer(vq, head, len);
	virtqueue_kick(vq);
}
EXPORT_SYMBOL_GPL(virtqueue_add_used_and_signal);

void virtqueue_add_used_and_signal_n(struct virtqueue *vq,
				     struct vring_used_elem *heads, int n)
{
	int i;

	for (i = 0; i < n; i++) {
		struct vring_used_elem *head = &heads[i];
		virtqueue_add_consumed_buffer(vq, head->id, head->len);
	}
	virtqueue_kick(vq);
}
EXPORT_SYMBOL_GPL(virtqueue_add_used_and_signal_n);

bool virtqueue_has_feature(struct virtqueue *vq, int bit)
{
	struct virtio_device *vdev = vq->vq_dev;
	return vdev->features & (1ULL << bit);
}
EXPORT_SYMBOL(virtqueue_has_feature);

void virtqueue_free(struct virtqueue *vq)
{
	if (vq) {
		if (vq->vq_free_cnt != vq->vq_nentries) {
			pr_warn("%s: freeing non-empty virtqueue\n",
				vq->vq_name);
		}

		kfree(vq);
	}
}
EXPORT_SYMBOL(virtqueue_free);

void *virtqueue_get_available_buffer(struct virtqueue *vq, uint16_t *avail_idx,
				     uint32_t *len)
{
	uint16_t head_idx = 0;
	void *buffer;

	smp_rmb();

	/* Avail.idx is updated by driver, invalidate it */
	VRING_INVALIDATE(&vq->vq_ring.avail->idx, sizeof(vq->vq_ring.avail->idx));
	if (vq->vq_available_idx == vq->vq_ring.avail->idx) {
		return NULL;
	}

	VQUEUE_BUSY(vq);

	head_idx = vq->vq_available_idx++ & (vq->vq_nentries - 1);

	/* Avail.ring is updated by driver, invalidate it */
	VRING_INVALIDATE(&vq->vq_ring.avail->ring[head_idx],
			 sizeof(vq->vq_ring.avail->ring[head_idx]));
	*avail_idx = vq->vq_ring.avail->ring[head_idx];

	/* Invalidate the desc entry written by driver before accessing it */
	VRING_INVALIDATE(&vq->vq_ring.desc[*avail_idx],
			 sizeof(vq->vq_ring.desc[*avail_idx]));
	buffer = virtqueue_phys_to_virt(vq, vq->vq_ring.desc[*avail_idx].addr);
	*len = vq->vq_ring.desc[*avail_idx].len;

	VQUEUE_IDLE(vq);

	return buffer;
}
EXPORT_SYMBOL(virtqueue_get_available_buffer);

int virtqueue_add_consumed_buffer(struct virtqueue *vq, uint16_t head_idx,
				  uint32_t len)
{
	struct vring_used_elem *used_desc = NULL;
	uint16_t used_idx;

	if (head_idx >= vq->vq_nentries) {
		return ERROR_VRING_NO_BUFF;
	}

	VQUEUE_BUSY(vq);

	/* CACHE: used is never written by driver, so it's safe to directly access it */
	used_idx = vq->vq_ring.used->idx & (vq->vq_nentries - 1);
	used_desc = &vq->vq_ring.used->ring[used_idx];
	used_desc->id = head_idx;
	used_desc->len = len;

	/* We still need to flush it because this is read by driver */
	VRING_FLUSH(&vq->vq_ring.used->ring[used_idx],
		    sizeof(vq->vq_ring.used->ring[used_idx]));

	/* Make sure buffer is written before we update index. */
	smp_mb();

	vq->vq_ring.used->idx++;

	/* Used.idx is read by driver, so we need to flush it */
	VRING_FLUSH(&vq->vq_ring.used->idx, sizeof(vq->vq_ring.used->idx));

	/* Keep pending count until virtqueue_notify(). */
	vq->vq_queued_cnt++;

	VQUEUE_IDLE(vq);

	return VQUEUE_SUCCESS;
}
EXPORT_SYMBOL(virtqueue_add_consumed_buffer);

int virtqueue_enable_cb(struct virtqueue *vq)
{
	return vq_ring_enable_interrupt(vq, 0);
}
EXPORT_SYMBOL(virtqueue_enable_cb);

void virtqueue_disable_cb(struct virtqueue *vq)
{
	VQUEUE_BUSY(vq);

	if (vq->vq_dev->features & VIRTIO_RING_F_EVENT_IDX) {
		vring_avail_event(&vq->vq_ring) =
			vq->vq_available_idx - vq->vq_nentries - 1;
		VRING_FLUSH(&vring_avail_event(&vq->vq_ring),
			    sizeof(vring_avail_event(&vq->vq_ring)));
	} else {
		vq->vq_ring.used->flags |= VRING_USED_F_NO_NOTIFY;
		VRING_FLUSH(&vq->vq_ring.used->flags,
			    sizeof(vq->vq_ring.used->flags));
	}

	smp_mb();

	VQUEUE_IDLE(vq);
}
EXPORT_SYMBOL(virtqueue_disable_cb);

void virtqueue_kick(struct virtqueue *vq)
{
	VQUEUE_BUSY(vq);

	/* Ensure updated avail->idx is visible to host. */
	smp_mb();

	if (vq_ring_must_notify(vq))
		vq_ring_notify(vq);

	vq->vq_queued_cnt = 0;

	VQUEUE_IDLE(vq);
}
EXPORT_SYMBOL(virtqueue_kick);

void virtqueue_dump(struct virtqueue *vq)
{
	if (!vq)
		return;

	VRING_INVALIDATE(&vq->vq_ring.avail, sizeof(vq->vq_ring.avail));
	VRING_INVALIDATE(&vq->vq_ring.used, sizeof(vq->vq_ring.used));

	pr_debug("VQ: %s - size=%d; free=%d; queued=%d; desc_head_idx=%d; "
		"available_idx=%d; avail.idx=%d; used_cons_idx=%d; "
		"used.idx=%d; avail.flags=0x%x; used.flags=0x%x\r\n",
		vq->vq_name, vq->vq_nentries, vq->vq_free_cnt,
		vq->vq_queued_cnt, vq->vq_desc_head_idx, vq->vq_available_idx,
		vq->vq_ring.avail->idx, vq->vq_used_cons_idx,
		vq->vq_ring.used->idx, vq->vq_ring.avail->flags,
		vq->vq_ring.used->flags);
}
EXPORT_SYMBOL(virtqueue_dump);

uint32_t virtqueue_get_desc_size(struct virtqueue *vq)
{
	uint16_t head_idx = 0;
	uint16_t avail_idx = 0;
	uint32_t len = 0;

	/* Avail.idx is updated by driver, invalidate it */
	VRING_INVALIDATE(&vq->vq_ring.avail->idx, sizeof(vq->vq_ring.avail->idx));

	if (vq->vq_available_idx == vq->vq_ring.avail->idx) {
		return 0;
	}

	VQUEUE_BUSY(vq);

	head_idx = vq->vq_available_idx & (vq->vq_nentries - 1);

	/* Avail.ring is updated by driver, invalidate it */
	VRING_INVALIDATE(&vq->vq_ring.avail->ring[head_idx],
			 sizeof(vq->vq_ring.avail->ring[head_idx]));
	avail_idx = vq->vq_ring.avail->ring[head_idx];

	/* Invalidate the desc entry written by driver before accessing it */
	VRING_INVALIDATE(&vq->vq_ring.desc[avail_idx].len,
			 sizeof(vq->vq_ring.desc[avail_idx].len));

	len = vq->vq_ring.desc[avail_idx].len;

	VQUEUE_IDLE(vq);

	return len;
}
EXPORT_SYMBOL(virtqueue_get_desc_size);

/**************************************************************************
 *                            Helper Functions                            *
 **************************************************************************/

/*
 *
 * vq_ring_add_buffer
 *
 */
static uint16_t vq_ring_add_buffer(struct virtqueue *vq,
				   struct vring_desc *desc, uint16_t head_idx,
				   struct virtqueue_buf *buf_list, int readable,
				   int writable)
{
	struct vring_desc *dp;
	int i, needed;
	uint16_t idx;

	(void)vq;

	needed = readable + writable;

	for (i = 0, idx = head_idx; i < needed; i++, idx = dp->next) {
		VQASSERT(vq, idx != VQ_RING_DESC_CHAIN_END,
			 "premature end of free desc chain");

		/* CACHE: No need to invalidate desc because it is only written by driver */
		dp = &desc[idx];
		dp->addr = virtqueue_virt_to_phys(vq, buf_list[i].buf);
		dp->len = buf_list[i].len;
		dp->flags = 0;

		if (i < needed - 1)
			dp->flags |= VRING_DESC_F_NEXT;

		/*
		 * Readable buffers are inserted  into vring before the
		 * writable buffers.
		 */
		if (i >= readable)
			dp->flags |= VRING_DESC_F_WRITE;

		/*
		 * Instead of flushing the whole desc region, we flush only the
		 * single entry hopefully saving some cycles
		 */
		VRING_FLUSH(&desc[idx], sizeof(desc[idx]));

	}

	return idx;
}

/*
 *
 * vq_ring_free_chain
 *
 */
static void vq_ring_free_chain(struct virtqueue *vq, uint16_t desc_idx)
{
	struct vring_desc *dp;
	struct vq_desc_extra *dxp;

	/* CACHE: desc is never written by remote, no need to invalidate */
	VQ_RING_ASSERT_VALID_IDX(vq, desc_idx);
	dp = &vq->vq_ring.desc[desc_idx];
	dxp = &vq->vq_descx[desc_idx];

	if (vq->vq_free_cnt == 0) {
		VQ_RING_ASSERT_CHAIN_TERM(vq);
	}

	vq->vq_free_cnt += dxp->ndescs;
	dxp->ndescs--;

	if ((dp->flags & VRING_DESC_F_INDIRECT) == 0) {
		while (dp->flags & VRING_DESC_F_NEXT) {
			VQ_RING_ASSERT_VALID_IDX(vq, dp->next);
			dp = &vq->vq_ring.desc[dp->next];
			dxp->ndescs--;
		}
	}

	VQASSERT(vq, dxp->ndescs == 0,
		 "failed to free entire desc chain, remaining");

	/*
	 * We must append the existing free chain, if any, to the end of
	 * newly freed chain. If the virtqueue was completely used, then
	 * head would be VQ_RING_DESC_CHAIN_END (ASSERTed above).
	 *
	 * CACHE: desc.next is never read by remote, no need to flush it.
	 */
	dp->next = vq->vq_desc_head_idx;
	vq->vq_desc_head_idx = desc_idx;
}

/*
 *
 * vq_ring_init
 *
 */
static void vq_ring_init(struct virtqueue *vq, void *ring_mem, int alignment)
{
	struct vring *vr;
	int size;

	size = vq->vq_nentries;
	vr = &vq->vq_ring;

	vring_init(vr, size, ring_mem, alignment);
}

/*
 *
 * vq_ring_update_avail
 *
 */
static void vq_ring_update_avail(struct virtqueue *vq, uint16_t desc_idx)
{
	uint16_t avail_idx;

	/*
	 * Place the head of the descriptor chain into the next slot and make
	 * it usable to the host. The chain is made available now rather than
	 * deferring to virtqueue_notify() in the hopes that if the host is
	 * currently running on another CPU, we can keep it processing the new
	 * descriptor.
	 *
	 * CACHE: avail is never written by remote, so it is safe to not invalidate here
	 */
	avail_idx = vq->vq_ring.avail->idx & (vq->vq_nentries - 1);
	vq->vq_ring.avail->ring[avail_idx] = desc_idx;

	/* We still need to flush the ring */
	VRING_FLUSH(&vq->vq_ring.avail->ring[avail_idx],
		    sizeof(vq->vq_ring.avail->ring[avail_idx]));

	smp_wmb();

	vq->vq_ring.avail->idx++;

	/* And the index */
	VRING_FLUSH(&vq->vq_ring.avail->idx, sizeof(vq->vq_ring.avail->idx));

	/* Keep pending count until virtqueue_notify(). */
	vq->vq_queued_cnt++;
}

/*
 *
 * vq_ring_enable_interrupt
 *
 */
static int vq_ring_enable_interrupt(struct virtqueue *vq, uint16_t ndesc)
{
	/*
	 * Enable interrupts, making sure we get the latest index of
	 * what's already been consumed.
	 */
	if (vq->vq_dev->features & VIRTIO_RING_F_EVENT_IDX) {
		vring_avail_event(&vq->vq_ring) = vq->vq_available_idx + ndesc;
		VRING_FLUSH(&vring_avail_event(&vq->vq_ring),
			    sizeof(vring_avail_event(&vq->vq_ring)));
	} else {
		vq->vq_ring.used->flags &= ~VRING_USED_F_NO_NOTIFY;
		VRING_FLUSH(&vq->vq_ring.used->flags,
			    sizeof(vq->vq_ring.used->flags));
	}

	smp_mb();

	/*
	 * Enough items may have already been consumed to meet our threshold
	 * since we last checked. Let our caller know so it processes the new
	 * entries.
	 */
	if (virtqueue_navail(vq) > ndesc) {
		return 1;
	}

	return 0;
}

/*
 *
 * virtqueue_interrupt
 *
 */
void virtqueue_notification(struct virtqueue *vq)
{
	smp_wmb();
	if (vq && vq->callback)
		vq->callback(vq);
}
EXPORT_SYMBOL(virtqueue_notification);

/*
 *
 * vq_ring_must_notify
 *
 */
static int vq_ring_must_notify(struct virtqueue *vq)
{
	uint16_t new_idx, prev_idx, event_idx;

	if (vq->vq_dev->features & VIRTIO_RING_F_EVENT_IDX) {
		/* CACHE: no need to invalidate used */
		new_idx = vq->vq_ring.used->idx;
		prev_idx = new_idx - vq->vq_queued_cnt;
		VRING_INVALIDATE(&vring_used_event(&vq->vq_ring),
				 sizeof(vring_used_event(&vq->vq_ring)));
		event_idx = vring_used_event(&vq->vq_ring);
		mb();
		return vring_need_event(event_idx, new_idx, prev_idx) != 0;
	} else {
		VRING_INVALIDATE(&vq->vq_ring.avail->flags,
				 sizeof(vq->vq_ring.avail->flags));
		return (vq->vq_ring.avail->flags &
			VRING_AVAIL_F_NO_INTERRUPT) == 0;
	}

	return 0;
}

/*
 *
 * vq_ring_notify
 *
 */
static void vq_ring_notify(struct virtqueue *vq)
{
	if (vq->notify)
		vq->notify(vq);
}

/*
 *
 * virtqueue_navail
 *
 */
static int virtqueue_navail(struct virtqueue *vq)
{
	uint16_t avail_idx, navail;

	/* Avail is written by driver */
	VRING_INVALIDATE(&vq->vq_ring.avail->idx, sizeof(vq->vq_ring.avail->idx));

	avail_idx = vq->vq_ring.avail->idx;

	navail = (uint16_t)(avail_idx - vq->vq_available_idx);
	VQASSERT(vq, navail <= vq->vq_nentries, "avail more than available");

	return navail;
}
