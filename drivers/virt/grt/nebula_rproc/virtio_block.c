// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2011 Taobao, Inc.
 * Author: Liu Yuan <tailai.ly@taobao.com>
 *
 * Copyright (C) 2012 Red Hat, Inc.
 * Author: Asias He <asias@redhat.com>
 *
 * Copyright (c) 2022 Virtuozzo International GmbH.
 * Author: Andrey Zhadchenko <andrey.zhadchenko@virtuozzo.com>
 *
 * virtio-blk host kernel accelerator.
 */

#define pr_fmt(fmt) "virtio_block: "fmt

#include <linux/module.h>
#include <linux/of_platform.h>
#include <linux/blkdev.h>
#include <linux/blkdev.h>
#include <linux/llist.h>
#include <linux/uio.h>
#include <linux/of_reserved_mem.h>
#include <linux/virtio_types.h>
#include <linux/sched/clock.h>
#include <linux/debugfs.h>

#include "nebula_rproc_remote.h"
#include "remoteproc_virtio.h"
#include "utility.h"
#include "virtqueue.h"
#include "virtio.h"

/* Resource table entries */
#define NUM_VRINGS  0x1
#define VRING_ALIGN 0x1000
#define VRING_SIZE  1024
#define BLK_VQ      0

/* Feature bits */
#define VIRTIO_BLK_F_SIZE_MAX	1	/* Indicates maximum segment size */
#define VIRTIO_BLK_F_SEG_MAX	2	/* Indicates maximum # of segments */
#define VIRTIO_BLK_F_GEOMETRY	4	/* Legacy geometry available  */
#define VIRTIO_BLK_F_RO		5	/* Disk is read-only */
#define VIRTIO_BLK_F_BLK_SIZE	6	/* Block size of disk is available*/
#define VIRTIO_BLK_F_TOPOLOGY	10	/* Topology information is available */
#define VIRTIO_BLK_F_MQ		12	/* support more than one vq */
#define VIRTIO_BLK_F_DISCARD	13	/* DISCARD is supported */
#define VIRTIO_BLK_F_WRITE_ZEROES	14	/* WRITE ZEROES is supported */
#define VIRTIO_BLK_F_SECURE_ERASE	16 /* Secure Erase is supported */

/* Legacy feature bits */
#ifndef VIRTIO_BLK_NO_LEGACY
#define VIRTIO_BLK_F_BARRIER	0	/* Does host support barriers? */
#define VIRTIO_BLK_F_SCSI	7	/* Supports scsi command passthru */
#define VIRTIO_BLK_F_FLUSH	9	/* Flush command supported */
#define VIRTIO_BLK_F_CONFIG_WCE	11	/* Writeback mode available in config */
#ifndef __KERNEL__
/* Old (deprecated) name for VIRTIO_BLK_F_FLUSH. */
#define VIRTIO_BLK_F_WCE VIRTIO_BLK_F_FLUSH
#endif
#endif /* !VIRTIO_BLK_NO_LEGACY */

/* These two define direction. */
#define VIRTIO_BLK_T_IN        0
#define VIRTIO_BLK_T_OUT    1

#ifndef VIRTIO_BLK_NO_LEGACY
/* This bit says it's a scsi command, not an actual read or write. */
#define VIRTIO_BLK_T_SCSI_CMD    2
#endif /* VIRTIO_BLK_NO_LEGACY */

/* Cache flush command */
#define VIRTIO_BLK_T_FLUSH    4

/* Get device ID command */
#define VIRTIO_BLK_T_GET_ID    8

/* Discard command */
#define VIRTIO_BLK_T_DISCARD    11

/* Write zeroes command */
#define VIRTIO_BLK_T_WRITE_ZEROES    13

/* Secure erase command */
#define VIRTIO_BLK_T_SECURE_ERASE    14

#ifndef VIRTIO_BLK_NO_LEGACY
/* Barrier before this op. */
#define VIRTIO_BLK_T_BARRIER    0x80000000
#endif /* !VIRTIO_BLK_NO_LEGACY */

/* And this is the final byte of the write scatter-gather list. */
#define VIRTIO_BLK_S_OK        0
#define VIRTIO_BLK_S_IOERR    1
#define VIRTIO_BLK_S_UNSUPP    2

/*
 * This comes first in the read scatter-gather list.
 * For legacy virtio, if VIRTIO_F_ANY_LAYOUT is not negotiated,
 * this is the first element of the read scatter-gather list.
 */
struct virtio_blk_outhdr {
	/* VIRTIO_BLK_T* */
	u32 type;
	/* io priority. */
	u32 ioprio;
	/* Sector (ie. 512 byte offset) */
	u64 sector;
};

struct virtio_blk_config {
	/* The capacity (in 512-byte sectors). */
	u64 capacity;
	/* The maximum segment size (if VIRTIO_BLK_F_SIZE_MAX) */
	u32 size_max;
	/* The maximum number of segments (if VIRTIO_BLK_F_SEG_MAX) */
	u32 seg_max;
	/* geometry of the device (if VIRTIO_BLK_F_GEOMETRY) */
	struct virtio_blk_geometry {
		u16 cylinders;
		u8 heads;
		u8 sectors;
	} geometry;

	/* block size of device (if VIRTIO_BLK_F_BLK_SIZE) */
	u32 blk_size;

	/* the next 4 entries are guarded by VIRTIO_BLK_F_TOPOLOGY  */
	/* exponent for physical block per logical block. */
	u8 physical_block_exp;
	/* alignment offset in logical blocks. */
	u8 alignment_offset;
	/* minimum I/O size without performance penalty in logical blocks. */
	u16 min_io_size;
	/* optimal sustained I/O size in logical blocks. */
	u32 opt_io_size;

	/* writeback mode (if VIRTIO_BLK_F_CONFIG_WCE) */
	u8 wce;
	u8 unused;

	/* number of vqs, only available when VIRTIO_BLK_F_MQ is set */
	u16 num_queues;

	/* the next 3 entries are guarded by VIRTIO_BLK_F_DISCARD */
	/*
	 * The maximum discard sectors (in 512-byte sectors) for
	 * one segment.
	 */
	u32 max_discard_sectors;
	/*
	 * The maximum number of discard segments in a
	 * discard command.
	 */
	u32 max_discard_seg;
	/* Discard commands must be aligned to this number of sectors. */
	u32 discard_sector_alignment;

	/* the next 3 entries are guarded by VIRTIO_BLK_F_WRITE_ZEROES */
	/*
	 * The maximum number of write zeroes sectors (in 512-byte sectors) in
	 * one segment.
	 */
	u32 max_write_zeroes_sectors;
	/*
	 * The maximum number of segments in a write zeroes
	 * command.
	 */
	u32 max_write_zeroes_seg;
	/*
	 * Set if a VIRTIO_BLK_T_WRITE_ZEROES request may result in the
	 * deallocation of one or more of the sectors.
	 */
	u8 write_zeroes_may_unmap;

	u8 unused1[3];

	/* the next 3 entries are guarded by VIRTIO_BLK_F_SECURE_ERASE */
	/*
	 * The maximum secure erase sectors (in 512-byte sectors) for
	 * one segment.
	 */
	u32 max_secure_erase_sectors;
	/*
	 * The maximum number of secure erase segments in a
	 * secure erase command.
	 */
	u32 max_secure_erase_seg;
	/* Secure erase commands must be aligned to this number of sectors. */
	u32 secure_erase_sector_alignment;

} __attribute__((packed));

/* Discard/write zeroes range for each request. */
struct virtio_blk_discard_write_zeroes {
	/* discard/write zeroes start sector */
	u64 sector;
	/* number of discard/write zeroes sectors */
	u32 num_sectors;
	/* flags for this range */
	u32 flags;
};

struct block_device_descriptor {
	struct fw_rsc_vdev vdev;
	struct fw_rsc_vdev_vring vrings[NUM_VRINGS];
	struct virtio_blk_config config;
} __packed;

#define HOST_BLK_FEATURES \
	VIRTIO_RING_F_INDIRECT_DESC | \
	(1 << VIRTIO_BLK_F_TOPOLOGY) | \
	(1 << VIRTIO_BLK_F_SIZE_MAX) | \
	(1 << VIRTIO_BLK_F_SEG_MAX) | \
	(1 << VIRTIO_BLK_F_BLK_SIZE) | \
	(1 << VIRTIO_BLK_F_FLUSH) | \
	(1 << VIRTIO_BLK_F_MQ) /*| \
	VIRTIO_RING_F_EVENT_IDX | \
	(1 << VIRTIO_BLK_F_DISCARD) | \
	(1 << VIRTIO_BLK_F_GEOMETRY) | \
	(1 << VIRTIO_BLK_F_WRITE_ZEROES) | \
	(1 << VIRTIO_BLK_F_SECURE_ERASE) | \
	(1 << VIRTIO_BLK_F_RO) | \
	(1 << VIRTIO_BLK_F_ZONED)*/

#define VHOST_MAX_DATA_IOV  VRING_SIZE
#define VHOST_MAX_METADATA_IOV 1

#define NR_INLINE 320

struct virtio_blk_req {
	struct bio *bio[NR_INLINE];

	struct llist_node llnode;

	struct kvec *iov;
	int iov_nr;
	atomic_t bio_nr;

	struct kvec status[VHOST_MAX_METADATA_IOV];

	sector_t sector;
	int bi_opf;
	u16 head;
	long len;
	int bio_err;

	struct virtio_blk *blk;
	struct virtio_blk_vq *blk_vq;
};

struct virtio_blk_vq {
	struct virtqueue *vq;
	struct virtio_blk_req *req;
	struct kvec iov[VHOST_MAX_DATA_IOV];
	struct llist_head llhead;
	struct work_struct work;
};

#define VIRTIO_BLK_ID_BYTES	20	/* ID string length */

struct virtio_blk {
	struct virtio_blk_vq bvq;
	char serial[VIRTIO_BLK_ID_BYTES];
	struct workqueue_struct *workq;
	struct file *file;
	struct block_device *bdev;
};

static struct block_device *virt_bdev;
static struct block_device_descriptor block_vdev_desc;

/*
 * from: kvec move data from
 * to:   kvec move data to
 *
 */
static int move_kvec(struct kvec *from, struct kvec *to,
			  size_t len, int iov_count_from, int iov_count_to)
{
	int moved_seg = 0, spent_seg = 0;
	size_t size;

	while (len && spent_seg < iov_count_from && moved_seg < iov_count_to) {
		if (from->iov_len == 0) {
			++from;
			++spent_seg;
			continue;
		}
		size = min(from->iov_len, len);
		to->iov_base = from->iov_base;
		to->iov_len = size;
		from->iov_len -= size;
		from->iov_base += size;
		len -= size;
		++from;
		++to;
		++moved_seg;
		++spent_seg;
	}

	return len ? -1 : moved_seg;
}

static inline int iov_num_pages(struct kvec *iov)
{
	return (PAGE_ALIGN((unsigned long)iov->iov_base + iov->iov_len) -
		   ((unsigned long)iov->iov_base & PAGE_MASK)) >> PAGE_SHIFT;
}

static inline int virtio_blk_set_status(struct virtio_blk_req *req, u8 status)
{
	struct iov_iter iter;
	int ret;

	iov_iter_kvec(&iter, ITER_DEST, req->status, ARRAY_SIZE(req->status),
			sizeof(status));
	ret = copy_to_iter(&status, sizeof(status), &iter);
	if (ret != sizeof(status)) {
		pr_err("Failed to write status\n");
		return -EFAULT;
	}

	return 0;
}

static void virtio_blk_req_done(struct bio *bio)
{
	struct virtio_blk_req *req = bio->bi_private;
	struct virtio_blk *blk = req->blk;
	int err;

	err = blk_status_to_errno(bio->bi_status);
	if (err)
		req->bio_err = err;

	if (atomic_dec_and_test(&req->bio_nr)) {
		/* 
		 * All bios of the req is done, wake up the worker
		 * to fill status and signal front-end.
		 */
		llist_add(&req->llnode, &req->blk_vq->llhead);
		queue_work(blk->workq, &req->blk_vq->work);
	}

	bio_put(bio);
}

static int virtio_blk_bio_make_simple(struct virtio_blk_req *req,
					 struct block_device *bdev)
{
	struct bio *bio;

	bio = bio_alloc(bdev, 1, req->bi_opf, GFP_KERNEL);
	if (!bio)
		return -ENOMEM;

	bio->bi_iter.bi_sector = req->sector;
	bio_set_dev(bio, bdev);
	bio->bi_private = req;
	bio->bi_end_io  = virtio_blk_req_done;
	bio->bi_opf    = req->bi_opf;
	req->bio[0] = bio;

	atomic_set(&req->bio_nr, 1);

	return 0;
}

static int virtio_blk_bio_make_discard(struct virtio_blk_req *req,
					 struct block_device *bdev)
{
	struct kvec *iov = req->iov;
	struct virtio_blk_discard_write_zeroes *range;
	struct bio *bio = NULL;
	int ret;

	if (unlikely(WARN_ON(req->iov_nr != 1)))
	    return -EINVAL;

	range = (struct virtio_blk_discard_write_zeroes *)iov[0].iov_base;
	ret = __blkdev_issue_discard(bdev, range->sector, range->num_sectors,
			GFP_KERNEL, &bio);
	if (unlikely(ret)) {
	    pr_err("discard failed @sector(%llu) len(%u)\n",
			    range->sector, range->num_sectors);
	    return ret;
	}

	bio->bi_end_io = virtio_blk_req_done;
	bio->bi_private = req;
	bio->bi_opf = req->bi_opf;
	req->bio[0] = bio;

	atomic_set(&req->bio_nr, 1);

	return 0;
}

static int virtio_blk_bio_make(struct virtio_blk_req *req,
		struct block_device *bdev)
{
	int i, j, iov_nr, bio_nr, pages_nr, pages_nr_total;
	struct kvec *iov = req->iov;
	struct page *page;
	struct bio *bio = NULL;

	if (unlikely(req->bi_opf == REQ_OP_FLUSH))
		return virtio_blk_bio_make_simple(req, bdev);

	if (req->bi_opf == REQ_OP_DISCARD)
		return virtio_blk_bio_make_discard(req, bdev);

	iov_nr = req->iov_nr;
	req->iov_nr = 0;
	bio_nr = 0;

	pages_nr_total = 0;
	for (i = 0; i < iov_nr; i++)
		pages_nr_total += iov_num_pages(&iov[i]);

	/* pages_nr_total <= max_sectors_kb/PAGE_SIZE = 1280KB/4KB = 320 */
	for (i = 0; i < iov_nr; i++) {
		unsigned long iov_base, iov_len;

		pages_nr = iov_num_pages(&iov[i]);
		iov_base = (unsigned long)iov[i].iov_base;
		iov_len  = (unsigned long)iov[i].iov_len;
		req->iov_nr++;

		/* pages_nr <= max_segment_size/PAGE_SIZE = 256KB/4KB = 64 */
		for (j = 0; j < pages_nr; j++) {
			unsigned int off, len;

			page = virt_to_page((void *)iov_base);
			off = iov_base & ~PAGE_MASK;
			len = PAGE_SIZE - off;
			if (len > iov_len)
				len = iov_len;

			while (!bio || !bio_add_page(bio, page, len, off)) {
				int alloc_segs = bio_max_segs(pages_nr_total);
				bio = bio_alloc(bdev, alloc_segs, req->bi_opf, GFP_KERNEL);
				if (!bio)
					goto fail;
				bio->bi_iter.bi_sector = req->sector;
				bio_set_dev(bio, bdev);
				bio->bi_private = req;
				bio->bi_end_io = virtio_blk_req_done;
				bio->bi_opf = req->bi_opf;
				req->bio[bio_nr++] = bio;
			}

			/* 512 bytes per sector */
			req->sector += len >> SECTOR_SHIFT;
			iov_base += len;
			iov_len -= len;
			pages_nr_total--;
		}
	}

	WARN_ON(iov_nr < req->iov_nr);
	WARN_ON(pages_nr_total != 0);
	atomic_set(&req->bio_nr, bio_nr);
	return 0;

fail:
	for (i = 0; i < bio_nr; i++)
		bio_put(req->bio[i]);
	return -ENOMEM;
}

static inline void virtio_blk_bio_send(struct virtio_blk_req *req)
{
	struct blk_plug plug;
	int i, bio_nr;

	bio_nr = atomic_read(&req->bio_nr);
	blk_start_plug(&plug);
	for (i = 0; i < bio_nr; i++)
		submit_bio(req->bio[i]);

	blk_finish_plug(&plug);
}

static int virtio_blk_req_submit(struct virtio_blk_req *req)
{
	int ret;

	ret = virtio_blk_bio_make(req, req->blk->bdev);
	if (ret < 0)
		return ret;

	virtio_blk_bio_send(req);

	return 0;
}

static struct kvec vq_iov[VHOST_MAX_DATA_IOV];

static inline size_t kvec_length(const struct kvec *iov,
		unsigned long nr_segs)
{
	unsigned long seg;
	size_t ret = 0;

	for (seg = 0; seg < nr_segs; seg++)
		ret += iov[seg].iov_len;
	return ret;
}

static int virtio_blk_req_handle(struct virtio_blk_vq *blk_vq,
				struct virtio_blk_outhdr *hdr,
				u16 head, u16 total_iov_nr)
{
	struct virtio_blk *blk = container_of(blk_vq, struct virtio_blk, bvq);
	struct virtqueue *vq = blk_vq->vq;
	struct virtio_blk_req *req;
	struct iov_iter iter;
	int ret, len;
	u8 status;

	BUG_ON(!vq);
	req = &blk_vq->req[head];
	req->blk_vq = blk_vq;
	req->head = head;
	req->blk = blk;
	req->sector = hdr->sector;
	req->iov = blk_vq->iov;
	req->bio_err = 0;

	/* calculate payload length */
	req->len = kvec_length(vq_iov, total_iov_nr) - sizeof(status);

	/* move payload to req->iov */
	req->iov_nr = move_kvec(vq_iov, req->iov, req->len, total_iov_nr,
					 ARRAY_SIZE(blk_vq->iov));

	/* move status to req->status */
	ret = move_kvec(vq_iov, req->status, sizeof(status), total_iov_nr,
			 ARRAY_SIZE(req->status));
	if (unlikely(ret < 0 || req->iov_nr < 0))
		return -EINVAL;

	switch (hdr->type) {
	case VIRTIO_BLK_T_OUT:
		req->bi_opf = REQ_OP_WRITE;
		ret = virtio_blk_req_submit(req);
		break;
	case VIRTIO_BLK_T_IN:
		req->bi_opf = REQ_OP_READ;
		ret = virtio_blk_req_submit(req);
		break;
	case VIRTIO_BLK_T_FLUSH:
		req->bi_opf = REQ_OP_FLUSH;
		ret = virtio_blk_req_submit(req);
		break;
	case VIRTIO_BLK_T_DISCARD:
		req->bi_opf = REQ_OP_DISCARD;
		ret = virtio_blk_req_submit(req);
		break;
	case VIRTIO_BLK_T_GET_ID:
		len = strnlen(blk->serial, VIRTIO_BLK_ID_BYTES);
		iov_iter_kvec(&iter, ITER_DEST, req->iov, req->iov_nr, req->len);
		ret = copy_to_iter(blk->serial, len, &iter);
		status = ret != len ? VIRTIO_BLK_S_IOERR : VIRTIO_BLK_S_OK;
		ret = virtio_blk_set_status(req, status);
		if (ret)
			break;
		virtqueue_add_consumed_buffer(vq, head, len);
		virtqueue_kick(vq);
		break;
	default:
		WARN(1, "Unsupported request type %d\n", hdr->type);
		status = VIRTIO_BLK_S_UNSUPP;
		ret = virtio_blk_set_status(req, status);
		if (ret)
			break;
		virtqueue_add_consumed_buffer(vq, head, 0);
		virtqueue_kick(vq);
	}

	return ret;
}

static void virtio_blk_handle_guest_kick(struct virtqueue *vq)
{
	struct virtio_blk_outhdr hdr;
	struct virtio_blk_vq *blk_vq;
	struct virtio_blk_req *req;
	struct kvec hdr_iovec[VHOST_MAX_METADATA_IOV];
	struct iov_iter iter;
	struct virtio_blk *blk;
	int in, out, ret;
	int head;

	if (vq->vq_available_idx == vq->vq_ring.avail->idx) {
		/* NOTE:
		 * remote block driver may kick us when no enough descs space left,
		 * we don't have a better way to speed up the I/O procedure,
		 * so just ignore it */
		pr_debug("An empty kick coming\n");
		return;
	}

	blk = vq->priv;
	blk_vq = &blk->bvq;

	virtqueue_disable_cb(vq);
	for (;;) {
		head = virtqueue_get_vq_desc(vq, vq_iov, ARRAY_SIZE(vq_iov), &out, &in);
		if (unlikely(head == ERROR_VRING_NO_BUFF)) {
			cond_resched();
			if (unlikely(virtqueue_enable_cb(vq))) {
				/* process new entries */
				virtqueue_disable_cb(vq);
				continue;
			}
			break;
		}

		if (unlikely(head < 0))
			break;

		req = &blk_vq->req[head];

		/* move header to local */
		ret = move_kvec(vq_iov, hdr_iovec, sizeof(hdr), in + out,
				ARRAY_SIZE(hdr_iovec));
		if (unlikely(ret < 0)) {
			pr_err("virtio_blk_hdr is too split!");
			break;
		}

		/* The second segment is data */
		iov_iter_kvec(&iter, ITER_SOURCE, hdr_iovec, ARRAY_SIZE(hdr_iovec),
				sizeof(hdr));
		ret = copy_from_iter(&hdr, sizeof(hdr), &iter);
		if (unlikely(ret != sizeof(hdr))) {
			pr_err("Failed to get block header: read %d bytes instead of %ld!\n",
				   ret, sizeof(hdr));
			break;
		}

		ret = virtio_blk_req_handle(blk_vq, &hdr, head, out + in);
		if (unlikely(ret < 0)) {
			pr_err("virtio_blk_hdr is too split!");
			break;
		}
	}
}

static void virtio_blk_handle_host_kick(struct work_struct *work)
{
	struct virtio_blk_vq *blk_vq;
	struct virtio_blk_req *req;
	struct virtqueue *vq;
	struct llist_node *llnode;
	struct virtio_blk *blk = NULL;
	bool added;
	u8 status;
	int ret;

	blk_vq = container_of(work, struct virtio_blk_vq, work);
	vq = blk_vq->vq;
	llnode = llist_del_all(&blk_vq->llhead);
	added = false;

	while (llnode) {
		req = llist_entry(llnode, struct virtio_blk_req, llnode);
		llnode = llist_next(llnode);

		if (!blk)
			blk = req->blk;

		status = req->bio_err == 0 ? VIRTIO_BLK_S_OK : VIRTIO_BLK_S_IOERR;
		ret = virtio_blk_set_status(req, status);
		if (unlikely(ret)) {
			pr_err("ERROR: req%u set status failed! ret=%d\n", req->head, ret);
			continue;
		}

		ret = virtqueue_add_consumed_buffer(vq, req->head, req->len);
		if (unlikely(ret)) {
			pr_err("ERROR: req%u add used failed! ret=%d\n", req->head, ret);
			continue;
		}
		added = true;
	}

	if (likely(added))
		virtqueue_kick(vq);
}

int block_device_create(struct virtio_device *vdev,
			 struct metal_io_region *shm_io)
{
	const char *vq_names[NUM_VRINGS];
	vq_callback callback[NUM_VRINGS];
	struct virtqueue *vq;
	struct kvec *iovs;
	int ret;

	if (!virt_bdev)
		return -EIO;

	struct virtio_blk *blk =
		kzalloc(sizeof(struct virtio_blk), GFP_KERNEL);
	if (!blk)
		return -ENOMEM;

	blk->bdev = virt_bdev;

	snprintf(blk->serial, VIRTIO_BLK_ID_BYTES, "virtio-blk");

	blk->workq = alloc_workqueue("virtio-block",
			/*WQ_HIGHPRI | WQ_UNBOUND | WQ_MEM_RECLAIM*/0, 1);
	if (!blk->workq) {
		ret = -ENOMEM;
		goto err_free_blk;
	}

	blk->bvq.req = kvmalloc(sizeof(struct virtio_blk_req) * VHOST_MAX_DATA_IOV,
			GFP_KERNEL);
	if (!blk->bvq.req) {
		ret = -ENOMEM;
		goto err_release_workq;
	}

	iovs = kvmalloc(sizeof(*iovs) * VHOST_MAX_DATA_IOV, GFP_KERNEL);
	if (!iovs) {
		ret = -ENOMEM;
		goto err_free_req;
	}

	INIT_WORK(&blk->bvq.work, virtio_blk_handle_host_kick);

	vq_names[0] = "blk_vq";
	callback[0] = virtio_blk_handle_guest_kick;
	vdev->priv = blk;

	/* Create virtqueues for remote device */
	ret = virtio_create_virtqueues(vdev, 0, NUM_VRINGS, vq_names,
					  callback, NULL);
	if (ret != VQUEUE_SUCCESS) {
		pr_err("failed to create virtqueue, err=%d\n", ret);
		return -EIO;
		goto err_free_iov;
	}

	vq = vdev->vrings_info[0].vq;

	/* the shm_io is used by phys_to_virt()/virt_to_phys() */
	virtqueue_set_shmem_io(vq, shm_io);
	blk->bvq.vq = vq;
	blk->bvq.vq->priv = blk;

	return 0;

err_free_iov:
	kvfree(iovs);
err_free_req:
	kvfree(blk->bvq.req);
err_release_workq:
	destroy_workqueue(blk->workq);
err_free_blk:
	kfree(blk);

	return ret;
}

void block_device_destroy(struct virtio_device *vdev)
{
	struct virtio_blk *blk = vdev->priv;

	// TODO: blk_flush
	destroy_workqueue(blk->workq);
	virtqueue_free(blk->bvq.vq);
	kvfree(blk->bvq.req);
	blkdev_put(blk->bdev, NULL);
	kfree(blk);
	vdev->priv = NULL;
}

static void block_device_reset(struct virtio_device *vdev)
{
	/* 
	 * TODO:
	 * By now, this function will never be invoked.
	 * implement this later.
	 */
}

static struct nebula_rproc_vdev_ops block_vdev_ops = {
	.on_create = block_device_create,
	.on_destroy = block_device_destroy,
	.on_reset = block_device_reset,
};

static struct block_device_descriptor block_vdev_desc = {
	.vdev        = {
		.type        = RSC_VDEV,
		.id        = VIRTIO_ID_BLOCK,
		.dfeatures    = HOST_BLK_FEATURES,
		.config_len    = sizeof(struct virtio_blk_config),
		.num_of_vrings    = NUM_VRINGS,
	},
	.vrings    = {
		[BLK_VQ]    = {
			.da        = FW_RSC_U32_ADDR_ANY,
			.align        = VRING_ALIGN,
			.num        = VRING_SIZE,
		},
	},
	.config = {
		.num_queues = 1,
	}
};

static int block_config_blk_settings(void)
{
	struct virtio_blk_config *config;
	struct request_queue *q;
	u32 phys_blk_sz;
	u16 max_discard_segs;
	int ret = -EIO;

	virt_bdev = blkdev_get_by_path("/dev/sdc", FMODE_READ | FMODE_WRITE,
			NULL, NULL);
	if (!virt_bdev) {
		pr_err("fatal error: /dev/sdc not found!\n");
		return -EPROBE_DEFER;
	}

	q = bdev_get_queue(virt_bdev);
	config = &block_vdev_desc.config;

	/* capacity of block device */
	config->capacity = bdev_nr_sectors(virt_bdev);
	if (config->capacity == 0) {
		pr_err("fatal error: zero capacity!\n");
		goto put_blkdev;
	}

	/* data length related */
	config->size_max = queue_max_segment_size(q);
	config->seg_max = bdev_max_segments(virt_bdev);
	config->blk_size = bdev_logical_block_size(virt_bdev);
	if (config->blk_size == 0) {
		pr_err("fatal error: wrong block size!\n");
		goto put_blkdev;
	}

	/* topology */
	phys_blk_sz = bdev_physical_block_size(virt_bdev);
	config->physical_block_exp = ffs(phys_blk_sz / config->blk_size) - 1;
	config->alignment_offset = bdev_alignment_offset(virt_bdev) / config->blk_size;
	config->min_io_size = bdev_io_min(virt_bdev) / config->blk_size;
	config->opt_io_size = bdev_io_opt(virt_bdev) / config->blk_size;

	pr_debug("virtio-block(BE): cap:%llu size_max:%u seg_max:%u blksz:%u(phys:%u)\n",
			config->capacity, config->size_max, config->seg_max,
			config->blk_size, phys_blk_sz);

	/* discard/erase */
	max_discard_segs = queue_max_discard_segments(q);
	if (max_discard_segs == 1) {
		/* we only support 1 disard segments */
		block_vdev_desc.vdev.dfeatures |= (1 << VIRTIO_BLK_F_DISCARD);
		config->max_discard_seg = max_discard_segs;
		config->max_discard_sectors = bdev_max_discard_sectors(virt_bdev);
		config->discard_sector_alignment = bdev_discard_granularity(virt_bdev);
		/*config->discard_sector_alignment =
			bdev_discard_alignment(virt_bdev) >> SECTOR_SHIFT;*/
		pr_debug("discard: max_seg:%u max_sectors:%u sector_alignment:%u",
				config->max_discard_seg, config->max_discard_sectors,
				config->discard_sector_alignment);
	} else
	    pr_warn("discard is not supported.\n");

	return 0;

put_blkdev:
	blkdev_put(virt_bdev, NULL);
	virt_bdev = NULL;

	return ret;
}

static int __init nebula_virtio_block_init(void)
{
	int ret;

	ret = block_config_blk_settings();
	if (ret)
		return ret;

	nebula_rproc_register_device(&block_vdev_desc, sizeof(block_vdev_desc),
					 &block_vdev_ops);
	return 0;
}

module_init(nebula_virtio_block_init);
MODULE_LICENSE("Dual BSD/GPL");
MODULE_ALIAS("platform:rproc-virtio:virtio_block");
