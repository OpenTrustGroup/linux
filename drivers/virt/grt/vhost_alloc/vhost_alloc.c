// SPDX-License-Identifier: GPL-2.0-only

#define pr_fmt(fmt) "vhost_alloc: "fmt

#include <linux/compat.h>
#include <linux/eventfd.h>
#include <linux/vhost.h>
#include <linux/version.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/workqueue.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/completion.h>
#include <linux/spinlock.h>
#include <linux/notifier.h>
#include <linux/xarray.h>

#if defined(CONFIG_DEBUG_FS)
#include <linux/debugfs.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#endif

#define MiB(x) ((x) * 1024 * 1024)

#include "vhost.h"
#include "guest_page_pool.h"

#include "../nebula_rproc/trace.h"

/* Max number of bytes transferred before requeueing the job.
 * Using this limit prevents one virtqueue from starving others. */
#define VHOST_ALLOC_WEIGHT 0x80000

/* Max number of packets transferred before requeueing the job.
 * Using this limit prevents one virtqueue from starving others with
 * pkts.
 */
#define VHOST_ALLOC_PKT_WEIGHT 256

#define SHRINK_REQ_COUNT 0
#define SHRINK_REQ_SCAN 1

#define VHOST_ALLOC_SET_RUNNING     _IOW(VHOST_VIRTIO, 0x81, int)

enum {
	ALLOC_VQ = 0,
	REPLY_VQ = 1,
	RELEASE_VQ = 2,
	SHRINKER_VQ = 3,
	VHOST_ALLOC_VQ_MAX,
};

#define MAX_FREE_PFNS 512

struct alloc_req {
	u64 req_id;
	u64 requested_pages;
};

struct free_req {
	u32 num_pages;
	u32 pfns[MAX_FREE_PFNS];
};

struct alloc_reply {
	u64 req_id;
	u32 num_pages;
};

struct shrink_count_res {
	u32 free_pages;
};

struct shrink_scan_res {
	u32 freed_pages;
};

struct shrink_req {
	u32 req_id;
	u32 scan_free_pages;
	union {
		struct shrink_count_res count_res;
		struct shrink_scan_res scan_res;
	};
	struct completion done;
};


#if defined(CONFIG_DEBUG_FS)
struct page_pool {
	struct xarray pfn_pool;
};

static void page_pool_init(struct page_pool *pool)
{
	xa_init_flags(&pool->pfn_pool, XA_FLAGS_ALLOC);
}

static int page_pool_add_bulk(struct page_pool *pool, u32 *pfns, size_t count)
{
	size_t i, j;
	u32 *indexs;
	int ret;

	indexs = kzalloc(count * sizeof(u32), GFP_KERNEL);
	if (!indexs) {
		pr_err("Failed to allocate index array\n");
		return -ENOMEM;
	}

	xa_lock(&pool->pfn_pool);
	for (i = 0; i < count; i++) {
		ret = __xa_alloc(&pool->pfn_pool, &indexs[i],
				 xa_mk_value(pfns[i]), XA_LIMIT(0, INT_MAX),
				 GFP_KERNEL);
		if (ret) {
			pr_err("Failed to add page %u to pool, ret=%d\n",
			       pfns[i], ret);
			break;
		}
	}

	if (ret) {
		for (j = 0; j < i; j++) {
			__xa_erase(&pool->pfn_pool, indexs[j]);
		}
	}
	xa_unlock(&pool->pfn_pool);
	kfree(indexs);

	return ret;
}

static void page_pool_remove_bulk(struct page_pool *pool, u32 *pfns, u32 count,
				  u32 *actual_count)
{
	size_t idx = 0;
	unsigned long index;
	void *entry;

	xa_lock(&pool->pfn_pool);
	xa_for_each(&pool->pfn_pool, index, entry) {
		if (idx == count)
			break;
		pfns[idx++] = xa_to_value(__xa_erase(&pool->pfn_pool, index));
	}
	xa_unlock(&pool->pfn_pool);

	*actual_count = idx;
}

static void page_pool_clear(struct page_pool *pool)
{
	xa_destroy(&pool->pfn_pool);
}
#endif

typedef void (*done_callback_t)(void *ctx, u32 *pfns, u32 num_pfns);
struct request {
	u64 req_id;
	done_callback_t done_callback;
	struct mutex mutex;
	void *ctx;
	struct list_head node;
	DECLARE_FLEX_ARRAY(u8, cmd);
};

enum {
	VHOST_ALLOC_EVENT_GUEST_READY = 0,
	VHOST_ALLOC_EVENT_GUEST_NOT_READY,
	VHOST_ALLOC_EVENT_GUEST_MALI_SHRINK,
	VHOST_ALLOC_EVENT_MAX
};

static BLOCKING_NOTIFIER_HEAD(g_event_notifier_chain);

int vhost_alloc_notifier_register(struct notifier_block *nb)
{
	return blocking_notifier_chain_register(&g_event_notifier_chain, nb);
}
EXPORT_SYMBOL(vhost_alloc_notifier_register);

int vhost_alloc_notifier_unregister(struct notifier_block *nb)
{
	return blocking_notifier_chain_unregister(&g_event_notifier_chain, nb);
}
EXPORT_SYMBOL(vhost_alloc_notifier_unregister);

static int blocking_signal_event(unsigned long event)
{
	int ret = blocking_notifier_call_chain(&g_event_notifier_chain, event,
					       NULL);
	if (ret & NOTIFY_STOP_MASK)
		pr_err("%s: notifier chain failed with status 0x%x\n", __func__,
		       ret);
	return notifier_to_errno(ret);
}

#define NUM_ALLOC_THREADS   20
#define NUM_RELEASE_THREADS 20

struct request_queue {
	spinlock_t list_lock;
	struct list_head req_list;
};

struct vhost_alloc_vq {
	struct vhost_virtqueue vq;
	u32 num;
};

struct vhost_alloc {
	struct vhost_dev dev;
	struct vhost_alloc_vq vqs[VHOST_ALLOC_VQ_MAX];
	struct vhost_poll poll_alloc;
	struct vhost_poll poll_release;

	spinlock_t list_lock;
	struct list_head wait_list;
	atomic_t next_id;

	struct request_queue alloc_queue;
	struct request_queue release_queue;

	atomic_t is_active;

	uint64_t guest_paddr_start;
	uint64_t guest_paddr_end;

#if defined(CONFIG_DEBUG_FS)
	struct page_pool page_pool;
	struct dentry *debugfs_root;
	struct task_struct *alloc_threads[NUM_ALLOC_THREADS];
	struct task_struct *free_threads[NUM_RELEASE_THREADS];
#endif
};

static struct vhost_alloc __rcu *g_alloc;
static bool is_guest_ready(struct vhost_alloc *n);
static void enqueue_request(struct request_queue *q, struct request *req);

int alloc_guest_page_batch(size_t size, void *pool_ctx, void *callback)
{
	struct vhost_alloc *n;
	size_t chunks;
	int i;

	if (unlikely(size == 0))
		return -EINVAL;

	chunks = DIV_ROUND_UP(size, SZ_2M);

	rcu_read_lock();
	n = rcu_dereference(g_alloc);

	if (!is_guest_ready(n)) {
		rcu_read_unlock();
		return -ENOTSUPP;
	}

	for (i = 0; i < chunks; i++) {
		struct request *req;
		struct alloc_req *cmd;

		req = kzalloc(sizeof(*req) + sizeof(*cmd), GFP_ATOMIC);
		if (!req) {
			/* don't rollback, alloc pages as many as possible */
			break;
		}

		cmd = (struct alloc_req *)req->cmd;
		cmd->req_id = atomic_inc_return(&n->next_id);
		cmd->requested_pages = CHUNK_PAGE_COUNT;
		req->req_id = cmd->req_id;
		req->done_callback = callback;
		req->ctx = pool_ctx;
		enqueue_request(&n->alloc_queue, req);
	}

	vhost_poll_queue(&n->poll_alloc);
	rcu_read_unlock();

	return 0;
}

int free_guest_page_batch(void *pool_ctx, int nr_pages)
{
	int i, chunks, freed_pages, tmp, pgs;
	struct vhost_alloc *n;
	struct request *req;

	if (unlikely(nr_pages == 0))
		return -EINVAL;

	pgs = nr_pages;
	chunks = DIV_ROUND_UP(pgs, MAX_FREE_PFNS);

	pr_info("start to free %d pages, %d chunks\n", pgs, chunks);

	rcu_read_lock();
	n = rcu_dereference(g_alloc);

	if (!is_guest_ready(n)) {
		rcu_read_unlock();
		return -ENOTSUPP;
	}

	freed_pages = 0;
	for (i = 0; i < chunks; i++) {
		struct free_req *cmd;

		req = kzalloc(sizeof(*req) + sizeof(*cmd), GFP_ATOMIC);
		if (!req)
			break;

		cmd = (struct free_req *)req->cmd;
		cmd->num_pages = min_t(typeof(pgs), pgs, MAX_FREE_PFNS);

		drain_guest_pool(cmd->pfns, cmd->num_pages, &tmp, pool_ctx);
		if (tmp != cmd->num_pages) {
			pr_debug("short pages freed!\n");
			break;
		}

		pgs -= tmp;
		freed_pages += tmp;
		cmd->num_pages = tmp;

		enqueue_request(&n->release_queue, req);
	}

	if (freed_pages > 0)
		vhost_poll_queue(&n->poll_release);
	rcu_read_unlock();

	pr_info("freed %d pages\n", freed_pages);

	return freed_pages;
}

static struct request *remove_request_from_wait_list(struct vhost_alloc *n,
						     u64 req_id)
{
	struct request *tmp, *state, *found = NULL;

	spin_lock_bh(&n->list_lock);
	list_for_each_entry_safe(state, tmp, &n->wait_list, node) {
		if (state->req_id == req_id) {
			list_del(&state->node);
			found = state;
			break;
		}
	}
	spin_unlock_bh(&n->list_lock);

	return found;
}

static int retrieve_reply_msg(struct vhost_alloc *n,
			      struct alloc_reply *out_reply, u32 **out_pfns)
{
	struct alloc_reply reply;
	struct iov_iter iter;
	struct vhost_virtqueue *vq = &n->vqs[REPLY_VQ].vq;
	size_t size;
	int ret;

	iov_iter_init(&iter, ITER_SOURCE, &vq->iov[0], 1, sizeof(reply));
	ret = copy_from_iter(&reply, sizeof(reply), &iter);
	if (ret != sizeof(reply)) {
		pr_err("Failed to read reply\n");
		return -EFAULT;
	}

	if (reply.num_pages != 0) {
		size = reply.num_pages * sizeof(u32);
		u32 *pfns = kzalloc(size, GFP_KERNEL);
		if (!pfns) {
			pr_err("Failed to allocate pfns array\n");
			return -ENOMEM;
		}

		iov_iter_init(&iter, ITER_SOURCE, &vq->iov[1], 1, size);
		ret = copy_from_iter(pfns, size, &iter);
		if (ret != size) {
			pr_err("Failed to read pfns array\n");
			kfree(pfns);
			return -EFAULT;
		}

		*out_pfns = pfns;
	}

	*out_reply = reply;
	return 0;
}

struct wait_ctx {
	struct completion comp;
	bool success;
};

static int send_alloc_request(struct vhost_alloc *n, struct request *req)
{
	struct vhost_virtqueue *vq;
	unsigned out, in;
	int ret;
	int head;
	struct alloc_req *cmd = (struct alloc_req *)req->cmd;
	struct iov_iter iter;

	TRACE_FUNC_BEGIN();
	vq = &n->vqs[ALLOC_VQ].vq;

	head = vhost_get_vq_desc(vq, vq->iov, ARRAY_SIZE(vq->iov), &out, &in,
				 NULL, NULL);
	/* On error, stop handling until the next kick. */
	if (unlikely(head < 0)) {
		ret = -EAGAIN;
		pr_err("id:%llu head=%d\n", req->req_id, head);
		goto err_out;
	}
	if (head == vq->num) {
		pr_err("id:%llu No free req descriptors\n", req->req_id);
		ret = -EAGAIN;
		goto err_out;
	}

	iov_iter_init(&iter, ITER_DEST, vq->iov, 1, sizeof(*cmd));
	ret = copy_to_iter(cmd, sizeof(*cmd), &iter);
	if (ret != sizeof(*cmd)) {
		pr_err("id:%llu Failed to write alloc request, ret=%d\n",
		       req->req_id, ret);
		ret = -EFAULT;
		goto err_discard;
	}

	pr_debug("sending alloc request, req_id=%llu, requested_pages=%llu\n",
		 req->req_id, cmd->requested_pages);
	vhost_add_used(vq, head, sizeof(*cmd));

	spin_lock_bh(&n->list_lock);
	list_add_tail(&req->node, &n->wait_list);
	spin_unlock_bh(&n->list_lock);
	TRACE_FUNC_END();
	return 0;

err_discard:
	vhost_discard_vq_desc(vq, 1);
err_out:
	TRACE_FUNC_END();
	return ret;
}

static int send_release_request(struct vhost_alloc *n, struct request *req)
{
	struct vhost_virtqueue *req_vq;
	unsigned out, in;
	int ret;
	int head;
	struct free_req *cmd = (struct free_req *)req->cmd;
	struct iov_iter iter;

	TRACE_FUNC_BEGIN();
	req_vq = &n->vqs[RELEASE_VQ].vq;

	head = vhost_get_vq_desc(req_vq, req_vq->iov, ARRAY_SIZE(req_vq->iov),
				 &out, &in, NULL, NULL);
	/* On error, stop handling until the next kick. */
	if (unlikely(head < 0)) {
		pr_err("head=%d\n", head);
		ret = -EAGAIN;
		goto err_out;
	}
	if (head == req_vq->num) {
		pr_err("No free req descriptors\n");
		ret = -EAGAIN;
		goto err_out;
	}

	iov_iter_init(&iter, ITER_DEST, req_vq->iov, 1, sizeof(*cmd));
	ret = copy_to_iter(cmd, sizeof(*cmd), &iter);
	if (ret != sizeof(*cmd)) {
		pr_err("Failed to write release request, ret=%d\n", ret);
		ret = -EFAULT;
		goto err_discard;
	}

	vhost_add_used(req_vq, head, sizeof(*cmd));
	kfree(req);
	TRACE_FUNC_END();
	return 0;

err_discard:
	vhost_discard_vq_desc(req_vq, 1);
err_out:
	TRACE_FUNC_END();
	return ret;
}

static void request_queue_init(struct request_queue *q)
{
	spin_lock_init(&q->list_lock);
	INIT_LIST_HEAD(&q->req_list);
}

static void enqueue_request(struct request_queue *q, struct request *req)
{
	spin_lock_bh(&q->list_lock);
	list_add_tail(&req->node, &q->req_list);
	spin_unlock_bh(&q->list_lock);
}

static struct request *dequeue_request(struct request_queue *q)
{
	struct request *req;

	spin_lock_bh(&q->list_lock);
	if (list_empty(&q->req_list)) {
		req = NULL;
	} else {
		req = list_first_entry(&q->req_list, struct request, node);
		list_del(&req->node);
	}
	spin_unlock_bh(&q->list_lock);

	return req;
}

static void drain_request_queue(struct request_queue *q)
{
	struct request *req, *tmp;

	spin_lock_bh(&q->list_lock);
	list_for_each_entry_safe(req, tmp, &q->req_list, node) {
		list_del(&req->node);
		if (req->done_callback)
			req->done_callback(req->ctx, NULL, 0);
		kfree(req);
	}
	spin_unlock_bh(&q->list_lock);
}

static void handle_reply(struct vhost_work *work)
{
	unsigned out, in;
	int head;
	struct vhost_virtqueue *vq =
		container_of(work, struct vhost_virtqueue, poll.work);
	struct vhost_alloc *n = container_of(vq->dev, struct vhost_alloc, dev);
	bool added = false;

	mutex_lock(&vq->mutex);
	vhost_disable_notify(&n->dev, vq);

	for (;;) {
		struct alloc_reply reply;
		struct request *req;
		u32 *pfns = NULL;
		int ret;

		head = vhost_get_vq_desc(vq, vq->iov, ARRAY_SIZE(vq->iov), &out,
					 &in, NULL, NULL);
		/* On error, stop handling until the next kick. */
		if (unlikely(head < 0))
			break;
		/* Nothing new?  Wait for eventfd to tell us they refilled. */
		if (head == vq->num) {
			if (unlikely(vhost_enable_notify(&n->dev, vq))) {
				vhost_disable_notify(&n->dev, vq);
				continue;
			}
			break;
		}

		ret = retrieve_reply_msg(n, &reply, &pfns);
		pr_debug("reply: req_id=%llu, num_pages=%u\n", reply.req_id,
			 reply.num_pages);
		if (ret) {
			pr_err("Failed to retrieve reply message, ret=%d\n",
			       ret);
			vhost_discard_vq_desc(vq, 1);
			continue;
		}

		req = remove_request_from_wait_list(n, reply.req_id);
		BUG_ON(req == NULL);

		if (reply.num_pages == 0) {
			pr_err("id:%llu Guest failed to fulfill allocation request\n",
			       reply.req_id);
		}

		BUG_ON(req->done_callback == NULL);
		req->done_callback(req->ctx, pfns, reply.num_pages);
		kfree(pfns);
		kfree(req);
		vhost_add_used(vq, head, 0);
		added = true;
	}
	if (added)
		vhost_signal(&n->dev, vq);
	mutex_unlock(&vq->mutex);
}

typedef int (*request_handler)(struct vhost_alloc *n, struct request *req);

static void handle_req(struct vhost_alloc *n, struct vhost_virtqueue *vq,
		       struct request_queue *q, request_handler req_handler)
{
	struct request *req;
	int ret;

	bool added = false;

	mutex_lock(&vq->mutex);

	/* Avoid further vmexits, we're already processing the virtqueue */
	vhost_disable_notify(&n->dev, vq);

	do {
		req = dequeue_request(q);
		if (!req) {
			vhost_enable_notify(&n->dev, vq);
			break;
		}

		ret = req_handler(n, req);
		if (ret) {
			pr_err("id:%llu Failed to send request, ret=%d\n",
			       req->req_id, ret);

			// We need to requeue the request and wait for the next kick.
			enqueue_request(q, req);

			/* We cannot finish yet if more buffers snuck in while
	     		 * re-enabling notify.
	     		*/
			if (unlikely(vhost_enable_notify(&n->dev, vq))) {
				vhost_disable_notify(&n->dev, vq);
				continue;
			}
			break;
		}

		added = true;
	} while (true);
	if (added)
		vhost_signal(&n->dev, vq);

	mutex_unlock(&vq->mutex);
}

static void handle_alloc_host_kick(struct vhost_work *work)
{
	struct vhost_alloc *n =
		container_of(work, struct vhost_alloc, poll_alloc.work);
	struct vhost_virtqueue *vq = &n->vqs[ALLOC_VQ].vq;
	handle_req(n, vq, &n->alloc_queue, send_alloc_request);
}

static void handle_alloc_guest_kick(struct vhost_work *work)
{
	struct vhost_virtqueue *vq =
		container_of(work, struct vhost_virtqueue, poll.work);
	struct vhost_alloc *n = container_of(vq->dev, struct vhost_alloc, dev);

	handle_req(n, vq, &n->alloc_queue, send_alloc_request);
}

static void handle_release_host_kick(struct vhost_work *work)
{
	struct vhost_alloc *n =
		container_of(work, struct vhost_alloc, poll_release.work);
	struct vhost_virtqueue *vq = &n->vqs[RELEASE_VQ].vq;
	handle_req(n, vq, &n->release_queue, send_release_request);
}

static void handle_release_guest_kick(struct vhost_work *work)
{
	struct vhost_virtqueue *vq =
		container_of(work, struct vhost_virtqueue, poll.work);
	struct vhost_alloc *n = container_of(vq->dev, struct vhost_alloc, dev);

	handle_req(n, vq, &n->release_queue, send_release_request);
}

static void handle_shrinker_guest_kick(struct vhost_work *work)
{
	unsigned out, in;
	int head;
	struct iovec *out_iov, *in_iov;
	struct iov_iter out_iter, in_iter;
	size_t out_size, in_size;
	struct vhost_virtqueue *vq = container_of(work, struct vhost_virtqueue, poll.work);
	struct vhost_alloc *alloc = container_of(vq->dev, struct vhost_alloc, dev);
	bool added = false;
	struct shrink_req req;
	struct shrink_count_res count_resp;
	struct shrink_scan_res scan_resp;

	size_t resp_size = 0;

	mutex_lock(&vq->mutex);
	vhost_disable_notify(&alloc->dev, vq);

	for (;;) {
		int ret;

		head = vhost_get_vq_desc(vq, vq->iov, ARRAY_SIZE(vq->iov), &out, &in, NULL, NULL);
		if (unlikely(head < 0)) {
			pr_err("failed to get vring desc: %d\n", head);
			break;
		}
		if (head == vq->num) {
			if (unlikely(vhost_enable_notify(&alloc->dev, vq))) {
				vhost_disable_notify(&alloc->dev, vq);
				continue;
			}
			break;
		}

		out_iov = vq->iov;
		out_size = iov_length(out_iov, out);
		iov_iter_init(&out_iter, ITER_SOURCE, out_iov, out, out_size);
		ret = copy_from_iter(&req, sizeof(req), &out_iter);
		if (ret != sizeof(req)) {
			pr_err("Failed to copy request, ret=%d\n", ret);
			vhost_discard_vq_desc(vq, 1);
			break;
		}
		/* TODO Only Test */
		if (req.req_id == SHRINK_REQ_COUNT) {
			count_resp.free_pages = shrink_get_free_pages_count();
			resp_size = sizeof(struct shrink_count_res);
		}
		else if (req.req_id == SHRINK_REQ_SCAN) {
			blocking_signal_event(VHOST_ALLOC_EVENT_GUEST_MALI_SHRINK);
			pr_info("shrink req scan is %d\n",  req.scan_free_pages);
			resp_size = sizeof(struct shrink_scan_res);
			scan_resp.freed_pages = shrink_free_pages(req.scan_free_pages);
		} else {
			pr_err("req_id(%d) not support\n", req.req_id);
			vhost_discard_vq_desc(vq, 1);
			break;
		}

		/* TODO Only Test */
		in_iov = &vq->iov[out];
		in_size = iov_length(in_iov, in);
		iov_iter_init(&in_iter, ITER_DEST, in_iov, in, in_size);

		if (req.req_id == SHRINK_REQ_COUNT)
			ret = copy_to_iter(&count_resp, resp_size, &in_iter);
		else
			ret = copy_to_iter(&scan_resp, resp_size, &in_iter);

		if (ret != resp_size) {
			pr_err("Failed to copy result, ret=%d\n", ret);
			vhost_discard_vq_desc(vq, 1);
			break;
		}
		vhost_add_used(vq, head, resp_size);
		added = true;
	}
	if (added)
		vhost_signal(&alloc->dev, vq);
	mutex_unlock(&vq->mutex);
}

static size_t align_up_to(size_t offset, size_t granularity)
{
	// Granularity must be a power of two.
	return (offset + granularity - 1) & ~(granularity - 1);
}

static bool is_guest_ready(struct vhost_alloc *n)
{
	if (n == NULL) {
		return false;
	}

	return atomic_read(&n->is_active);
}

#if defined(CONFIG_DEBUG_FS)
static void allocation_done(void *ctx, u32 *pfns, u32 num_pfns)
{
	struct wait_ctx *wait_ctx = ctx;
	int ret;

	TRACE_FUNC_BEGIN();
	wait_ctx->success = (pfns != NULL);

	if (wait_ctx->success) {
		struct vhost_alloc *n;

		rcu_read_lock();
		n = rcu_dereference(g_alloc);
		if (n) {
			ret = page_pool_add_bulk(&n->page_pool, pfns, num_pfns);
			// TODO: Handle error properly.
			BUG_ON(ret);
			pr_debug("%u pages added to page pool\n", num_pfns);
		}
		rcu_read_unlock();
	}
	complete(&wait_ctx->comp);
	TRACE_FUNC_END();
}

bool alloc_guest_memory(size_t size)
{
	struct wait_ctx ctx = {};
	size_t aligned_size = align_up_to(size, PAGE_SIZE);
	struct request *req;
	struct vhost_alloc *n;
	struct alloc_req *cmd;
	size_t req_size = sizeof(*cmd) + sizeof(*req);

	rcu_read_lock();
	n = rcu_dereference(g_alloc);

	if (!is_guest_ready(n)) {
		rcu_read_unlock();
		return NULL;
	}

	req = kzalloc(req_size, GFP_ATOMIC);
	if (!req) {
		rcu_read_unlock();
		return NULL;
	}

	TRACE_FUNC_BEGIN();
	init_completion(&ctx.comp);

	cmd = (struct alloc_req *)req->cmd;
	cmd->req_id = atomic_inc_return(&n->next_id);
	cmd->requested_pages = aligned_size / PAGE_SIZE;
	req->req_id = cmd->req_id;
	req->done_callback = allocation_done;
	req->ctx = &ctx;

	enqueue_request(&n->alloc_queue, req);
	vhost_poll_queue(&n->poll_alloc);
	rcu_read_unlock();

	wait_for_completion(&ctx.comp);
	TRACE_FUNC_END();

	return ctx.success;
}

void release_guest_memory(u32 *nr_pages_released)
{
	struct request *req;
	struct vhost_alloc *n;
	u32 nr_pages = MAX_FREE_PFNS;
	struct free_req *cmd;
	size_t req_size = sizeof(*cmd) + sizeof(*req);

	rcu_read_lock();
	n = rcu_dereference(g_alloc);

	if (!is_guest_ready(n)) {
		rcu_read_unlock();
		return;
	}

	req = kzalloc(req_size, GFP_ATOMIC);
	BUG_ON(req == NULL);

	cmd = (struct free_req *)req->cmd;
	page_pool_remove_bulk(&n->page_pool, cmd->pfns, nr_pages, &nr_pages);
	pr_debug("%u pages removed from page pool\n", nr_pages);
	if (nr_pages == 0) {
		*nr_pages_released = 0;
		kfree(req);
		rcu_read_unlock();
		return;
	}

	cmd->num_pages = nr_pages;
	enqueue_request(&n->release_queue, req);
	vhost_poll_queue(&n->poll_release);

	rcu_read_unlock();
	*nr_pages_released = nr_pages;
}
#endif

int retrieve_guest_memory_region(phys_addr_t *out_start, phys_addr_t *out_end)
{
	struct vhost_alloc *n;

	rcu_read_lock();
	n = rcu_dereference(g_alloc);

	if (!is_guest_ready(n)) {
		rcu_read_unlock();
		return -ENOTSUPP;
	}

	*out_start = n->guest_paddr_start;
	*out_end = n->guest_paddr_end;
	rcu_read_unlock();

	return 0;
}
EXPORT_SYMBOL(retrieve_guest_memory_region);

#if defined(CONFIG_DEBUG_FS)
static int alloc_show(struct seq_file *s, void *data)
{
	bool success = alloc_guest_memory(SZ_2M);
	seq_printf(s, "%s\n", success ? "success" : "failure");
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(alloc);

static int free_show(struct seq_file *s, void *data)
{
	u32 released;
	release_guest_memory(&released);
	seq_printf(s, "%u pages released\n", released);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(free);

static int state_show(struct seq_file *s, void *data)
{
	struct vhost_alloc *n = s->private;

	seq_printf(s, "active: %d\n", atomic_read(&n->is_active));
	seq_printf(s, "guest_paddr: 0x%llx-0x%llx\n", n->guest_paddr_start,
		   n->guest_paddr_end);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(state);

static int alloc_thread_fn(void *data)
{
	struct vhost_alloc *n = data;

	while (!kthread_should_stop()) {
		if (!is_guest_ready(n))
			break;

		if (!alloc_guest_memory(SZ_2M)) {
			pr_err("Failed to allocate page\n");
			continue;
		}

		msleep(100);
	}

	return 0;
}

static int free_thread_fn(void *data)
{
	struct vhost_alloc *n = data;
	u32 released;

	while (!kthread_should_stop()) {
		if (!is_guest_ready(n))
			break;
		msleep(100);

		release_guest_memory(&released);
	}

	return 0;
}

static int start_stress_show(struct seq_file *s, void *data)
{
	int i;
	struct vhost_alloc *n = s->private;

	for (i = 0; i < NUM_ALLOC_THREADS; i++) {
		n->alloc_threads[i] =
			kthread_create(alloc_thread_fn, n, "vhost_alloc_%d", i);
		if (IS_ERR(n->alloc_threads[i])) {
			pr_err("Failed to create alloc thread %d\n", i);
			n->alloc_threads[i] = NULL;
			continue;
		}
		wake_up_process(n->alloc_threads[i]);
	}

	for (i = 0; i < NUM_RELEASE_THREADS; i++) {
		n->free_threads[i] =
			kthread_create(free_thread_fn, n, "vhost_free_%d", i);
		if (IS_ERR(n->free_threads[i])) {
			pr_err("Failed to create free thread %d\n", i);
			n->free_threads[i] = NULL;
			continue;
		}
		wake_up_process(n->free_threads[i]);
	}

	return 0;
}
DEFINE_SHOW_ATTRIBUTE(start_stress);

static int stop_stress_show(struct seq_file *s, void *data)
{
	int i;
	struct vhost_alloc *n = s->private;

	for (i = 0; i < NUM_ALLOC_THREADS; i++) {
		if (n->alloc_threads[i]) {
			kthread_stop(n->alloc_threads[i]);
			n->alloc_threads[i] = NULL;
		}
	}

	for (i = 0; i < NUM_RELEASE_THREADS; i++) {
		if (n->free_threads[i]) {
			kthread_stop(n->free_threads[i]);
			n->free_threads[i] = NULL;
		}
	}

	return 0;
}
DEFINE_SHOW_ATTRIBUTE(stop_stress);
#endif

static int event_receiver(struct notifier_block *nb, unsigned long action,
			  void *data)
{
	struct vhost_alloc *n;
	int ret = NOTIFY_OK;

	rcu_read_lock();
	n = rcu_dereference(g_alloc);

	switch (action) {
	case VHOST_ALLOC_EVENT_GUEST_READY:
		guest_pool_init_post();
		pr_info("Guest is ready\n");
		break;
	case VHOST_ALLOC_EVENT_GUEST_NOT_READY:
		pr_info("Guest is not ready\n");
		break;
	case VHOST_ALLOC_EVENT_GUEST_MALI_SHRINK:
		pr_info("Mali Shrink\n");
		break;
	default:
		pr_err("Unknown event: %lu\n", action);
		ret = NOTIFY_BAD;
		break;
	}
	rcu_read_unlock();

	return ret;
}

static struct notifier_block event_receiver_nb = {
	.notifier_call = event_receiver,
};

static int vhost_alloc_open(struct inode *inode, struct file *f)
{
	struct vhost_alloc *n = kzalloc(sizeof *n, GFP_KERNEL);
	struct vhost_dev *dev;
	struct vhost_virtqueue **vqs;
#if defined(CONFIG_DEBUG_FS)
	const char *dev_name = "vhost_alloc";
	static struct dentry *root;
#endif
	int ret;

	if (!n)
		return -ENOMEM;

	vqs = kmalloc_array(VHOST_ALLOC_VQ_MAX, sizeof(*vqs), GFP_KERNEL);
	if (!vqs) {
		kfree(n);
		return -ENOMEM;
	}

	dev = &n->dev;
	vqs[ALLOC_VQ] = &n->vqs[ALLOC_VQ].vq;
	vqs[REPLY_VQ] = &n->vqs[REPLY_VQ].vq;
	vqs[RELEASE_VQ] = &n->vqs[RELEASE_VQ].vq;
	vqs[SHRINKER_VQ] = &n->vqs[SHRINKER_VQ].vq;
	n->vqs[ALLOC_VQ].vq.handle_kick = handle_alloc_guest_kick;
	n->vqs[REPLY_VQ].vq.handle_kick = handle_reply;
	n->vqs[RELEASE_VQ].vq.handle_kick = handle_release_guest_kick;
	n->vqs[SHRINKER_VQ].vq.handle_kick = handle_shrinker_guest_kick;
	vhost_dev_init(dev, vqs, VHOST_ALLOC_VQ_MAX, UIO_MAXIOV,
		       VHOST_ALLOC_PKT_WEIGHT, VHOST_ALLOC_WEIGHT, true, NULL);
	INIT_LIST_HEAD(&n->wait_list);
	atomic_set(&n->next_id, 0);
	atomic_set(&n->is_active, false);
	request_queue_init(&n->alloc_queue);
	request_queue_init(&n->release_queue);
	spin_lock_init(&n->list_lock);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
	vhost_poll_init(&n->poll_alloc, handle_alloc_host_kick, EPOLLIN, dev, vqs[ALLOC_VQ]);
	vhost_poll_init(&n->poll_release, handle_release_host_kick, EPOLLIN, dev, vqs[RELEASE_VQ]);
#else
	vhost_poll_init(&n->poll_alloc, handle_alloc_host_kick, EPOLLIN, dev);
	vhost_poll_init(&n->poll_release, handle_release_host_kick, EPOLLIN, dev);
#endif
#if defined(CONFIG_DEBUG_FS)
	page_pool_init(&n->page_pool);
#endif
	ret = guest_pool_init();
	if (ret)
		return ret;

	f->private_data = n;
	rcu_assign_pointer(g_alloc, n);
	synchronize_rcu();

#if defined(CONFIG_DEBUG_FS)
	root = debugfs_create_dir(dev_name, NULL);
	if (IS_ERR(root)) {
		return PTR_ERR(root);
	}
	debugfs_create_file("alloc", 0600, root, n, &alloc_fops);
	debugfs_create_file("free", 0600, root, n, &free_fops);
	debugfs_create_file("start_stress", 0600, root, n, &start_stress_fops);
	debugfs_create_file("stop_stress", 0600, root, n, &stop_stress_fops);
	debugfs_create_file("state", 0600, root, n, &state_fops);
	n->debugfs_root = root;
#endif
	vhost_alloc_notifier_register(&event_receiver_nb);

	return 0;
}

static void clear_all_requests(struct vhost_alloc *n)
{
	struct request *tmp, *req;

	drain_request_queue(&n->alloc_queue);
	drain_request_queue(&n->release_queue);

	spin_lock_bh(&n->list_lock);
	list_for_each_entry_safe(req, tmp, &n->wait_list, node) {
		list_del(&req->node);

		if (req->done_callback)
			req->done_callback(req->ctx, NULL, 0);
		kfree(req);
	}
	spin_unlock_bh(&n->list_lock);
}

static int vhost_alloc_release(struct inode *inode, struct file *f)
{
	struct vhost_alloc *n = f->private_data;

	atomic_set(&n->is_active, false);
	blocking_signal_event(VHOST_ALLOC_EVENT_GUEST_NOT_READY);

	guest_pool_destroy();

	rcu_assign_pointer(g_alloc, NULL);
	synchronize_rcu();

#if defined(CONFIG_DEBUG_FS)
	debugfs_remove_recursive(n->debugfs_root);
#endif
	vhost_dev_flush(&n->dev);
	vhost_dev_stop(&n->dev);
	vhost_dev_cleanup(&n->dev);
	kfree(n->dev.vqs);

	clear_all_requests(n);

	guest_pool_destroy();

#if defined(CONFIG_DEBUG_FS)
	page_pool_clear(&n->page_pool);
#endif
	kfree(n);
	vhost_alloc_notifier_unregister(&event_receiver_nb);

	return 0;
}

static long vhost_alloc_reset_owner(struct vhost_alloc *n)
{
	long err;
	struct vhost_iotlb *umem;

	atomic_set(&n->is_active, false);
	blocking_signal_event(VHOST_ALLOC_EVENT_GUEST_NOT_READY);

	rcu_assign_pointer(g_alloc, NULL);
	synchronize_rcu();

	mutex_lock(&n->dev.mutex);
	err = vhost_dev_check_owner(&n->dev);
	if (err)
		goto done;
	umem = vhost_dev_reset_owner_prepare();
	if (!umem) {
		err = -ENOMEM;
		goto done;
	}
	vhost_dev_flush(&n->dev);
	vhost_dev_stop(&n->dev);
	vhost_dev_reset_owner(&n->dev, umem);

	clear_all_requests(n);

	guest_pool_destroy();
done:
	mutex_unlock(&n->dev.mutex);
	return err;
}

static int vhost_alloc_set_features(struct vhost_alloc *n, u64 features)
{
	struct vhost_virtqueue *vq;

	mutex_lock(&n->dev.mutex);
	if ((features & (1 << VHOST_F_LOG_ALL)) &&
	    !vhost_log_access_ok(&n->dev)) {
		mutex_unlock(&n->dev.mutex);
		return -EFAULT;
	}

	vq = &n->vqs[ALLOC_VQ].vq;
	mutex_lock(&vq->mutex);
	vq->acked_features = features;
	mutex_unlock(&vq->mutex);

	vq = &n->vqs[REPLY_VQ].vq;
	mutex_lock(&vq->mutex);
	vq->acked_features = features;
	mutex_unlock(&vq->mutex);

	vq = &n->vqs[RELEASE_VQ].vq;
	mutex_lock(&vq->mutex);
	vq->acked_features = features;
	mutex_unlock(&vq->mutex);

	vq = &n->vqs[SHRINKER_VQ].vq;
	mutex_lock(&vq->mutex);
	vq->acked_features = features;
	mutex_unlock(&vq->mutex);

	mutex_unlock(&n->dev.mutex);
	return 0;
}

static int vhost_alloc_setup(struct vhost_alloc *valloc, void __user *argp)
{
	struct vhost_vring_state s;

	if (copy_from_user(&s, argp, sizeof(s)))
		return -EFAULT;

	valloc->vqs[s.index].num = s.num;

	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
struct vhost_task {
	bool (*fn)(void *data);
	void *data;
	struct completion exited;
	unsigned long flags;
	struct task_struct *task;
};

static struct task_struct *vhost_worker_get_task(struct vhost_worker *worker)
{
	return worker->vtsk->task;
}
#else
static struct task_struct *vhost_worker_get_task(struct vhost_worker *worker)
{
	return worker->task;
}
#endif

extern struct vhost_worker *vhost_worker_create_with_name(struct vhost_dev *dev,
							  const char *name);
extern void vhost_vq_attach_worker_external(struct vhost_virtqueue *vq,
					    struct vhost_worker *worker);

static int vhost_alloc_create_worker(struct vhost_alloc *n)
{
	cpumask_t mask;
	int i;
	struct vhost_worker *vhost_worker;

	vhost_worker =
		vhost_worker_create_with_name(&n->dev, "vhost_alloc_worker");
	if (vhost_worker) {
		vhost_vq_attach_worker_external(&n->vqs[ALLOC_VQ].vq,
						vhost_worker);
		vhost_vq_attach_worker_external(&n->vqs[RELEASE_VQ].vq,
						vhost_worker);
		vhost_vq_attach_worker_external(&n->vqs[REPLY_VQ].vq,
						vhost_worker);
		vhost_vq_attach_worker_external(&n->vqs[SHRINKER_VQ].vq,
						vhost_worker);
	} else {
		pr_info("not able to create vhost worker\n");
		return -ENOMEM;
	}

	cpumask_clear(&mask);
	for (i = 4; i < 8; i++)
		cpumask_set_cpu(i, &mask);
	set_cpus_allowed_ptr(vhost_worker_get_task(vhost_worker), &mask);
	return 0;
}

static long vhost_alloc_ioctl(struct file *f, unsigned int ioctl,
			      unsigned long arg)
{
	struct vhost_alloc *n = f->private_data;
	void __user *argp = (void __user *)arg;
	u64 __user *featurep = argp;
	u64 features;
	int r;
	switch (ioctl) {
	case VHOST_GET_FEATURES:
		features = VHOST_FEATURES;
		if (copy_to_user(featurep, &features, sizeof features))
			return -EFAULT;
		return 0;
	case VHOST_SET_FEATURES:
		if (copy_from_user(&features, featurep, sizeof features))
			return -EFAULT;

		if (features & ~VHOST_FEATURES)
			return -EOPNOTSUPP;

		return vhost_alloc_set_features(n, features);
	case VHOST_RESET_OWNER:
		return vhost_alloc_reset_owner(n);
    case VHOST_ALLOC_SET_RUNNING:
		return vhost_alloc_create_worker(n);
	default:
		mutex_lock(&n->dev.mutex);
		r = vhost_dev_ioctl(&n->dev, ioctl, argp);
		if (r == -ENOIOCTLCMD)
			r = vhost_vring_ioctl(&n->dev, ioctl, argp);
		if (!r && ioctl == VHOST_SET_VRING_NUM)
			r = vhost_alloc_setup(n, argp);
		vhost_dev_flush(&n->dev);
		mutex_unlock(&n->dev.mutex);

		if (ioctl == VHOST_SET_MEM_TABLE && r == 0) {
			struct vhost_iotlb_map *map;

			map = vhost_iotlb_itree_first(n->dev.umem, 0, -1);
			if (map) {
				n->guest_paddr_start = map->start;
				n->guest_paddr_end = map->last + 1;
			}
			atomic_set(&n->is_active, true);
			blocking_signal_event(VHOST_ALLOC_EVENT_GUEST_READY);
		}
		return r;
	}
}

static const struct file_operations vhost_alloc_fops = {
	.owner = THIS_MODULE,
	.release = vhost_alloc_release,
	.unlocked_ioctl = vhost_alloc_ioctl,
	.compat_ioctl = compat_ptr_ioctl,
	.open = vhost_alloc_open,
	.llseek = noop_llseek,
};

static struct miscdevice vhost_alloc_misc = {
	MISC_DYNAMIC_MINOR,
	"vhost-alloc",
	&vhost_alloc_fops,
};
module_misc_device(vhost_alloc_misc);
MODULE_LICENSE("GPL v2");
