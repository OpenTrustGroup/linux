// SPDX-License-Identifier: GPL-2.0-only

#define pr_fmt(fmt) "guest_page_pool: "fmt

#include <linux/kobject.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/debugfs.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <asm/pgtable.h>

#include "guest_page_pool.h"

enum {
	POOL_STATE_NORMAL,
	POOL_STATE_REFILL,
	POOL_STATE_DRAIN,
};

#if GUEST_POOL_STATS

#define GUEST_POOL_STATS_COUNT	SZ_16M

struct guest_page_pool_stats {
	u64 timestamp;
	int pfn;
	u32 state:4;
#define PAGE_ALLOC_STATE_FAST		0
#define PAGE_ALLOC_STATE_SLOW		1
#define PAGE_ALLOC_STATE_FAIL		2
#define PAGE_FREE_STATE_BACK		3
#define PAGE_STATE_REFILL			4
#define PAGE_STATE_REFILL_DONE		5
#define PAGE_STATE_DRAIN			6
#define PAGE_STATE_SHRINK_COUNT		7
#define PAGE_STATE_SHRINK_SCAN		8
	u32 refill_count:14;
	u32 drain_count:14;
	u64 latency;
	u32 free_pages;
	u32 using_pages;
};

#define DECLARE_STATS_TS \
	ktime_t ___s = 0, ___e = 0, ___l = 0;

#define stats_s_timestamp() \
	do { ___s = ktime_get(); } while (0)

#define stats_e_timestamp() \
	do { \
		___e = ktime_get(); \
		___l = ktime_to_ns(ktime_sub(___e, ___s)); \
	} while (0)

#define stats_rec(_pool, _state, _pfn) \
	do { \
		struct guest_page_pool_stats *___sts; \
		int ___state = _state; \
		if ((_pool)->stats_count >= GUEST_POOL_STATS_COUNT) \
			break; \
		spin_lock(&(_pool)->stats_lock); \
		___sts = &(_pool)->stats[(_pool)->stats_count++]; \
		spin_unlock(&(_pool)->stats_lock); \
		___sts->timestamp = ktime_get(); \
		___sts->state = _state; \
		___sts->refill_count = atomic_long_read(&(_pool)->refill_count); \
		___sts->drain_count = atomic_long_read(&(_pool)->drain_count); \
		___sts->free_pages = atomic_long_read(&(_pool)->free_count); \
		___sts->using_pages = atomic_long_read(&(_pool)->using_count); \
		___sts->pfn = _pfn; \
		___sts->latency = ___l; \
		switch (___state) { \
		case PAGE_ALLOC_STATE_FAST: \
			atomic_long_inc(&(_pool)->using_count); \
			atomic_long_inc(&(_pool)->cache_hit); \
			break; \
		case PAGE_ALLOC_STATE_SLOW: \
			atomic_long_inc(&(_pool)->using_count); \
			fallthrough; \
		case PAGE_ALLOC_STATE_FAIL: \
			atomic_long_inc(&(_pool)->cache_miss); \
			break; \
		case PAGE_FREE_STATE_BACK: \
			atomic_long_dec(&(_pool)->using_count); \
			break; \
		case PAGE_STATE_REFILL: \
			atomic_long_inc(&(_pool)->refill_count); \
			break; \
		case PAGE_STATE_REFILL_DONE: \
			break; \
		case PAGE_STATE_DRAIN: \
			atomic_long_inc(&(_pool)->drain_count); \
			break; \
		default: \
			break; \
		} \
	} while (0)

#else

#define DECLARE_STATS_TS
#define stats_s_timestamp()	do { } while (0)
#define stats_e_timestamp()	do { } while (0)
#define stats_rec(pool, state, pfn) do {} while (0)

#endif

struct guest_page_pool {
#if USE_XA_VERIFY
	struct xarray pfn_pool;
#endif

	struct list_head free_list;
	atomic_long_t free_count;

	spinlock_t lock;
	struct delayed_work watermark_work;
	atomic_t worker_running;
	struct timer_list timer;
	struct kobject *kobj;
	atomic_t state;

	struct dentry *debugfs_dir;

#if GUEST_POOL_STATS
	atomic_long_t using_count;
	/* statistics */
	atomic_long_t cache_hit;
	atomic_long_t cache_miss;
	atomic_long_t refill_count;
	atomic_long_t drain_count;

	struct guest_page_pool_stats *stats;
	u32 stats_count;
	spinlock_t stats_lock;
#endif
};

static struct guest_page_pool __rcu *g_guest_pool;

/* watermarkers */
static atomic_long_t low_wm = ATOMIC_LONG_INIT(SZ_64M >> PAGE_SHIFT);
static atomic_long_t high_wm = ATOMIC_LONG_INIT(SZ_128M >> PAGE_SHIFT);
static u64 monitor_interval_ms = 5000ULL;
/*
 * How many pages should be drained each time:
 *   (free_count - high_wm) * drain_ratio / 100
 */
static u32 drain_ratio = 100;
/*
 * Expose how many pages to shrinker:
 *   (high_wm - low_wm) * shrink_ratio / 100
 */
static u32 shrink_ratio = 75;

#define current_watermark(pool)	(atomic_long_read(&(pool)->free_count))
#define below_low_watermark(pool) \
	(atomic_long_read(&low_wm) > current_watermark(pool))
#define exceed_high_watermark(pool) \
	(current_watermark(pool) >= (atomic_long_read(&high_wm) + CHUNK_PAGE_COUNT))
#define refill_page_count(pool) \
	(atomic_long_read(&high_wm) - current_watermark(pool))
#define drain_page_count(pool) \
	(current_watermark(pool) - atomic_long_read(&high_wm))
#define shrink_page_count(pool) \
	((atomic_long_read(&high_wm) - atomic_long_read(&low_wm)) * shrink_ratio / 100)

/* remote alloc done, fill the page pool */
static void alloc_batch_done(void *ctx, u32 *pfns, u32 num_pfns)
{
	int i;
	struct guest_page_pool *pool;
	struct page *page;
	DECLARE_STATS_TS;

	if (!ctx)
		return;
	pool = ctx;

	stats_s_timestamp();
	for (i = 0; i < num_pfns; i++) {
		page = pfn_to_page(pfns[i]);
		spin_lock(&pool->lock);
		list_add_tail(&page->lru, &pool->free_list);
		spin_unlock(&pool->lock);
#if USE_XA_VERIFY
		xa_lock(&pool->pfn_pool);
		xa_store(&pool->pfn_pool, pfns[i], xa_mk_value(pfns[i]), GFP_ATOMIC);
		xa_unlock(&pool->pfn_pool);
#endif
		atomic_long_inc(&pool->free_count);
	}

	atomic_set(&pool->state, POOL_STATE_NORMAL);
	stats_e_timestamp();
	stats_rec(pool, PAGE_STATE_REFILL_DONE, -1);

	pr_debug("Refilled %u pages\n", num_pfns);
}

static void refill_to_high_watermark(struct guest_page_pool *pool)
{
	long pages_to_fill = refill_page_count(pool);
	DECLARE_STATS_TS;

	if (pages_to_fill < CHUNK_PAGE_COUNT)
		return;

	pr_info("Refilling pool: current=%ldMiB, target=%ldMiB, needed=%ldpages\n",
			atomic_long_read(&pool->free_count) / 256,
			atomic_long_read(&high_wm) / 256,
			pages_to_fill);

	atomic_set(&pool->state, POOL_STATE_REFILL);
	stats_s_timestamp();
	alloc_guest_page_batch(pages_to_fill << PAGE_SHIFT, pool, alloc_batch_done);
	stats_e_timestamp();
	stats_rec(pool, PAGE_STATE_REFILL, -1);
}

static long calc_drain_pages(struct guest_page_pool *pool)
{
	return round_down(drain_page_count(pool) * drain_ratio / 100,
			CHUNK_PAGE_COUNT);
}

static void drain_to_high_watermark(struct guest_page_pool *pool)
{
	long pages_to_free;
	DECLARE_STATS_TS;

	if (atomic_read(&pool->state) == POOL_STATE_DRAIN)
		return;

	pr_info("Draining pool: current=%ldMiB, target=%ldMiB\n",
			atomic_long_read(&pool->free_count) / 256,
			atomic_long_read(&high_wm) / 256);

	stats_s_timestamp();
	atomic_set(&pool->state, POOL_STATE_DRAIN);
	pages_to_free = 0;
	if (exceed_high_watermark(pool)) {
		long pages = calc_drain_pages(pool);
		if (pages)
			free_guest_page_batch(pool, pages);
		pages_to_free += pages;
	}
	stats_e_timestamp();

	stats_rec(pool, PAGE_STATE_DRAIN, -1);
	atomic_set(&pool->state, POOL_STATE_NORMAL);

	pr_info("Drained %ld pages\n", pages_to_free);
}

/*
 * Monitoring the high/low watermark to refill/drain the pages.
 */
static void watermark_worker(struct work_struct *work)
{
	struct guest_page_pool *pool = container_of(work, struct guest_page_pool,
			watermark_work.work);

#if GUEST_POOL_STATS
	pr_info("wm: Free:%ldMiB In-Use:%ldMiB\n",
			atomic_long_read(&pool->free_count) / 256,
			atomic_long_read(&pool->using_count) / 256);
#else
	pr_info("wm: Free:%ldMiB\n",
			atomic_long_read(&pool->free_count) / 256);
#endif
	/* If worker is already running, we just quit */
	if (atomic_cmpxchg(&pool->worker_running, 0, 1)) {
		return;
	}

	if (below_low_watermark(pool)) {
		/* refill if below the low watermark */
		refill_to_high_watermark(pool);
	} else if (exceed_high_watermark(pool)) {
		/* drain if exceed the high watermark */
		drain_to_high_watermark(pool);
	}

	atomic_set(&pool->worker_running, 0);
}

static void timer_callback(struct timer_list *t) {
	struct guest_page_pool *pool = from_timer(pool, t, timer);

	/* if worker is already running just quit */
	if (!atomic_read(&pool->worker_running))
		queue_delayed_work(system_wq, &pool->watermark_work, 0);

	mod_timer(&pool->timer,
			jiffies + msecs_to_jiffies(monitor_interval_ms));
}

#if GUEST_POOL_STATS
void guest_pool_clear_stats(void)
{
	struct guest_page_pool *pool;

	rcu_read_lock();
	pool = rcu_dereference(g_guest_pool);
	if (!pool) {
		rcu_read_unlock();
		return;
	}

	atomic_long_set(&pool->refill_count, 0);
	atomic_long_set(&pool->drain_count, 0);
	spin_lock(&pool->stats_lock);
	memset(pool->stats, 0, sizeof(*pool->stats) * GUEST_POOL_STATS_COUNT);
	pool->stats_count = 0;
	spin_unlock(&pool->stats_lock);

	rcu_read_unlock();
}
EXPORT_SYMBOL(guest_pool_clear_stats);

static int status_show(struct seq_file *m, void *v)
{
	struct guest_page_pool *pool = m->private;
	long hit = atomic_long_read(&pool->cache_hit);
	long miss = atomic_long_read(&pool->cache_miss);
	long total = hit + miss;

	seq_printf(m, "Low watermark: %ld MiB\n",
			   atomic_long_read(&low_wm) / 256);
	seq_printf(m, "High watermark: %ld MiB\n",
			   atomic_long_read(&high_wm) / 256);
	seq_printf(m, "Drain ratio: %%u\n", drain_ratio);
	seq_printf(m, "\n");
	seq_printf(m, "Current Pool Free size: %ld MiB\n",
			   atomic_long_read(&pool->free_count) / 256);
	seq_printf(m, "Current in use size: %ld MiB\n",
			   atomic_long_read(&pool->using_count) / 256);
	seq_printf(m, "Cache hits: %ld\n", hit);
	seq_printf(m, "Cache misses: %ld\n", miss);
	seq_printf(m, "Refill operations: %ld\n", atomic_long_read(&pool->refill_count));
	seq_printf(m, "Drain operations: %ld\n", atomic_long_read(&pool->drain_count));

	if (total > 0) {
		seq_printf(m, "Cache hit ratio: %ld%%\n", (hit * 100) / total);
	}

	return 0;
}

static int status_open(struct inode *inode, struct file *file)
{
	return single_open(file, status_show, inode->i_private);
}

static const struct file_operations status_fops = {
	.open = status_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int stats_show(struct seq_file *m, void *v)
{
	int i;
	struct guest_page_pool *pool = m->private;
	struct guest_page_pool_stats *s;

	seq_puts(m, "timestamp,type,pfn,latency,refill_count,drain_count,free_pages,using_pages\n");

	for (i = 0; i < pool->stats_count; i++) {
		s = &pool->stats[i];
		if (!s->timestamp)
			continue;
		seq_printf(m, "%llu,%u,%d,%llu,%u,%u,%u,%u\n",
				s->timestamp, s->state, s->pfn, s->latency, s->refill_count,
				s->drain_count, s->free_pages, s->using_pages);
	}

	return 0;
}

static int stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, stats_show, inode->i_private);
}

static const struct file_operations stats_fops = {
	.open = stats_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};
#endif

static ssize_t low_watermark_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%ld\n", atomic_long_read(&low_wm));
}

static ssize_t low_watermark_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	long value;
	if (kstrtol(buf, 10, &value))
		return -EINVAL;

	if (value < PAGE_SIZE || value > atomic_long_read(&high_wm))
		return -EINVAL;

	atomic_long_set(&low_wm, value);
	return count;
}

static ssize_t high_watermark_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%ld\n", atomic_long_read(&high_wm));
}

static ssize_t high_watermark_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	long value;
	if (kstrtol(buf, 10, &value))
		return -EINVAL;

	if (value < atomic_long_read(&low_wm))
		return -EINVAL;

	atomic_long_set(&high_wm, value);
	return count;
}

static ssize_t monitor_interval_ms_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%llu(ms)\n", monitor_interval_ms);
}

static ssize_t monitor_interval_ms_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	long value;
	if (kstrtol(buf, 10, &value))
		return -EINVAL;

	monitor_interval_ms = value;
	return count;
}

static ssize_t drain_ratio_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%u\n", drain_ratio);
}

static ssize_t drain_ratio_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	long value;

	if (kstrtol(buf, 10, &value))
		return -EINVAL;

	if (value < 0 || value > 100)
		return -EINVAL;

	drain_ratio = value;
	return count;
}

static ssize_t shrink_ratio_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%u\n", shrink_ratio);
}

static ssize_t shrink_ratio_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	long value;

	if (kstrtol(buf, 10, &value))
		return -EINVAL;

	if (value < 0 || value > 100)
		return -EINVAL;

	shrink_ratio = value;
	return count;
}

static struct kobj_attribute low_watermark_attr =
	__ATTR(low_watermark, 0644, low_watermark_show, low_watermark_store);

static struct kobj_attribute high_watermark_attr =
	__ATTR(high_watermark, 0644, high_watermark_show, high_watermark_store);

static struct kobj_attribute monitor_interval_ms_attr =
	__ATTR(monitor_interval_ms, 0644, monitor_interval_ms_show, monitor_interval_ms_store);

static struct kobj_attribute drain_ratio_attr =
	__ATTR(drain_ratio, 0644, drain_ratio_show, drain_ratio_store);

static struct kobj_attribute shrink_ratio_attr =
	__ATTR(shrink_ratio, 0644, shrink_ratio_show, shrink_ratio_store);

static struct attribute *pagepool_attrs[] = {
	&low_watermark_attr.attr,
	&high_watermark_attr.attr,
	&monitor_interval_ms_attr.attr,
	&drain_ratio_attr.attr,
	&shrink_ratio_attr.attr,
	NULL,
};

static struct attribute_group pagepool_attr_group = {
	.name = "guest_pagepool",
	.attrs = pagepool_attrs,
};

void guest_pool_init_post(void)
{
	struct guest_page_pool *pool;

	rcu_read_lock();
	pool = rcu_dereference(g_guest_pool);
	if (!pool) {
		rcu_read_unlock();
		return;
	}

	mod_timer(&pool->timer, jiffies + msecs_to_jiffies(100));

	rcu_read_unlock();
}

u32 shrink_get_free_pages_count(void)
{
	struct guest_page_pool *pool;
	long count;
	DECLARE_STATS_TS;

	rcu_read_lock();
	pool = rcu_dereference(g_guest_pool);
	if (!pool) {
		rcu_read_unlock();
		return 0;
	}

	stats_s_timestamp();
	count = shrink_page_count(pool);
	if (count < 0)
		count = 0;
	stats_e_timestamp();
	stats_rec(pool, PAGE_STATE_SHRINK_COUNT, -1);

	rcu_read_unlock();

	pr_debug("shrinker ask count of free pages, answer: %ld\n", count);
	return (u32)count;
}

u32 shrink_free_pages(u32 pages_to_free)
{
	struct guest_page_pool *pool;
	u32 state;
	int count;
	DECLARE_STATS_TS;

	if (unlikely(pages_to_free == 0))
		return 0;

	rcu_read_lock();
	pool = rcu_dereference(g_guest_pool);
	if (!pool) {
		rcu_read_unlock();
		return 0;
	}

	count = 0;
	stats_s_timestamp();
	state = atomic_read(&pool->state);
	if (state != POOL_STATE_REFILL && state != POOL_STATE_DRAIN) {
		count = free_guest_page_batch(pool, pages_to_free);
		if (count < 0)
			count = 0;
	}
	stats_e_timestamp();
	stats_rec(pool, PAGE_STATE_SHRINK_SCAN, count);

	rcu_read_unlock();
	pr_info("shrinker ask to free pages, freed: %d\n", count);

	return (u32)count;
}

void drain_guest_pool(u32 *pfns, u32 count, u32 *actual_count, void *ctx)
{
	struct guest_page_pool *pool;
	struct page *page;
	int i, j;

	if (!ctx)
		return;
	pool = ctx;

	for (i = 0, j = 0; i < count; i++) {
		spin_lock(&pool->lock);
		page = list_first_entry_or_null(&pool->free_list, struct page, lru);
		if (page) {
			list_del(&page->lru);
			spin_unlock(&pool->lock);

#if USE_XA_VERIFY
			xa_lock(&pool->pfn_pool);
			pfns[j++] = xa_to_value(xa_erase(&pool->pfn_pool, page_to_pfn(page)));
			xa_unlock(&pool->pfn_pool);
#else
			pfns[j++] = page_to_pfn(page);
#endif

			atomic_long_dec(&pool->free_count);
		} else {
			spin_unlock(&pool->lock);
		}
	}

	if (actual_count)
		*actual_count = j;
}

int guest_pool_init(void)
{
	struct guest_page_pool *pool;
	int ret;

	pr_info("Initializing page pool\n");

	pool = kzalloc(sizeof(*pool), GFP_KERNEL);
	if (!pool)
		return -ENOMEM;

	RCU_INIT_POINTER(g_guest_pool, pool);

#if USE_XA_VERIFY
	xa_init_flags(&pool->pfn_pool, XA_FLAGS_ALLOC1);
#endif

	INIT_LIST_HEAD(&pool->free_list);
	atomic_long_set(&pool->free_count, 0);
	spin_lock_init(&pool->lock);
	atomic_set(&pool->worker_running, 0);
	INIT_DELAYED_WORK(&pool->watermark_work, watermark_worker);

	timer_setup(&pool->timer, timer_callback, 0);

	pool->kobj = kobject_create_and_add("guest_pagepool", kernel_kobj);
	if (!pool->kobj) {
		pr_err("Failed to create sysfs kobject\n");
		ret = -ENOMEM;
		goto free_pool;
	}

	ret = sysfs_create_group(pool->kobj, &pagepool_attr_group);
	if (ret) {
		pr_err("Failed to create sysfs group: %d\n", ret);
		goto free_kobj;
	}

#if GUEST_POOL_STATS
	atomic_long_set(&pool->using_count, 0);
	atomic_long_set(&pool->cache_hit, 0);
	atomic_long_set(&pool->cache_miss, 0);
	atomic_long_set(&pool->refill_count, 0);
	atomic_long_set(&pool->drain_count, 0);

	spin_lock_init(&pool->stats_lock);

	pool->stats = kvcalloc(GUEST_POOL_STATS_COUNT, sizeof(struct guest_page_pool_stats),
			GFP_KERNEL);
	if (!pool->stats) {
		ret = -ENOMEM;
		goto remove_sysfs;
	}

	pool->debugfs_dir = debugfs_create_dir("guest_pagepool", NULL);
	if (!pool->debugfs_dir) {
		ret = -ENODEV;
		pr_err("Failed to create debugfs directory\n");
		goto free_stats;
	}

	debugfs_create_file("status", 0400, pool->debugfs_dir, pool, &status_fops);
	debugfs_create_file("stats", 0400, pool->debugfs_dir, pool, &stats_fops);
#endif

	pr_info("page pool initialized\n");
	return 0;

#if GUEST_POOL_STATS
free_stats:
	kvfree(pool->stats);
remove_sysfs:
	sysfs_remove_group(pool->kobj, &pagepool_attr_group);
#endif
free_kobj:
	kobject_put(pool->kobj);
free_pool:
	pool = rcu_dereference_protected(g_guest_pool, 1);
	rcu_assign_pointer(g_guest_pool, NULL);
	synchronize_rcu();
	kfree(pool);

	return ret;
}

void guest_pool_destroy(void)
{
	struct guest_page_pool *pool;

	pr_info("Exiting page pool\n");

	pool = rcu_dereference_protected(g_guest_pool, 1);
	if (!pool) {
		printk("pool has already been freed!\n");
		return;
	}

	rcu_assign_pointer(g_guest_pool, NULL);
	synchronize_rcu();

	del_timer_sync(&pool->timer);
	cancel_delayed_work_sync(&pool->watermark_work);
	debugfs_remove_recursive(pool->debugfs_dir);
	sysfs_remove_group(pool->kobj, &pagepool_attr_group);
	kobject_put(pool->kobj);

#if USE_XA_VERIFY
	xa_destroy(&pool->pfn_pool);
#endif

#if GUEST_POOL_STATS
	kvfree(pool->stats);
#endif

	kfree(pool);

	pr_info("page pool exited\n");
}

static struct page *alloc_guest_page_fast(struct guest_page_pool *pool)
{
	struct page *page;
	spin_lock(&pool->lock);
	page = list_first_entry_or_null(&pool->free_list, struct page, lru);
	if (likely(page)) {
		list_del(&page->lru);
		atomic_long_dec(&pool->free_count);
	}
	spin_unlock(&pool->lock);
	return page;
}

static struct page *alloc_guest_page_slow(struct guest_page_pool *pool)
{
	struct page *page;
	int i;

	i = 0;
	/* wait until we got page or encounter an error */
	while (true) {
		page = alloc_guest_page_fast(pool);
		if (page)
			return page;

		rcu_read_unlock();

		usleep_range(100, 200);

		rcu_read_lock();
		pool = rcu_dereference(g_guest_pool);
		if (!pool)
			break;

		i++;
		if (i > 25000) {
			break;
		}
	}

	return NULL;
}

struct page *alloc_guest_page(size_t size)
{
	struct page *page;
	struct guest_page_pool *pool;
	DECLARE_STATS_TS;

	rcu_read_lock();
	pool = rcu_dereference(g_guest_pool);
	if (!pool) {
		rcu_read_unlock();
		return NULL;
	}

	/* wakeup worker to refill */
	if (unlikely(below_low_watermark(pool)))
		queue_delayed_work(system_wq, &pool->watermark_work, 0);

	stats_s_timestamp();
	page = alloc_guest_page_fast(pool);
	stats_e_timestamp();

	/* slow path */
	if (unlikely(!page)) {
		stats_s_timestamp();
		page = alloc_guest_page_slow(pool);
		stats_e_timestamp();
		stats_rec(pool, page ? PAGE_ALLOC_STATE_SLOW :
				PAGE_ALLOC_STATE_FAIL, page_to_pfn(page));
	} else {
		stats_rec(pool, PAGE_ALLOC_STATE_FAST, page_to_pfn(page));
	}

	rcu_read_unlock();

	return page;
}
EXPORT_SYMBOL(alloc_guest_page);

void release_guest_page(struct page *page)
{
	struct guest_page_pool *pool;
	DECLARE_STATS_TS;

	rcu_read_lock();
	pool = rcu_dereference(g_guest_pool);
	if (!pool) {
		rcu_read_unlock();
		return;
	}

	stats_s_timestamp();
	spin_lock(&pool->lock);
	list_add_tail(&page->lru, &pool->free_list);
	spin_unlock(&pool->lock);
	atomic_long_inc(&pool->free_count);

	stats_e_timestamp();
	stats_rec(pool, PAGE_FREE_STATE_BACK, page_to_pfn(page));

	rcu_read_unlock();
}
EXPORT_SYMBOL(release_guest_page);
