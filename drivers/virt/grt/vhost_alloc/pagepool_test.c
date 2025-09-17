// SPDX-License-Identifier: GPL-2.0-only

#define pr_fmt(fmt) "page_pool_test: "fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/ktime.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <uapi/linux/sched/types.h>
#include <linux/sched.h>
#include <linux/random.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/completion.h>
#include <linux/jiffies.h>
#include <linux/uaccess.h>

#include "guest_page_pool.h"

#define POOL_SIZE_GB 4
#define POOL_SIZE_PAGES (POOL_SIZE_GB * 1024 * 1024 / 4) /* 4GiB in pages (4KiB each) */
#define BURST_SIZE_MB 200
#define BURST_SIZE_PAGES (BURST_SIZE_MB * 1024 / 4)
#define MAX_BURST_THREADS 16
#define MAX_BURST_DURATION_NS (16 * 1000 * 1000) /* 16ms in ns */
#define MAX_OP_RECORDS (POOL_SIZE_PAGES * 2)	 /* For test4 */

struct test_data {
	u64 *latencies;
	struct page **pages;
	size_t count;
	size_t capacity;
	ktime_t start_time;
	char name[20];
};

struct burst_thread_data {
	struct task_struct *task;
	int thread_id;
	int num_threads;
	int pages_per_thread;
	u64 *records;
	struct page **thread_pages;
	atomic_t *ready_count;
	struct completion *start_signal;
	struct completion done;
	ktime_t burst_start;
};

enum op_type {
	OP_ALLOC,
	OP_FREE
};

struct mixed_op_record {
	u64 latency;
	enum op_type type;
	struct page *page;
};

static struct test_data test1_data;
static struct test_data test2_data;
static struct test_data test3_data;
static struct mixed_op_record *test4_records;
static size_t test4_count;
static size_t test4_capacity;

static struct page **allocated_pages;
static size_t allocated_count;
static size_t allocated_capacity;
static DEFINE_MUTEX(page_pool_lock);

static int prealloc_test_data(struct test_data *data, size_t capacity,
		const char *name)
{
	if (!data->latencies) {
		data->latencies = vzalloc(capacity * sizeof(u64));
		if (!data->latencies)
			return -ENOMEM;
	}

	if (!data->pages) {
		data->pages = vzalloc(capacity * sizeof(struct page *));
		if (!data->pages) {
			vfree(data->latencies);
			return -ENOMEM;
		}
	}

	data->capacity = capacity;
	data->count = 0;
	strncpy(data->name, name, sizeof(data->name) - 1);
	data->name[sizeof(data->name) - 1] = '\0';
	return 0;
}

static void free_test_data(struct test_data *data)
{
	if (data->latencies) {
		vfree(data->latencies);
		data->latencies = NULL;
	}

	if (data->pages) {
		vfree(data->pages);
		data->pages = NULL;
	}

	data->capacity = 0;
	data->count = 0;
}

static int init_test4(size_t capacity)
{
	if (!test4_records) {
		test4_records = vzalloc(capacity * sizeof(struct mixed_op_record));
		if (!test4_records)
			return -ENOMEM;
	}

	test4_capacity = capacity;
	test4_count = 0;

	if (!allocated_pages) {
		allocated_pages = vzalloc(POOL_SIZE_PAGES * sizeof(struct page *));
		if (!allocated_pages) {
			vfree(test4_records);
			return -ENOMEM;
		}
	}

	allocated_capacity = POOL_SIZE_PAGES;
	allocated_count = 0;

	return 0;
}

static void cleanup_test4(void)
{
	if (test4_records) {
		vfree(test4_records);
		test4_records = NULL;
	}

	if (allocated_pages) {
		vfree(allocated_pages);
		allocated_pages = NULL;
	}

	test4_capacity = 0;
	test4_count = 0;
	allocated_capacity = 0;
	allocated_count = 0;
}

static int test_sequential_alloc(void)
{
	int ret = prealloc_test_data(&test1_data, POOL_SIZE_PAGES, "sequential_alloc");
	if (ret) {
		pr_err("Failed to preallocate memory for test1\n");
		return ret;
	}

	pr_info("Starting sequential alloc test (4GiB, %u pages)\n", POOL_SIZE_PAGES);

	test1_data.start_time = ktime_get();

	for (size_t i = 0; i < POOL_SIZE_PAGES; i++) {
		ktime_t start, end;
		u64 latency;

		start = ktime_get();
		test1_data.pages[i] = alloc_guest_page(PAGE_SIZE);
		end = ktime_get();

		if (!test1_data.pages[i]) {
			pr_err("Allocation failed at page %zu\n", i);
			break;
		}

		latency = ktime_to_ns(ktime_sub(end, start));
		test1_data.latencies[i] = latency;
		test1_data.count++;

		if (POOL_SIZE_PAGES > 10 && i % (POOL_SIZE_PAGES / 10) == 0) {
			unsigned int percent = (i * 100) / POOL_SIZE_PAGES;
			pr_info("Allocated %zu pages (%u%%)\n", i, percent);
		}
	}

	ktime_t total_time = ktime_sub(ktime_get(), test1_data.start_time);
	pr_info("Sequential alloc test completed. Allocated %zu pages in %lld ms\n",
			test1_data.count, ktime_to_ms(total_time));

	return 0;
}

static int test_sequential_free(void)
{
	int ret;

	if (!test1_data.pages || test1_data.count == 0) {
		pr_err("No pages to free. Run test1 first\n");
		return -EINVAL;
	}

	ret = prealloc_test_data(&test2_data, test1_data.count, "sequential_free");
	if (ret) {
		pr_err("Failed to preallocate memory for test2\n");
		return ret;
	}

	pr_info("Starting sequential free test (%zu pages)\n", test1_data.count);

	test2_data.start_time = ktime_get();

	for (size_t i = 0; i < test1_data.count; i++) {
		ktime_t start, end;
		u64 latency;

		if (!test1_data.pages[i]) {
			pr_warn("Skipping null page at index %zu\n", i);
			continue;
		}

		start = ktime_get();
		release_guest_page(test1_data.pages[i]);
		end = ktime_get();

		latency = ktime_to_ns(ktime_sub(end, start));
		test2_data.latencies[i] = latency;
		test2_data.count++;

		/* Clear pointer to avoid double-free */
		test1_data.pages[i] = NULL;
	}

	ktime_t total_time = ktime_sub(ktime_get(), test2_data.start_time);
	pr_info("Sequential free test completed. Freed %zu pages in %lld ms\n",
			test2_data.count, ktime_to_ms(total_time));

	/* Reset test1 data */
	test1_data.count = 0;

	return 0;
}

static int burst_alloc_thread(void *data)
{
	struct burst_thread_data *tdata = data;
	int pages_to_alloc = tdata->pages_per_thread;

	struct sched_param param = { .sched_priority = 50 };
	sched_setscheduler(current, SCHED_FIFO, &param);

	atomic_inc(tdata->ready_count);
	wait_for_completion(tdata->start_signal);

	for (int i = 0; i < pages_to_alloc; i++) {
		ktime_t start, end;

		start = ktime_get();
		struct page *pg = alloc_guest_page(PAGE_SIZE);
		end = ktime_get();

		if (!pg) {
			pr_warn("Burst allocation failed in thread %d\n", tdata->thread_id);
			tdata->thread_pages[i] = NULL;
		} else {
			tdata->thread_pages[i] = pg;
		}

		ktime_t burst_offset = ktime_sub(end, tdata->burst_start);
		tdata->records[i] = ktime_to_ns(burst_offset);
	}

	complete(&tdata->done);
	return 0;
}

static int test_burst_alloc(int burst_interval_ms)
{
	const int num_bursts = 100;
	int num_threads = min(MAX_BURST_THREADS, (int)(BURST_SIZE_PAGES / 128));
	int pages_per_thread = BURST_SIZE_PAGES / num_threads;
	int remaining_pages = BURST_SIZE_PAGES % num_threads;

	pr_info("Starting burst alloc test: interval=%dms, %d threads, %d pages/thread\n",
			burst_interval_ms, num_threads, pages_per_thread);

	int ret = prealloc_test_data(&test3_data, num_bursts * BURST_SIZE_PAGES, "burst_alloc");
	if (ret) {
		pr_err("Failed to preallocate memory for test3\n");
		return ret;
	}

	struct burst_thread_data threads[MAX_BURST_THREADS];
	atomic_t ready_count = ATOMIC_INIT(0);
	DECLARE_COMPLETION(start_signal);

	for (int burst = 0; burst < num_bursts; burst++) {
		struct page **burst_pages = vzalloc(BURST_SIZE_PAGES * sizeof(struct page *));
		if (!burst_pages) {
			pr_err("Failed to allocate burst page array\n");
			break;
		}

		int thread_idx = 0;
		for (int i = 0; i < num_threads; i++) {
			int pages_for_this_thread = pages_per_thread;
			if (i < remaining_pages) pages_for_this_thread++;

			threads[i].thread_id = i;
			threads[i].num_threads = num_threads;
			threads[i].pages_per_thread = pages_for_this_thread;
			threads[i].ready_count = &ready_count;
			threads[i].start_signal = &start_signal;
			threads[i].records = &test3_data.latencies[test3_data.count];

			threads[i].thread_pages = vzalloc(pages_for_this_thread * sizeof(struct page *));
			if (!threads[i].thread_pages) {
				pr_err("Failed to allocate page array for thread %d\n", i);
				continue;
			}

			init_completion(&threads[i].done);

			char name[16];
			snprintf(name, sizeof(name), "burst_alloc_%d", i);

			threads[i].task = kthread_create(burst_alloc_thread, &threads[i], name);
			if (IS_ERR(threads[i].task)) {
				pr_err("Failed to create thread %d\n", i);
				vfree(threads[i].thread_pages);
				continue;
			}

			wake_up_process(threads[i].task);
			thread_idx++;
		}

		while (atomic_read(&ready_count) < thread_idx) {
			usleep_range(100, 200);
		}

		ktime_t burst_start = ktime_get();
		for (int i = 0; i < thread_idx; i++) {
			threads[i].burst_start = burst_start;
		}

		reinit_completion(&start_signal);
		complete_all(&start_signal);

		int pages_allocated = 0;

		for (int i = 0; i < thread_idx; i++) {
			unsigned long timeout = nsecs_to_jiffies(MAX_BURST_DURATION_NS + 1000000);
			if (wait_for_completion_timeout(&threads[i].done, timeout) == 0) {
				pr_warn("Thread %d didn't finish in time\n", i);
				kthread_stop(threads[i].task);
			}

			for (int j = 0; j < threads[i].pages_per_thread; j++) {
				if (pages_allocated < BURST_SIZE_PAGES) {
					burst_pages[pages_allocated] = threads[i].thread_pages[j];
					pages_allocated++;
				}
			}

			test3_data.count += threads[i].pages_per_thread;

			vfree(threads[i].thread_pages);
			threads[i].thread_pages = NULL;
		}

		ktime_t free_start = ktime_get();
		for (int i = 0; i < pages_allocated; i++) {
			if (burst_pages[i]) {
				release_guest_page(burst_pages[i]);
			}
		}
		u64 free_time = ktime_to_ns(ktime_sub(ktime_get(), free_start));

		vfree(burst_pages);

		pr_info("Burst %d/%d: %d pages allocated, freed in %lld us\n",
				burst + 1, num_bursts, pages_allocated, free_time / 1000);

		if (burst < num_bursts - 1) {
			msleep(burst_interval_ms);
		}

		atomic_set(&ready_count, 0);
		reinit_completion(&start_signal);
	}

	pr_info("Burst alloc test completed. Total operations: %zu\n", test3_data.count);
	return 0;
}

static struct page *get_random_allocated_page(void)
{
	if (allocated_count == 0)
		return NULL;

	unsigned int idx;
	get_random_bytes(&idx, sizeof(idx));
	idx %= allocated_count;

	struct page *pg = allocated_pages[idx];

	allocated_pages[idx] = allocated_pages[allocated_count - 1];
	allocated_count--;

	return pg;
}

static int test_mixed_operations(void)
{
	const size_t total_ops = 1000000;
	const size_t warmup_pages = POOL_SIZE_PAGES / 2;

	pr_info("Starting mixed operations test (%zu operations)\n", total_ops);

	int ret = init_test4(total_ops);
	if (ret) {
		pr_err("Failed to initialize test4 data\n");
		return ret;
	}

	pr_info("Warming up: allocating %zu pages\n", warmup_pages);
	for (size_t i = 0; i < warmup_pages; i++) {
		struct page *pg = alloc_guest_page(PAGE_SIZE);
		if (!pg) {
			pr_err("Warmup allocation failed at %zu\n", i);
			break;
		}

		if (allocated_count < allocated_capacity) {
			allocated_pages[allocated_count++] = pg;
		} else {
			release_guest_page(pg);
		}
	}

	/* mixed operations */
	for (size_t i = 0; i < total_ops; i++) {
		enum op_type op;
		ktime_t start, end;
		unsigned int rand_val;

		if (allocated_count == 0) {
			op = OP_ALLOC;
		} else if (allocated_count >= allocated_capacity) {
			op = OP_FREE;
		} else {
			get_random_bytes(&rand_val, sizeof(rand_val));
			op = (rand_val % 2) ? OP_ALLOC : OP_FREE;
		}

		struct page *pg = NULL;
		start = ktime_get();

		if (op == OP_ALLOC) {
			pg = alloc_guest_page(PAGE_SIZE);
			if (pg && allocated_count < allocated_capacity) {
				allocated_pages[allocated_count++] = pg;
			} else if (pg) {
				release_guest_page(pg);
				pg = NULL;
			}
		} else {
			pg = get_random_allocated_page();
			if (pg) {
				release_guest_page(pg);
			}
		}

		end = ktime_get();

		if (test4_count < test4_capacity) {
			struct mixed_op_record *rec = &test4_records[test4_count++];
			rec->latency = ktime_to_ns(ktime_sub(end, start));
			rec->type = op;
			rec->page = pg;
		}

		if (total_ops > 10 && i % (total_ops / 10) == 0) {
			unsigned int percent = (i * 100) / total_ops;
			pr_info("Completed %zu operations (%u%%), pool size: %zu\n",
					i, percent, allocated_count);
		}
	}

	pr_info("Cleaning up: freeing %zu remaining pages\n", allocated_count);
	for (size_t i = 0; i < allocated_count; i++) {
		if (allocated_pages[i]) {
			release_guest_page(allocated_pages[i]);
		}
	}
	allocated_count = 0;

	pr_info("Mixed operations test completed. Total operations: %zu\n", test4_count);
	return 0;
}

static struct proc_dir_entry *test_dir;

static ssize_t test_write(struct file *file, const char __user *buf,
						  size_t count, loff_t *ppos)
{
	char cmd[32];

	if (count > sizeof(cmd) - 1)
		return -EINVAL;

	if (copy_from_user(cmd, buf, count))
		return -EFAULT;

	cmd[count] = '\0';

	if (strncmp(cmd, "test1", 5) == 0) {
		test_sequential_alloc();
	} else if (strncmp(cmd, "test2", 5) == 0) {
		test_sequential_free();
	} else if (strncmp(cmd, "test3_20", 8) == 0) {
		test_burst_alloc(20);
	} else if (strncmp(cmd, "test3_50", 8) == 0) {
		test_burst_alloc(50);
	} else if (strncmp(cmd, "test3_100", 9) == 0) {
		test_burst_alloc(100);
	} else if (strncmp(cmd, "test3_200", 9) == 0) {
		test_burst_alloc(200);
	} else if (strncmp(cmd, "test3_500", 9) == 0) {
		test_burst_alloc(500);
	} else if (strncmp(cmd, "test3_1000", 10) == 0) {
		test_burst_alloc(1000);
	} else if (strncmp(cmd, "test4", 5) == 0) {
		test_mixed_operations();
	} else if (strncmp(cmd, "clear", 5) == 0) {
		guest_pool_clear_stats();
	} else {
		pr_warn("Unknown test command: %s\n", cmd);
		return -EINVAL;
	}

	return count;
}

static int test_show(struct seq_file *m, void *v)
{
	seq_puts(m, "Page Pool Test Module\n");
	seq_puts(m, "Available commands:\n");
	seq_puts(m, " test1	- Sequential allocation (4GiB)\n");
	seq_puts(m, " test2	- Sequential free (4GiB)\n");
	seq_puts(m, " test3_20 - Burst alloc with 20ms interval\n");
	seq_puts(m, " test3_50 - Burst alloc with 50ms interval\n");
	seq_puts(m, " test3_100 - Burst alloc with 100ms interval\n");
	seq_puts(m, " test3_200 - Burst alloc with 200ms interval\n");
	seq_puts(m, " test3_500 - Burst alloc with 500ms interval\n");
	seq_puts(m, " test3_1000 - Burst alloc with 1000ms interval\n");
	seq_puts(m, " test4	- Mixed operations test\n");
	seq_puts(m, "\n");
	seq_puts(m, "Use 'cat /proc/page_pool_test/records' to export test data\n");

	return 0;
}

static int test_open(struct inode *inode, struct file *file)
{
	return single_open(file, test_show, NULL);
}

static const struct proc_ops test_fops = {
	.proc_open	= test_open,
	.proc_read	= seq_read,
	.proc_write   = test_write,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

static ssize_t records_read(struct file *file, char __user *buf,
							size_t count, loff_t *ppos)
{
	static const char header[] = "test_name,operation,latency_ns\n";
	static size_t header_len = sizeof(header) - 1;

	size_t total_size = 0;
	size_t copied = 0;
	char *kbuf = NULL;
	size_t kbuf_size = 0;
	loff_t pos = *ppos;

	if (pos == 0) {
		if (copy_to_user(buf, header, min(count, header_len)))
			return -EFAULT;
		*ppos = min(count, header_len);
		return min(count, header_len);
	}

	pos -= header_len;
	if (pos < 0)
		return 0;

	size_t test1_size = test1_data.count * sizeof(u64);
	size_t test2_size = test2_data.count * sizeof(u64);
	size_t test3_size = test3_data.count * sizeof(u64);
	size_t test4_size = test4_count * sizeof(struct mixed_op_record);

	total_size = test1_size + test2_size + test3_size + test4_size;

	if (pos >= total_size)
		return 0;

	kbuf_size = min_t(size_t, count, PAGE_SIZE);
	kbuf = kmalloc(kbuf_size, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	size_t kbuf_pos = 0;
	loff_t current_pos = pos;

	if (current_pos < test1_size) {
		size_t to_copy = min(kbuf_size, test1_size - current_pos);
		memcpy(kbuf, (char *)test1_data.latencies + current_pos, to_copy);
		kbuf_pos = to_copy;
		current_pos = 0;
	} else {
		current_pos -= test1_size;
	}

	if (kbuf_pos == 0 && current_pos < test2_size) {
		size_t to_copy = min(kbuf_size, test2_size - current_pos);
		memcpy(kbuf, (char *)test2_data.latencies + current_pos, to_copy);
		kbuf_pos = to_copy;
		current_pos = 0;
	} else if (kbuf_pos == 0) {
		current_pos -= test2_size;
	}

	if (kbuf_pos == 0 && current_pos < test3_size) {
		size_t to_copy = min(kbuf_size, test3_size - current_pos);
		memcpy(kbuf, (char *)test3_data.latencies + current_pos, to_copy);
		kbuf_pos = to_copy;
		current_pos = 0;
	} else if (kbuf_pos == 0) {
		current_pos -= test3_size;
	}

	if (kbuf_pos == 0 && current_pos < test4_size) {
		size_t to_copy = min(kbuf_size, test4_size - current_pos);
		memcpy(kbuf, (char *)test4_records + current_pos, to_copy);
		kbuf_pos = to_copy;
	}

	if (kbuf_pos > 0) {
		if (copy_to_user(buf, kbuf, kbuf_pos)) {
			kfree(kbuf);
			return -EFAULT;
		}
		copied = kbuf_pos;
	}

	kfree(kbuf);
	*ppos += copied;
	return copied;
}

static const struct proc_ops records_fops = {
	.proc_read	= records_read,
	.proc_lseek   = generic_file_llseek,
};

static int meta_show(struct seq_file *m, void *v)
{
	seq_puts(m, "Test Metadata\n");
	seq_puts(m, "-------------\n");

	/* Test1 metadata */
	seq_printf(m, "Test1: %s\n", test1_data.name);
	seq_printf(m, "  Records: %zu\n", test1_data.count);
	seq_printf(m, "  Data size: %zu bytes\n", test1_data.count * sizeof(u64));

	/* Test2 metadata */
	seq_printf(m, "Test2: %s\n", test2_data.name);
	seq_printf(m, "  Records: %zu\n", test2_data.count);
	seq_printf(m, "  Data size: %zu bytes\n", test2_data.count * sizeof(u64));

	/* Test3 metadata */
	seq_printf(m, "Test3: %s\n", test3_data.name);
	seq_printf(m, "  Records: %zu\n", test3_data.count);
	seq_printf(m, "  Data size: %zu bytes\n", test3_data.count * sizeof(u64));

	/* Test4 metadata */
	seq_puts(m, "Test4: mixed_operations\n");
	seq_printf(m, "  Records: %zu\n", test4_count);
	seq_printf(m, "  Data size: %zu bytes\n", test4_count * sizeof(struct mixed_op_record));

	return 0;
}

static int meta_open(struct inode *inode, struct file *file)
{
	return single_open(file, meta_show, NULL);
}

static const struct proc_ops meta_fops = {
	.proc_open	= meta_open,
	.proc_read	= seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

static int __init page_pool_test_init(void)
{
	pr_info("Page Pool Test Module Loaded\n");

	memset(&test1_data, 0, sizeof(test1_data));
	memset(&test2_data, 0, sizeof(test2_data));
	memset(&test3_data, 0, sizeof(test3_data));
	test4_records = NULL;
	test4_count = 0;

	test_dir = proc_mkdir("page_pool_test", NULL);
	if (!test_dir)
		return -ENOMEM;

	proc_create("control", 0666, test_dir, &test_fops);
	proc_create("records", 0444, test_dir, &records_fops);
	proc_create("meta", 0444, test_dir, &meta_fops);

	return 0;
}

static void __exit page_pool_test_exit(void)
{
	free_test_data(&test1_data);
	free_test_data(&test2_data);
	free_test_data(&test3_data);
	cleanup_test4();

	if (test_dir) {
		remove_proc_entry("control", test_dir);
		remove_proc_entry("records", test_dir);
		remove_proc_entry("meta", test_dir);
		proc_remove(test_dir);
	}

	pr_info("Page Pool Test Module Unloaded\n");
}

module_init(page_pool_test_init);
module_exit(page_pool_test_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Page Pool Test Module");
