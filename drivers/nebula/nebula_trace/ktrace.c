/* SPDX-License-Identifier: GPL-2.0-only */

#define pr_fmt(fmt) "nbl_trace: "fmt

#include <asm/acrn.h>
#include <linux/slab.h>
#include <linux/debugfs.h>
#include <linux/kthread.h>
#include <linux/timer.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/bitops.h>

#include "trace.h"

#define HC_GUEST_START_KTRACE 0xB0000006

#define NBL_TRACE_LOG_FILE  "/data/ktrace.raw"

#define EVENT_NAME_LEN_MAX  32
#define TRACE_EVENT_CNT     32

typedef struct {
    uint64_t magic;
#define NBL_SCHED_TRACE_MAGIC  0x5472617363686564 // Trasched
    volatile uint64_t write_pos;
    volatile uint64_t read_pos;
    uint32_t sz;
    uint32_t enable;
    // events we supported
    uint32_t support_events;
    uint32_t set_events;
    char events_name[TRACE_EVENT_CNT][EVENT_NAME_LEN_MAX];
    uint32_t reserved;
    volatile char data[];
} ktrace_ringbuf_t;

struct nbl_ktrace {
    bool quit;
    struct dentry *dbgfs;
    struct timer_list timer;
    wait_queue_head_t ve_event;
    struct task_struct *trace_thread;
    bool thread_running;
    struct file *tfile;
    loff_t pos;
    ktrace_ringbuf_t *buf;
};

static struct nbl_ktrace *_ktrace;

static void start_ktrace(struct nbl_ktrace *ktrace)
{
    acrn_hypercall0(HC_GUEST_START_KTRACE);
}

static inline bool ktrace_is_running(struct nbl_ktrace *ktrace)
{
    return ktrace->thread_running;
}

static void ktrace_dotimer(struct timer_list *t)
{
    struct nbl_ktrace *ktrace = from_timer(ktrace, t, timer);

    if (!ktrace->thread_running)
        return;

    wake_up_interruptible(&ktrace->ve_event);
    mod_timer(&ktrace->timer, jiffies + msecs_to_jiffies(5));
}

static inline u32 ktrace_get_data_len(ktrace_ringbuf_t *rb)
{
    u64 size = rb->write_pos - rb->read_pos;
    WARN_ON(rb->read_pos > rb->write_pos);
    /*
     * Wait for a while to collect more data before write to storage.
     * Avoid frequently I/O impact, and ensure data has been
     * written before read it out.
     */
    return (size < (rb->sz / 5)) ? 0 : size;
}

static inline bool ktrace_ready(void)
{
    return _ktrace->buf->magic == NBL_SCHED_TRACE_MAGIC;
}

static ssize_t ktrace_reader(struct nbl_ktrace *ktrace)
{
    ktrace_ringbuf_t *rb = ktrace->buf;
    u8 *buf;
    u64 write_pos, rd, wr;
    size_t len, total_len = 0;
    ssize_t ret;

    write_pos = rb->write_pos;
    rd = rb->read_pos % rb->sz;
    wr = write_pos % rb->sz;
    if (rd > wr) {
        buf = (u8 *)rb->data + rd;
        len = rb->sz - rd;
        total_len += len;
        ret = kernel_write(ktrace->tfile, buf, len, &ktrace->pos);
        if (ret != len) {
            pr_err("kernel_write: write trace file failed: %zd\n", ret);
            return ret < 0 ? ret : -ENODEV;
        }
        rd = 0;
    }

    if (rd < wr) {
        buf = (u8 *)rb->data + rd;
        len = wr - rd;
        total_len += len;
        ret = kernel_write(ktrace->tfile, buf, len, &ktrace->pos);
        if (ret != len) {
            pr_err("kernel_write: write trace file failed: %zd\n", ret);
            return ret < 0 ? ret : -ENODEV;
        }
    }

    rb->read_pos = write_pos;

    return total_len;
}

static void ktrace_exit(struct nbl_ktrace *ktrace)
{
    ktrace_ringbuf_t *rb = ktrace->buf;

    rb->enable = false;
    wmb();

    del_timer_sync(&ktrace->timer);
    if (ktrace->tfile)
        filp_close(ktrace->tfile, NULL);
    ktrace->tfile = NULL;
    ktrace->pos = 0;

    rb->write_pos = 0;
    rb->read_pos = 0;
}

static int ktrace_thread(void *data)
{
    struct nbl_ktrace *ktrace = data;
    ktrace_ringbuf_t *rb = ktrace->buf;
    int ret = 0;

    ktrace->thread_running = true;

    timer_setup(&ktrace->timer, ktrace_dotimer, 0);
    ktrace->timer.expires = jiffies + msecs_to_jiffies(5);
    add_timer(&ktrace->timer);

    wait_event_interruptible(ktrace->ve_event, rb->enable);
    while (!kthread_should_stop()) {
        ret = wait_event_interruptible(ktrace->ve_event,
                ktrace->quit || ktrace_get_data_len(rb));
        if (ret)
            break;

        if (!rb->enable) {
            /*
             * Hypervisor trace overflow detected, here we just drop
             * the rest log.
             */
            pr_err("Trace buffer overflow. Trace truncated.\n");
            break;
        }

        ret = ktrace_reader(ktrace);
        if (ret < 0) {
            pr_err("write recs to storage failed! (%d)\n", ret);
            break;
        }
    }

    ktrace_exit(ktrace);
    ktrace->thread_running = false;

    return ret;
}

static int ktrace_start(struct nbl_ktrace *ktrace)
{
    ktrace_ringbuf_t *rb = ktrace->buf;
    int ret;

    ktrace->tfile = filp_open(NBL_TRACE_LOG_FILE, O_CREAT | O_RDWR | O_TRUNC, 0600);
    if (IS_ERR(ktrace->tfile)) {
        ktrace->tfile = filp_open(NBL_TRACE_LOG_FILE, O_RDWR | O_TRUNC, 0600);
        if (IS_ERR(ktrace->tfile)) {
            pr_err("Open ktrace log file failed!!\n");
            ret = PTR_ERR(ktrace->tfile);
            ktrace->tfile = NULL;
            return ret;
        }
    }

    rb->write_pos = 0;
    rb->read_pos = 0;
    ktrace->quit = false;
    ktrace->pos = 0;

    ktrace->trace_thread = kthread_run(ktrace_thread, ktrace,
            "ktrace_reader");
    if (IS_ERR(ktrace->trace_thread)) {
        pr_err("trace_thread thread creation failed");
        return PTR_ERR(ktrace->trace_thread);
    }

    /* ensure read & write pointer been reset prior to enable tracing */
    wmb();
    start_ktrace(ktrace);

    return 0;
}

static void ktrace_stop(struct nbl_ktrace *ktrace)
{
    ktrace->quit = true;
    wake_up_interruptible(&ktrace->ve_event);
    kthread_stop(ktrace->trace_thread);
}

static int ktrace_enable_get(void *data, u64 *val)
{
    struct nbl_ktrace *ktrace = data;
    *val = ktrace->buf->enable;
    return 0;
}

static int ktrace_enable_set(void *data, u64 val)
{
    struct nbl_ktrace *ktrace = data;
    bool enabled = ktrace->buf->enable;
    int ret = 0;

    if (enabled == !!val) {
        pr_info("Trace already %s!\n", enabled ? "enabled" : "disabled");
        return 0;
    }

    if (val == 0) {
        ktrace_stop(ktrace);
    } else {
        if (!ktrace->buf->set_events) {
            pr_err("no event specified! do nothing\n");
            return -EPERM;
        }
        ret = ktrace_start(ktrace);
    }

    pr_info("%s ktrace!\n",
            ktrace->buf->enable ? "Start tracing" : "Stop tracing");
    if (!ktrace->buf->enable)
        pr_info("log stored in %s!\n", NBL_TRACE_LOG_FILE);

    return ret;
}

DEFINE_SIMPLE_ATTRIBUTE(ktrace_enable_ops,
    ktrace_enable_get,
    ktrace_enable_set,
    "%llu\n");

static int trace_available_event_show(struct seq_file *s, void *data)
{
    ktrace_ringbuf_t *rb = s->private;
    unsigned long events;
    int i;

    events = rb->support_events;
    for (i = 0; i < TRACE_EVENT_CNT; i++) {
        if (test_bit(i, &events))
            seq_printf(s, "%s ", rb->events_name[i]);
    }
    seq_printf(s, "\n");

    return 0;
}

static int trace_available_event_open(struct inode *inode, struct file *file)
{
    return single_open(file, trace_available_event_show, inode->i_private);
}

static const struct file_operations trace_avaiable_grp_ops = {
    .open    = trace_available_event_open,
    .read    = seq_read,
    .llseek  = seq_lseek,
    .release = single_release,
};

static void trace_set_events(char *str, ktrace_ringbuf_t *rb)
{
    char *p, *tmp;
    unsigned long events;
    u32 available_events;

    tmp = kstrdup(str, GFP_KERNEL);
    events = 0;

    while (1) {
        int i;

        p = strsep(&tmp, " \t\n\r");
        if (!p)
            break;

        available_events = rb->support_events;
        for (i = 0;
             i < TRACE_EVENT_CNT && available_events;
             i++, available_events >>= 1) {
            u32 len = strnlen(rb->events_name[i], EVENT_NAME_LEN_MAX);
            if (strncmp(p, rb->events_name[i], len) == 0) {
                set_bit(i, &events);
                break;
            }
        }
    }

    rb->set_events = events;

    kfree(tmp);
}

static ssize_t trace_set_event_write(struct file *file, const char __user *data,
                  size_t cnt, loff_t *ppos)
{
    struct seq_file *s = file->private_data;
    ktrace_ringbuf_t *rb = s->private;
    char *kbuf;
    ssize_t ret;

    if (ktrace_is_running(_ktrace)) {
        pr_info("Cannot set events while trace is running!\n");
        return -EBUSY;
    }

    kbuf = kzalloc(cnt + 1, GFP_KERNEL);
    if (!kbuf)
        return -ENOMEM;

    if (copy_from_user(kbuf, data, cnt)) {
        ret = -EFAULT;
        goto exit;
    }

    trace_set_events(kbuf, rb);

    ret = cnt;

exit:
    kfree(kbuf);
    return ret;
}

static int trace_set_event_show(struct seq_file *s, void *data)
{
    ktrace_ringbuf_t *rb = s->private;
    unsigned long events;
    int i, cnt;

    events = rb->set_events;
    for (i = 0, cnt = 0; i < TRACE_EVENT_CNT; i++) {
        if (test_bit(i, &events)) {
            seq_printf(s, "%s ", rb->events_name[i]);
            cnt++;
        }
    }
    if (cnt)
        seq_printf(s, "\n");

    return 0;
}

static int trace_set_event_open(struct inode *inode, struct file *file)
{
    return single_open(file, trace_set_event_show, inode->i_private);
}

static const struct file_operations trace_set_event_fops = {
    .open = trace_set_event_open,
    .read = seq_read,
    .write = trace_set_event_write,
    .llseek = seq_lseek,
    .release = single_release,
};

int ktrace_init(struct nbl_tracer_data *data)
{
    _ktrace = kzalloc(sizeof(*_ktrace), GFP_KERNEL);
    if (!_ktrace)
        return -ENOMEM;

    _ktrace->buf = nbl_trace_get_tracer_buf(data->tracer);

    if (!ktrace_ready()) {
        pr_err("sched trace is not support!\n");
        kfree(_ktrace);
        _ktrace = NULL;
        return -ENOTSUPP;
    }

    _ktrace->dbgfs = debugfs_create_dir(data->tracer->name, data->dbgfs_root);
    debugfs_create_file("enable", 0644, _ktrace->dbgfs, _ktrace,
            &ktrace_enable_ops);
    debugfs_create_file("available_events", 0444,_ktrace->dbgfs,
            _ktrace->buf, &trace_avaiable_grp_ops);
    debugfs_create_file("set_event", 0644, _ktrace->dbgfs,
            _ktrace->buf, &trace_set_event_fops);

    init_waitqueue_head(&_ktrace->ve_event);

    return 0;
}

