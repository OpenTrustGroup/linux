/* SPDX-License-Identifier: GPL-2.0-only */

#define pr_fmt(fmt) "nbl_trace: "fmt

#include <linux/debugfs.h>
#include "trace.h"
#include "vcpu_sched_delay.h"

vcpu_sched_delay_buf_t * _gl_vcpu_delay_buf = NULL;

static inline vcpu_sched_delay_buf_t * _get_vcpu_delay_buf(void)
{
    return _gl_vcpu_delay_buf;
}

int start_record_vcpu_sched_delay(void)
{
    int i, j;
    vcpu_sched_delay_buf_t * buf =  _get_vcpu_delay_buf();
    if(!buf)
        return -EFAULT;

    if (buf->enable) {
        pr_info("Trace vcpu sched delay already started!\n");
        return 0;
    }

    /* clear the previous data, but keep thread id */
    for (j = 0; j < NBL_TRACE_VM_CNT; j++) {
        for (i = 0; i < NBL_TRACE_VCPU_CNT; i++) {
            vcpu_sched_delay_hdr_t *pDelay = &buf->delay[j][i];
            pDelay->enter_timestamp = 0;
            pDelay->current_delay_time = 0;
            pDelay->max_delay_time = 0;
            pDelay->min_delay_time = 0;
            pDelay->total_delay_time = 0;
            pDelay->run_times = 0;
            pDelay->bRun = 0;
        }
    }
    buf->enable = true;
    return 0;
}

int stop_record_vcpu_sched_delay(void)
{
    vcpu_sched_delay_buf_t *buf = _get_vcpu_delay_buf();
    if (!buf)
        return -EFAULT;

    if (!buf->enable) {
        pr_info("Trace vcpu sched delay already stoped!\n");
        return 0;
    }

    buf->enable = false;
    wmb();
    return 0;
}

vcpu_sched_delay_buf_t* get_vcpu_sched_delay_buf(void)
{
    return _get_vcpu_delay_buf();
}

static int vcpu_delay_enable_get(void *data, u64 *val)
{
    vcpu_sched_delay_buf_t *delay = data;
    *val = delay->enable;
    return 0;
}

static int vcpu_delay_enable_set(void *data, u64 val)
{
    vcpu_sched_delay_buf_t *delay = data;
    int ret = 0;
    int i, j;

    if (delay->enable == !!val) {
        pr_info("Trace already %s!\n", delay->enable ? "enabled" : "disabled");
        return 0;
    }

    if (val == 0) {
        /* clear the previous data, but keep thread id */
        for (j = 0; j < NBL_TRACE_VM_CNT; j++) {
            for (i = 0; i < NBL_TRACE_VCPU_CNT; i++) {
                vcpu_sched_delay_hdr_t *pDelay = &delay->delay[j][i];
                pDelay->enter_timestamp = 0;
                pDelay->current_delay_time = 0;
                pDelay->max_delay_time = 0;
                pDelay->min_delay_time = 0;
                pDelay->total_delay_time = 0;
                pDelay->run_times = 0;
                pDelay->bRun = 0;
            }
        }
        delay->enable = 0;
    } else {
        delay->enable = 1;
    }

    pr_info("%s vcpu delay!\n", delay->enable ? "Start tracing" : "Stop tracing");
    return ret;
}

DEFINE_SIMPLE_ATTRIBUTE(vcpu_delay_enable_ops,
    vcpu_delay_enable_get,
    vcpu_delay_enable_set,
    "%llu\n");

static inline void get_time_detail(u64 time, u64 *p_s, u64 *p_ms, u64 *p_us,
        u64 *p_ns, bool is_avg, u64 cntfrq)
{
    if (!is_avg) {
        *p_s = time / cntfrq;
        *p_ns = (time % cntfrq) * 1000000000 / cntfrq;
        *p_ms =  (*p_ns) / 1000000;
        *p_us = ((*p_ns) / 1000) % ((*p_ms) * 1000);
        *p_ns = (*p_ns) % (((*p_ms) * 1000 + (*p_us)) *1000);
    } else {
        *p_s =  (time / cntfrq)/1000;
        *p_ns = (time % (cntfrq * 1000)) * 1000000 / cntfrq;
        *p_ms =  (*p_ns) / 1000000;
        *p_us = ((*p_ns) / 1000) % ((*p_ms) * 1000);
        *p_ns = (*p_ns) % (((*p_ms) * 1000 + (*p_us)) *1000);
    }

    return;
}

static int vcpu_delay_show(struct seq_file *s, void *data)
{
    vcpu_sched_delay_buf_t *delay = s->private;
    int i, j;
    u64 cur_s, cur_ms, cur_us, cur_ns;
    u64 max_s, max_ms, max_us, max_ns;
    u64 min_s, min_ms, min_us, min_ns;
    u64 avg, avg_s, avg_ms, avg_us, avg_ns;
    u64 tid;
    avg = 0;

    if (!delay->enable)
        return 0;

    for (j = 0; j < NBL_TRACE_VM_CNT; j++) {
        if (j == 0) {
            seq_printf(s, "VM0\n");
        } else {
            seq_printf(s, "VM1\n");
        }
        seq_printf(s, "[Nebula] vcpu:\t  tid\t    cur:s.ms.us.ns\t max:s.ms.us.ns\t\t min:s.ms.us.ns\t\t avg:s.ms.us.ns\n");

        for (i = 0; i < NBL_TRACE_VCPU_CNT; i++) {
            vcpu_sched_delay_hdr_t *pDelay = &delay->delay[j][i];
            tid = pDelay->thread_id;
            if (tid == 0)
                /* TODO: assuming vcpu thread's id is not 0 */
                continue;

            get_time_detail(pDelay->current_delay_time, &cur_s, &cur_ms,
                &cur_us, &cur_ns, false, ARM64_GTIMER_FREQ);
            get_time_detail(pDelay->max_delay_time, &max_s, &max_ms, &max_us,
                &max_ns, false, ARM64_GTIMER_FREQ);
            get_time_detail(pDelay->min_delay_time, &min_s, &min_ms, &min_us,
                &min_ns, false, ARM64_GTIMER_FREQ);

            if (pDelay->run_times > 0)
                avg = (pDelay->total_delay_time * 1000) / pDelay->run_times;
            get_time_detail(avg, &avg_s, &avg_ms, &avg_us, &avg_ns, true,
                ARM64_GTIMER_FREQ);

            seq_printf(s, "    vcpu-%u delay: tid:%llu, cur:%03llu.%03llu.%03llu.%03llu\t max:%03llu.%03llu.%03llu.%03llu\t min:%03llu.%03llu.%03llu.%03llu\t avg:%03llu.%03llu.%03llu.%03llu \n",
                i, tid, cur_s, cur_ms, cur_us, cur_ns,
                max_s, max_ms, max_us, max_ns,
                min_s, min_ms, min_us, min_ns,
                avg_s, avg_ms, avg_us, avg_ns);
        }
    }
    return 0;
}

static int vcpu_delay_open(struct inode *inode, struct file *file)
{
    return single_open(file, vcpu_delay_show, inode->i_private);
}

static const struct file_operations vcpu_delay_ops = {
    .open    = vcpu_delay_open,
    .read    = seq_read,
    .llseek	 = seq_lseek,
    .release = single_release,
};

int vcpu_sched_delay_init(struct nbl_tracer_data *data)
{
    struct dentry *dbgfs_delay;
    vcpu_sched_delay_buf_t *delay;
    _gl_vcpu_delay_buf = delay = nbl_trace_get_tracer_buf(data->tracer);

    dbgfs_delay = debugfs_create_dir(data->tracer->name, data->dbgfs_root);
    debugfs_create_file("enable", 0600, dbgfs_delay, delay,
            &vcpu_delay_enable_ops);
    debugfs_create_file(data->tracer->name, 0444, dbgfs_delay, delay,
            &vcpu_delay_ops);
    return 0;
}

