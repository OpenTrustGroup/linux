/* SPDX-License-Identifier: GPL-2.0-only */

#define pr_fmt(fmt) "nbl_trace: "fmt

#include <linux/debugfs.h>

#include "trace.h"

#define ARM64_GTIMER_FREQ       13000000

// Accumulative vcpu running time
typedef struct {
    uint64_t enter_tick[NBL_TRACE_VCPU_CNT][NBL_TRACE_VM_CNT];
    uint64_t exec_tick[NBL_TRACE_VCPU_CNT][NBL_TRACE_VM_CNT];
    uint64_t cur_tick;
} vcpu_accum_buf_t;

static int vcpu_accum_show(struct seq_file *s, void *data)
{
    vcpu_accum_buf_t *accum = s->private;
    u64 sec, msec, tick;
    int i, j;

    tick = accum->cur_tick;
    sec = tick / ARM64_GTIMER_FREQ;
    msec = (tick % ARM64_GTIMER_FREQ) * 1000 / ARM64_GTIMER_FREQ;
    seq_printf(s, "[Nebula] VM execution time:\n");
    seq_printf(s, "time elapsed since system boot: %llu.%llu\n", sec, msec);
    for (i = 0; i < NBL_TRACE_VCPU_CNT; i++) {
        seq_printf(s, "  PCPU%u:\n", i);
        for (j = 0; j < NBL_TRACE_VM_CNT; j++) {
            tick = accum->exec_tick[i][j];
            sec = tick / ARM64_GTIMER_FREQ;
            msec = (tick % ARM64_GTIMER_FREQ) * 1000 / ARM64_GTIMER_FREQ;
            seq_printf(s, "    VM%u: %llu.%llu \n", j, sec, msec);
        }
    }

    return 0;
}

static int vcpu_accum_open(struct inode *inode, struct file *file)
{
    return single_open(file, vcpu_accum_show, inode->i_private);
}

static const struct file_operations vcpu_accum_ops = {
    .open    = vcpu_accum_open,
    .read    = seq_read,
    .llseek	 = seq_lseek,
    .release = single_release,
};

int vcpu_exec_accum_init(struct nbl_tracer_data *data)
{
    debugfs_create_file(data->tracer->name, 0444, data->dbgfs_root,
            nbl_trace_get_tracer_buf(data->tracer), &vcpu_accum_ops);
    return 0;
}

