/* SPDX-License-Identifier: GPL-2.0-only */

#define pr_fmt(fmt) "nbl_trace: "fmt

#include <linux/slab.h>

#include "trace.h"

typedef struct {
    // For the case that vcpu-pcpu pairs would be changed in run-time.
    uint64_t pcpu : 5;
    uint64_t flag : 1;
#define FLAG_ENTER_VCPU  0
#define FLAG_EXIT_VCPU   1
    // vcpu entry/exit time measured in arm generic timer ticks
    uint64_t ticks : 58;
} vcpu_exec_split_rec_t;

#define VCPU_EXEC_REC_CNT     80000
typedef struct {
    bool enable;
    uint32_t write_pos[NBL_TRACE_VM_CNT][NBL_TRACE_VCPU_CNT];
    vcpu_exec_split_rec_t recs[NBL_TRACE_VM_CNT][NBL_TRACE_VCPU_CNT][VCPU_EXEC_REC_CNT];
} vcpu_exec_split_buf_t;

struct vcpu_exec {
    vcpu_exec_split_buf_t *buf;
    struct nbl_tracer_data *data;
};

static struct vcpu_exec *vcpu_exec = NULL;

static inline bool is_trace_ready(void)
{
    return (vcpu_exec != NULL);
}

static inline int vcpu_exec_enabled(void)
{
    return vcpu_exec->buf->enable;
}

static int __maybe_unused vcpu_exec_enable(void)
{
    if (is_trace_ready())
        return -ENXIO;

    if (vcpu_exec_enabled())
        return 0;

    vcpu_exec->buf->enable = true;
    return 0;
}

static int __maybe_unused vcpu_exec_disable(void)
{
    if (is_trace_ready())
        return -ENXIO;

    if (!vcpu_exec_enabled())
        return 0;

    memset(vcpu_exec->buf, 0, sizeof(*vcpu_exec->buf));
    return 0;
}

int vcpu_exec_split_init(struct nbl_tracer_data *data)
{
    vcpu_exec = kzalloc(sizeof(*vcpu_exec), GFP_KERNEL);
    if (!vcpu_exec)
        return -ENOMEM;

    vcpu_exec->data = data;
    vcpu_exec->buf = nbl_trace_get_tracer_buf(data->tracer);
    return 0;
}

