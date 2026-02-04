/* SPDX-License-Identifier: GPL-2.0-only */

#define pr_fmt(fmt) "nbl_trace: "fmt

#include <linux/slab.h>

#include "trace.h"

/*
 * ring buffer vmo layout:
 *  --------------------------------------------------------------
 * | vcpu_ringbuf_hdr_t | rec[0] | rec[1] | ...... | rec[n] |
 *  --------------------------------------------------------------
 *                            | <-             size            -> |
 * | <-      hdr_size      -> |
 *                            | <-           write_pos         -> |
 */
typedef struct {
    uint64_t write_pos;
    uint64_t read_pos;
    size_t hdr_size;
    size_t rec_size;
    uint32_t rec_cnt;
    uint8_t reserved0[4];
    bool enable;
    uint8_t reserved1[7];
} vcpu_ringbuf_hdr_t;

typedef struct {
    uint64_t vmid : 2;
#define TRACE_YOCTO_VMID      0
#define TRACE_ANDROID_VMID    1
    uint64_t vcpu : 5;
    uint64_t pcpu : 5;
    uint64_t flag : 2;
#define FLAG_ENTER_VCPU  0
#define FLAG_EXIT_VCPU   1
    // 50 bits timestamp is big enough, for 13MHz tick, it can record
    // for more than 5 years.
    uint64_t timestamp : 50;
} vcpu_exec_rec_t;

#define VCPU_EXEC_REC_CNT     80000
#define TRACE_VCPU_EXEC_REC_CNT \
    (NBL_TRACE_VM_CNT * NBL_TRACE_VCPU_CNT * VCPU_EXEC_REC_CNT)
// trace vm entey/exit timestamp
typedef struct {
    vcpu_ringbuf_hdr_t rb_hdr;
    vcpu_exec_rec_t recs[TRACE_VCPU_EXEC_REC_CNT];
} vcpu_exec_buf_t;

struct vcpu_exec {
    vcpu_exec_buf_t *buf;
    struct nbl_tracer_data *data;
};

static struct vcpu_exec *vcpu_exec = NULL;

static inline bool is_trace_ready(void)
{
    return (vcpu_exec != NULL);
}

static inline int vcpu_exec_enabled(void)
{
    return vcpu_exec->buf->rb_hdr.enable;
}

static int __maybe_unused vcpu_exec_enable(void)
{
    if (is_trace_ready())
        return -ENXIO;

    if (vcpu_exec_enabled())
        return 0;

    vcpu_exec->buf->rb_hdr.enable = true;
    return 0;
}

static int __maybe_unused vcpu_exec_disable(void)
{
    vcpu_ringbuf_hdr_t *rb_hdr;

    if (is_trace_ready())
        return -ENXIO;

    if (!vcpu_exec_enabled())
        return 0;

    rb_hdr = &vcpu_exec->buf->rb_hdr;
    rb_hdr->enable = false;
    rb_hdr->write_pos = 0;
    wmb();
    return 0;
}

int vcpu_exec_init(struct nbl_tracer_data *data)
{
    vcpu_exec = kzalloc(sizeof(*vcpu_exec), GFP_KERNEL);
    if (!vcpu_exec)
        return -ENOMEM;

    vcpu_exec->data = data;
    vcpu_exec->buf = nbl_trace_get_tracer_buf(data->tracer);
    return 0;
}
