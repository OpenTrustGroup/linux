/* SPDX-License-Identifier: GPL-2.0-only */

#define pr_fmt(fmt) "nbl_trace: "fmt

#include <linux/debugfs.h>
#include "trace.h"
#include "vcpu_exit.h"

// vcpu exit reason
enum {
    VCPU_EXIT_PHYSICAL_INTERRUPT,
    VCPU_EXIT_WFI_WFE_INSTRUCTION,
    VCPU_EXIT_SMC_INSTRUCTION,
    VCPU_EXIT_HVC_INSTRUCTION,
    VCPU_EXIT_SYSTEM_INSTRUCTION,
    VCPU_EXIT_INSTRUCTION_ABORT,
    VCPU_EXIT_DATA_ABORT,
    VCPU_EXIT_HYPERCALL,
    VCPU_EXIT_UNKNOWN,
    VCPU_EXIT_FAILURE,
    VCPU_EXIT_COUNT,
};

static const char *const vcpu_exit_reason[] = {
    [VCPU_EXIT_PHYSICAL_INTERRUPT] = "physical interrupt",
    [VCPU_EXIT_WFI_WFE_INSTRUCTION] = "wfi wfe instruction",
    [VCPU_EXIT_SMC_INSTRUCTION] = "smc instruction",
    [VCPU_EXIT_HVC_INSTRUCTION] = "hvc instruction",
    [VCPU_EXIT_SYSTEM_INSTRUCTION] = "system instruction",
    [VCPU_EXIT_INSTRUCTION_ABORT] = "instruction abort",
    [VCPU_EXIT_DATA_ABORT] = "data abort",
    [VCPU_EXIT_HYPERCALL] = "hyper call",
    [VCPU_EXIT_UNKNOWN] = "unknown",
    [VCPU_EXIT_FAILURE] = "failure",
};

typedef struct {
    uint32_t reason[NBL_TRACE_VCPU_CNT][NBL_TRACE_VM_CNT][VCPU_EXIT_COUNT];
} vcpu_exit_buf_t;

wfe_exit_buf_t  _gl_wfe_exit;

vcpu_exit_buf_t *_gl_exit;

bool is_record;

static inline wfe_exit_buf_t * _get_wfe_exit_buf(void)
{
    return &_gl_wfe_exit;
}

int start_record_wfe_exit(void)
{
    int i, j;

    if(!_gl_exit)
        return -EFAULT;

    if (is_record) {
        pr_info("Trace vwfe exit already started!\n");
        return 0;
    }

    is_record = true;
    memset(&_gl_wfe_exit, 0, sizeof(_gl_wfe_exit));

    for (i = 0; i < NBL_TRACE_VCPU_CNT; i++) {
        for (j = 0; j < NBL_TRACE_VM_CNT; j++) {
            _gl_wfe_exit.reason[i][j] = _gl_exit->reason[i][j][VCPU_EXIT_WFI_WFE_INSTRUCTION];
        }
    }

    return 0;
}

int stop_record_wfe_exit(void)
{
    int i, j;
    if(!_gl_exit)
        return -EFAULT;

    if (!is_record) {
        pr_info("Trace vwfe exit already stoped!\n");
        return 0;
    }

    is_record = false;

    for (i = 0; i < NBL_TRACE_VCPU_CNT; i++) {
        for (j = 0; j < NBL_TRACE_VM_CNT; j++) {
            _gl_wfe_exit.reason[i][j] = _gl_exit->reason[i][j][VCPU_EXIT_WFI_WFE_INSTRUCTION] - _gl_wfe_exit.reason[i][j];
        }
    }

    wmb();
    return 0;
}

wfe_exit_buf_t* get_wfe_exit_buf(void)
{
    return _get_wfe_exit_buf();
}

static int vcpu_exit_reason_show(struct seq_file *s, void *data)
{
    vcpu_exit_buf_t *exit = s->private;
    int i, j, k;

    seq_printf(s, "[Nebula] VCPU exit reason:\n");
    for (i = 0; i < NBL_TRACE_VCPU_CNT; i++) {
        seq_printf(s, "  VCPU%u:\n", i);
        for (j = 0; j < NBL_TRACE_VM_CNT; j++) {
            seq_printf(s, "    VM%u:\n", j);
            for (k = 0; k < VCPU_EXIT_COUNT; k++) {
                seq_printf(s, "      %s: %u\n", vcpu_exit_reason[k],
                        exit->reason[i][j][k]);
            }
        }
    }

    return 0;
}

static int vcpu_exit_reason_open(struct inode *inode, struct file *file)
{
    return single_open(file, vcpu_exit_reason_show, inode->i_private);
}

static const struct file_operations vcpu_exit_reason_ops = {
    .open    = vcpu_exit_reason_open,
    .read    = seq_read,
    .llseek	 = seq_lseek,
    .release = single_release,
};

int vcpu_exit_reason_init(struct nbl_tracer_data *data)
{
    _gl_exit = nbl_trace_get_tracer_buf(data->tracer);
    debugfs_create_file(data->tracer->name, 0444, data->dbgfs_root,
            _gl_exit, &vcpu_exit_reason_ops);
    return 0;
}

