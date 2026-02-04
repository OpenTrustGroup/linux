/* SPDX-License-Identifier: GPL-2.0-only */

#define pr_fmt(fmt) "nbl_trace: "fmt

#include <linux/debugfs.h>

#include "trace.h"

// recording who is running on each pcpu
typedef struct {
    // vmid , yocto: 0,  android: 1, nebula: 2
    uint64_t current_vmid : 3;
#define TRACE_NEBULA_VMID    2
    //vcpu id, 0~7 is valid, 8 means nebule or idle
    uint64_t current_vcpu_id : 5;
#define NON_VM_CPU_ID   0xff
    //thread priority of vcpu
    uint64_t vcpu_thread_priority : 8;
} pcpu_status_rec_t;

typedef struct {
    pcpu_status_rec_t pcpu_status[NBL_TRACE_VCPU_CNT];
} pcpu_status_buf_t;

static int pcpu_status_show(struct seq_file *s, void *data)
{
    pcpu_status_buf_t *status = s->private;
    int i;

    for (i = 0; i < NBL_TRACE_VCPU_CNT; i++) {
        if (status->pcpu_status[i].current_vmid == 2)
            seq_printf(s, "pcpu%d is running on hypervisor\n", i);
        else
            seq_printf(s, "pcpu%d,  vm%u,  vcpu%u,   vcpu_thread_priority:%u\n",
                    i, status->pcpu_status[i].current_vmid,
                    status->pcpu_status[i].current_vcpu_id,
                    status->pcpu_status[i].vcpu_thread_priority);
    }

    return 0;
}

static int pcpu_status_open(struct inode *inode, struct file *file)
{
    return single_open(file, pcpu_status_show, inode->i_private);
}

//trace pcpu attr info
static const struct file_operations pcpu_status_ops = {
    .open    = pcpu_status_open,
    .read    = seq_read,
    .llseek  = seq_lseek,
    .release = single_release,
};

int pcpu_status_init(struct nbl_tracer_data *data)
{
    debugfs_create_file(data->tracer->name, 0444, data->dbgfs_root,
            nbl_trace_get_tracer_buf(data->tracer), &pcpu_status_ops);
    return 0;
}

