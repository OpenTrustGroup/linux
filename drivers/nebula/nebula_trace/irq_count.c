/* SPDX-License-Identifier: GPL-2.0-only */

#define pr_fmt(fmt) "nbl_trace: "fmt

#include <linux/debugfs.h>
#include "trace.h"
#include "irq_count.h"

static irq_count_buf_t * _gl_irq_count_buf = NULL;

static inline irq_count_buf_t * _get_irq_count_buf(void)
{
    return _gl_irq_count_buf;
}

irq_count_buf_t* get_irq_count_buf(void)
{
    return _get_irq_count_buf();
}

static int irq_count_show(struct seq_file *s, void *data)
{
    irq_count_buf_t *irqcnt = s->private;
    int i;

    seq_printf(s, "[Nebula] GIC V3 irq count:\n");
    for (i = 0; i < NBL_TRACE_MAX_IRQS; i++) {
        if (irqcnt->irq_count[i] != 0)
            seq_printf(s, "    irq-%u : %u   \n", i, irqcnt->irq_count[i]);
    }
    return 0;
}

static int irq_count_open(struct inode *inode, struct file *file)
{
    return single_open(file, irq_count_show, inode->i_private);
}

static const struct file_operations irq_count_ops = {
    .open    = irq_count_open,
    .read    = seq_read,
    .llseek	 = seq_lseek,
    .release = single_release,
};

int irq_count_init(struct nbl_tracer_data *data)
{
    irq_count_buf_t *buf;
    _gl_irq_count_buf = buf = nbl_trace_get_tracer_buf(data->tracer);

    debugfs_create_file(data->tracer->name, 0444, data->dbgfs_root,
            buf, &irq_count_ops);
    return 0;
}

