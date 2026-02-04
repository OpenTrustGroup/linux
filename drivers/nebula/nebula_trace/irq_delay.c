/* SPDX-License-Identifier: GPL-2.0-only */

#define pr_fmt(fmt) "nbl_trace: "fmt

#include <linux/debugfs.h>
#include "irq_delay.h"
#include "trace.h"

static inline int irq_delay_enabled(irq_delay_buf_t *buf);

static irq_delay_buf_t * _gl_irq_delay = NULL;

static inline irq_delay_buf_t * _get_irq_delay_buf(void)
{
    return _gl_irq_delay;
}

int start_record_irq_delay(void)
{
    irq_delay_buf_t * buf =  _get_irq_delay_buf();
    if(!buf)
        return -EFAULT;

    if (irq_delay_enabled(buf)) {
        pr_info("Trace irq_delay already started!\n");
        return 0;
    }

    buf->rb_hdr.write_pos = 0;
    memset(buf->rec, 0, sizeof(buf->rec));
    buf->rb_hdr.enable = true;
    return 0;
}

int stop_record_irq_delay(void)
{
    irq_delay_buf_t *buf = _get_irq_delay_buf();
    if (!buf)
        return -EFAULT;

    if (!irq_delay_enabled(buf)) {
        pr_info("Trace irq_delay already stoped!\n");
        return 0;
    }

    buf->rb_hdr.enable = false;
    wmb();
    return 0;
}

irq_delay_buf_t* get_irq_delay_buf(void)
{
    return _get_irq_delay_buf();
}

static inline int irq_delay_enabled(irq_delay_buf_t *buf)
{
    return buf->rb_hdr.enable;
}

static int irq_delay_enable(irq_delay_buf_t *buf)
{
    if (irq_delay_enabled(buf))
        return 0;

    buf->rb_hdr.enable = true;
    return 0;
}

static int irq_delay_disable(irq_delay_buf_t *buf)
{
    if (!irq_delay_enabled(buf))
        return 0;

    buf->rb_hdr.enable = false;
    buf->rb_hdr.write_pos = 0;
    memset(buf->rec, 0, sizeof(buf->rec));
    wmb();
    return 0;
}

static int trace_irq_delay_show(struct seq_file *s, void *data)
{
    irq_delay_buf_t *irq_delay = s->private;
    int i;

    if (!irq_delay_enabled(irq_delay))
        return 0;

    seq_printf(s, "    vector   delay\n");
    for (i = 0; i < IRQ_DELAY_MAX_RECS - 1; i++) {
        if (0 == irq_delay->rec[i].flag) {
            int j;
            for (j = i + 1; j < IRQ_DELAY_MAX_RECS; j++) {
                uint64_t delay = 0;

                if (irq_delay->rec[j].vector ==
                        irq_delay->rec[i].vector &&
                    irq_delay->rec[j].flag == 1) {
                    delay = irq_delay->rec[j].timestamp -
                        irq_delay->rec[i].timestamp;
                    seq_printf(s, "    irq-%u : %llu\n",
                           irq_delay->rec[j].vector,
                           delay);
                }
                break;
            }
        }
    }
    return 0;
}

static int irq_delay_enable_get(void *data, u64 *val)
{
    irq_delay_buf_t *irq_delay = data;
    *val = irq_delay_enabled(irq_delay);
    return 0;
}

static int irq_delay_enable_set(void *data, u64 val)
{
    irq_delay_buf_t *irq_delay = data;

    if (irq_delay->rb_hdr.enable == !!val) {
        pr_info("Trace irq_delay already %s!\n",
                irq_delay_enabled(irq_delay) ? "enabled" : "disabled");
        return 0;
    }

    if (val == 0)
        irq_delay_disable(irq_delay);
    else
        irq_delay_enable(irq_delay);

    pr_info("%s tracing irq delay!\n",
            irq_delay->rb_hdr.enable ? "Start" : "Stop");

    return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(irq_delay_enable_ops,
    irq_delay_enable_get,
    irq_delay_enable_set,
    "%llu\n");

static int irq_delay_open(struct inode *inode, struct file *file)
{
    return single_open(file, trace_irq_delay_show, inode->i_private);
}

static const struct file_operations irq_delay_ops= {
    .open    = irq_delay_open,
    .read    = seq_read,
    .llseek  = seq_lseek,
    .release = single_release,
};

int irq_delay_init(struct nbl_tracer_data *data)
{
    struct dentry *dbgfs_irq_delay;
    irq_delay_buf_t *buf;

    _gl_irq_delay = buf = nbl_trace_get_tracer_buf(data->tracer);

    dbgfs_irq_delay = debugfs_create_dir(data->tracer->name, data->dbgfs_root);
    debugfs_create_file("enable", 0600, dbgfs_irq_delay, buf,
            &irq_delay_enable_ops);
    debugfs_create_file(data->tracer->name, 0666, dbgfs_irq_delay, buf,
            &irq_delay_ops);

    return 0;
}
