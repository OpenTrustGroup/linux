/* SPDX-License-Identifier: GPL-2.0-only */

#define pr_fmt(fmt) "nbl_trace: "fmt

#include <linux/debugfs.h>
#include "comcat_link.h"
#include "trace.h"

typedef struct {
    uint32_t tag;
    uint64_t a;
    uint64_t b;
    uint64_t c;
    uint64_t tid;
    // 50 bits timestamp is big enough, for 13MHz tick, it can record
    // for more than 5 years.
    uint64_t timestamp : 50;
} commu_link_rec_t;

typedef struct {
    uint32_t len;   // Actual length of this time
    commu_link_rec_t rec[COMCAT_TRACE_MAX_RECS]; 
} comcat_link_t;

static inline int comcat_trace_enabled(comcat_trace_buf_t *buf);

static comcat_trace_buf_t * _gl_comcat_trace = NULL;

static inline comcat_trace_buf_t * _get_comcat_trace_buf(void)
{
    return _gl_comcat_trace;
}

int start_record_comcat_trace(void)
{
    comcat_trace_buf_t * buf =  _get_comcat_trace_buf();
    if(!buf)
        return -EFAULT;

    if (comcat_trace_enabled(buf)) {
        pr_info("Trace comcat_trace already started!\n");
        return 0;
    }

    buf->rb_hdr.write_pos = 0;
    memset(buf->rec, 0, sizeof(buf->rec));
    buf->rb_hdr.enable = true;
    return 0;
}

int stop_record_comcat_trace(void)
{
    comcat_trace_buf_t *comcat_trace = _get_comcat_trace_buf();
    if (!comcat_trace)
        return -EFAULT;

    if (!comcat_trace_enabled(comcat_trace)) {
        pr_info("Trace comcat_trace already stoped!\n");
        return 0;
    }

    comcat_trace->rb_hdr.enable = false;
    wmb();
    return 0;
}

comcat_trace_buf_t* get_comcat_trace_buf(void)
{
    return _get_comcat_trace_buf();
}

static void __maybe_unused comcat_processing_data(void)
{
    int i, j, k;
    uint64_t ticks;
    static comcat_link_t comcat_link_buf;
    comcat_trace_buf_t *comcat_trace =
        _get_comcat_trace_buf();
    k = 0;

    for (i = 0; i < COMCAT_TRACE_MAX_RECS - 1; i++) {
        if (0 == comcat_trace->rec[i].flag) {
            for (j = i + 1; j < COMCAT_TRACE_MAX_RECS; j++) {
                if (NT_COMM_EVENT(comcat_trace->rec[j].tag) == 
                NT_COMM_EVENT(comcat_trace->rec[i].tag) 
                && 1 == comcat_trace->rec[j].flag 
                && comcat_trace->rec[j].tid == comcat_trace->rec[i].tid 
                && comcat_trace->rec[j].timestamp 
                >= comcat_trace->rec[i].timestamp) {
                    ticks = comcat_trace->rec[j].timestamp - 
                    comcat_trace->rec[i].timestamp;

                    comcat_link_buf.rec[k].tag =
                        comcat_trace->rec[j].tag;
                    comcat_link_buf.rec[k].a =
                        comcat_trace->rec[j].a;
                    comcat_link_buf.rec[k].b =
                        comcat_trace->rec[j].b;
                    comcat_link_buf.rec[k].c =
                        comcat_trace->rec[j].c;
                    comcat_link_buf.rec[k].tid =
                        comcat_trace->rec[j].tid;
                    comcat_link_buf.rec[k].timestamp = ticks;
                    comcat_link_buf.len = k;
                    k++;
                    break;
                }
            }
        }
    }
}

static inline int comcat_trace_enabled(comcat_trace_buf_t *buf)
{
    return buf->rb_hdr.enable;
}

static int comcat_trace_enable(comcat_trace_buf_t *buf)
{
    if (comcat_trace_enabled(buf))
        return 0;

    buf->rb_hdr.enable = true;
    return 0;
}

static int comcat_trace_disable(comcat_trace_buf_t *buf)
{
    if (!comcat_trace_enabled(buf))
        return 0;

    buf->rb_hdr.enable = false;
    buf->rb_hdr.write_pos = 0;
    memset(buf->rec, 0, sizeof(buf->rec));
    wmb();
    return 0;
}

static int trace_comcat_trace_show(struct seq_file *s, void *data)
{
    comcat_trace_buf_t *comcat_trace = s->private;
    int i;
    int64_t ticks;

    if (!comcat_trace_enabled(comcat_trace))
        return 0;

    seq_printf(s, "   Comcat link\n");

    seq_printf(s, "%llu\n", comcat_trace->rb_hdr.write_pos);

    for (i = 0; i < COMCAT_TRACE_MAX_RECS; i++) {
        ticks = comcat_trace->rec[i].timestamp;
        seq_printf(s,
            "flag %d event %ld  ticks %llu tid %llu a %llu b %llu c %llu\n",
            comcat_trace->rec[i].flag,
            NT_COMM_EVENT(comcat_trace->rec[i].tag), ticks,
            comcat_trace->rec[i].tid, comcat_trace->rec[i].a,
            comcat_trace->rec[i].b, comcat_trace->rec[i].c);
    }
    return 0;
}

static int comcat_trace_enable_get(void *data, u64 *val)
{
    comcat_trace_buf_t *comcat_trace = data;
    *val = comcat_trace_enabled(comcat_trace);
    return 0;
}

static int comcat_trace_enable_set(void *data, u64 val)
{
    comcat_trace_buf_t *comcat_trace = data;

    if (comcat_trace->rb_hdr.enable == !!val) {
        pr_info("Trace comcat_trace already %s!\n",
                comcat_trace_enabled(comcat_trace) ? "enabled" : "disabled");
        return 0;
    }

    if (val == 0)
        comcat_trace_disable(comcat_trace);
    else
        comcat_trace_enable(comcat_trace);

    pr_info("%s tracing comcat trace!\n",
            comcat_trace->rb_hdr.enable ? "Start" : "Stop");

    return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(comcat_trace_enable_ops,
    comcat_trace_enable_get,
    comcat_trace_enable_set,
    "%llu\n");

static int comcat_trace_open(struct inode *inode, struct file *file)
{
    return single_open(file, trace_comcat_trace_show, inode->i_private);
}

static const struct file_operations comcat_trace_ops= {
    .open    = comcat_trace_open,
    .read    = seq_read,
    .llseek  = seq_lseek,
    .release = single_release,
};

int comcat_trace_init(struct nbl_tracer_data *data)
{
    struct dentry *dbgfs_comcat_trace;
    comcat_trace_buf_t *buf;

    _gl_comcat_trace = buf = nbl_trace_get_tracer_buf(data->tracer);

    dbgfs_comcat_trace = debugfs_create_dir(data->tracer->name, data->dbgfs_root);
    debugfs_create_file("enable", 0600, dbgfs_comcat_trace, buf,
            &comcat_trace_enable_ops);
    debugfs_create_file(data->tracer->name, 0666, dbgfs_comcat_trace, buf,
            &comcat_trace_ops);

    return 0;
}
