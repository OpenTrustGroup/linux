/* SPDX-License-Identifier: GPL-2.0-only */

#define pr_fmt(fmt) "nbl_trace: "fmt

#include <linux/debugfs.h>

#include "trace.h"

#define STATE_INFO_LEN  10
#define PROC_NAME_LEN 15
#define THREAD_NAME_LEN 35
typedef struct {
    uint32_t   PID;
    uint32_t   TID;
    uint32_t   percent;
    char       state[STATE_INFO_LEN];//state string, 10 byte is enough
    char       proc_name[PROC_NAME_LEN]; //proc name, size 15 is enough
    char       thread_name[THREAD_NAME_LEN]; //thread name, size 35 is enough
} trace_thread_stat_t;

#define TOP_THREAD_COUNT   50
typedef struct {
    trace_thread_stat_t status[TOP_THREAD_COUNT];  //currently 50 is enough
    bool write_done;
    bool read_done;
    bool enable;
} top_buf_t;

static int top_info_show(struct seq_file *s, void *data)
{
    top_buf_t *top = s->private;
    int i;

    if (!top->enable)
        return 0;

    seq_printf(s, "%8s %8s %14s %5s %s\n",
            "PID", "TID", "TIME%", "STATE", "NAME");
    for (i = 0; i < TOP_THREAD_COUNT; i++) {
        seq_printf(s, "%8u %8u %10d.%2d %5s %s:%s\n",
                top->status[i].PID,
                top->status[i].TID,
                top->status[i].percent / 100,
                top->status[i].percent % 100,
                top->status[i].state,
                top->status[i].proc_name,
                top->status[i].thread_name);
    }
    return 0;
}

static int top_util_open(struct inode *inode, struct file *file)
{
    return single_open(file, top_info_show, inode->i_private);
}

static const struct file_operations top_utils_ops= {
    .open    = top_util_open,
    .read    = seq_read,
    .llseek  = seq_lseek,
    .release = single_release,
};

int top_utils_init(struct nbl_tracer_data *data)
{
    struct dentry *dbgfs_top;
    top_buf_t *top = nbl_trace_get_tracer_buf(data->tracer);

    dbgfs_top = debugfs_create_dir(data->tracer->name, data->dbgfs_root);
    debugfs_create_bool("enable", 0666, dbgfs_top, &top->enable);
    debugfs_create_file("top", 0444, dbgfs_top, top, &top_utils_ops);
    return 0;
}

