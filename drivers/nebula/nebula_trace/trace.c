/* SPDX-License-Identifier: GPL-2.0-only */

#define pr_fmt(fmt) "nbl_trace: "fmt

#include <linux/version.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_reserved_mem.h>
#include <linux/debugfs.h>
#include <linux/timer.h>

#include "trace.h"

typedef struct {
#define NBL_TRACE_MAGIC  0x4e626c5472616365 // NblTrace
    uint64_t magic;
    size_t buf_offs;
    uint32_t version;
    uint32_t tracer_cnt;
    nbl_tracer_info_t tracers[GRP_TYPE_CNT];
} nbl_trace_header_t;

struct nbl_trace {
    struct reserved_mem *rmem;
    struct dentry *dbgfs_root;
    u64 cntfrq;
    nbl_trace_header_t *header;
    struct nbl_tracer_data *tracer_datas;
};

static struct nbl_trace g_nbl_trace;

static nbl_tracer_init tracer_ops[GRP_TYPE_CNT] = {
    [GRP_VCPU_EXEC] = vcpu_exec_init,
    [GRP_VCPU_RUN_ACCUM] = vcpu_exec_accum_init,
    [GRP_VCPU_EXIT_REASON] = vcpu_exit_reason_init,
    [GRP_IRQ_COUNT] = irq_count_init,
    [GRP_PCPU_STATUS] = pcpu_status_init,
    [GRP_VCPU_SCHED_DELAY] = vcpu_sched_delay_init,
    [GRP_VCPU_EXEC_SPLIT] = vcpu_exec_split_init,
    [GRP_TOP] = top_utils_init,
    [GRP_IRQ_DELAY] = irq_delay_init,
    [GRP_KTRACE] = ktrace_init,
    [GRP_COMCAT_LINK] = comcat_trace_init,
    [GRP_CPU_IPI_DELAY] = cpu_ipi_delay_init,
    [GRP_NBL_REV] = nebula_version_init,
};

static int __init nbl_trace_mem_init(struct reserved_mem *rmem)
{
    g_nbl_trace.rmem = rmem;
    return 0;
}
RESERVEDMEM_OF_DECLARE(nbl_trace, "mediatek,nbl_trace",
               nbl_trace_mem_init);

static int trace_available_show(struct seq_file *s, void *data)
{
    nbl_trace_header_t *header = s->private;
    u32 version = header->version;
    int i;

    seq_printf(s, "======================\n");
    seq_printf(s, "Version: %u.%u.%u%c\n",
            version >> 24, (version >> 16) & 0xff,
            (version >> 8) & 0xff, version & 0xff);
    seq_printf(s, "Available tools:\n");
    seq_printf(s, "----------------------\n");

    for (i = 0; i < header->tracer_cnt; i++) {
        seq_printf(s, "  %02d: %-32s: %s\n", i, header->tracers[i].name,
                header->tracers[i].supported ? "Support" : "");
    }
    seq_printf(s, "----------------------\n");

    return 0;
}

static int trace_available_open(struct inode *inode, struct file *file)
{
    return single_open(file, trace_available_show, inode->i_private);
}

static const struct file_operations trace_available_ops = {
    .open    = trace_available_open,
    .read    = seq_read,
    .llseek	 = seq_lseek,
    .release = single_release,
};

void *nbl_trace_get_tracer_buf(nbl_tracer_info_t *tracer)
{
    uintptr_t memaddr = (uintptr_t)g_nbl_trace.header;
    return (void *)(memaddr + tracer->buf_offs +
                g_nbl_trace.header->buf_offs);
}

static int nbl_trace_debugfs_init(struct nbl_trace *tc)
{
    tc->dbgfs_root = debugfs_create_dir("nebula_trace", NULL);
    debugfs_create_file("available_trace", 0444, tc->dbgfs_root,
            tc->header, &trace_available_ops);

    return 0;
}

static int nbl_trace_init_tracers(struct nbl_trace *tc)
{
    int i, ret;
    size_t sz;
    u32 ntracer = tc->header->tracer_cnt;

    sz = sizeof(struct nbl_tracer_data) * ntracer;
    tc->tracer_datas = kzalloc(sz, GFP_KERNEL);
    if (!tc->tracer_datas)
        return -ENOMEM;

    /* initialize all tracer we support */
    for (i = 0; i < ntracer; i++) {
        nbl_tracer_info_t *tracer = &tc->header->tracers[i];
        struct nbl_tracer_data *data = &tc->tracer_datas[i];
        if (tracer->supported) {
            if (tracer_ops[i]) {
                data->tracer = tracer;
                data->dbgfs_root = tc->dbgfs_root;
                ret = tracer_ops[i](data);
            }
        }
    }
    
    return 0;
}

static bool nbl_trace_validation(struct nbl_trace *tc)
{
    return tc->header->magic == NBL_TRACE_MAGIC;
}

static int __init nbl_trace_init(void)
{
    struct nbl_trace *tc = &g_nbl_trace;
    int ret = -EINVAL;

    if (!tc->rmem) {
#if (KERNEL_VERSION(4, 15, 0) <= LINUX_VERSION_CODE)
        /*
         * If build as a kernel module, nbl_trace_mem_init would not be invoked,
         * need to parse DTS manually.
         */
        struct device_node *np = of_find_compatible_node(NULL, NULL,
                "mediatek,nbl_trace");
        if (!np)
            return -ENOENT;

        tc->rmem = of_reserved_mem_lookup(np);
        if (!tc->rmem) {
            pr_err("%s: failed to get reserved memory\n", __func__);
            return -ENOENT;
        }
#else
        return -ENOENT;
#endif
    }

    tc->header = ioremap_cache(tc->rmem->base, tc->rmem->size);
    if (!tc->header)
        return -ENOMEM;

    if (!nbl_trace_validation(tc))
        goto unmap;

    tc->cntfrq = arch_timer_get_cntfrq();

    ret = nbl_trace_debugfs_init(tc);
    if (ret) {
        pr_err("create nebula trace debugfs failed!\n");
        goto unmap;
    }

    ret = nbl_trace_init_tracers(tc);
    if (ret) {
        pr_err("init nebula tracers failed!\n");
        goto unmap;
    }

    return 0;

unmap:
    if (tc->dbgfs_root)
        debugfs_remove_recursive(tc->dbgfs_root);
    if (tc->header)
        iounmap(tc->header);
    return ret;
}

static void __exit nbl_trace_exit(void)
{
    struct nbl_trace *tc = &g_nbl_trace;
    if (tc->dbgfs_root)
        debugfs_remove_recursive(tc->dbgfs_root);
    if (tc->header)
        iounmap(tc->header);
}

module_init(nbl_trace_init);
module_exit(nbl_trace_exit);

MODULE_DESCRIPTION("Nebula Tracing driver");
MODULE_LICENSE("GPL v2");
