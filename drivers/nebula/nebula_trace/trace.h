/*
 * Copyright 2024 GoldenRiver Technologies Co., Ltd. All rights reserved.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#ifndef _NBL_TRACE_H_
#define _NBL_TRACE_H_

#define ARM64_GTIMER_FREQ       13000000

#define NBL_TRACE_VCPU_CNT  8
#define NBL_TRACE_VM_CNT    2

/* group definition */
enum {
    GRP_VCPU_EXEC,
    GRP_VCPU_RUN_ACCUM,
    GRP_VCPU_EXIT_REASON,
    GRP_IRQ_COUNT,
    GRP_PCPU_STATUS,
    GRP_VCPU_SCHED_DELAY,
    GRP_VCPU_EXEC_SPLIT,
    GRP_TOP,
    GRP_IRQ_DELAY,
    GRP_KTRACE,
    GRP_COMCAT_LINK,
    GRP_CPU_IPI_DELAY,
    GRP_NBL_REV,
    GRP_TYPE_CNT,
};

#define TRACER_NAME_LEN     32 

/*
 * tracers[N] description:
 *
 * @name:
 *      tracer's name, which is the trace directory name and the key
 *      to query tracer.
 * @buf_offs:
 *      tracer's buffer offset, tracer can define its own structure
 *      in this buffer.
 * @buf_size:
 *      tracer's buffer size.
 * @err_code:
 *      the latest Error code return from Nebula.
 * @supported:
 *      if this tracer is supported?
 */
typedef struct {
    char name[TRACER_NAME_LEN];
    size_t buf_offs;
    size_t buf_size;
    int32_t err_code;
    bool supported;
} nbl_tracer_info_t;

struct nbl_tracer_data {
    nbl_tracer_info_t *tracer;
    struct dentry *dbgfs_root;
};

typedef int (*nbl_tracer_init)(struct nbl_tracer_data *data);

int irq_count_init(struct nbl_tracer_data *data);
int ktrace_init(struct nbl_tracer_data *data);
int pcpu_status_init(struct nbl_tracer_data *data);
int top_utils_init(struct nbl_tracer_data *data);
int vcpu_exec_init(struct nbl_tracer_data *data);
int vcpu_exec_split_init(struct nbl_tracer_data *data);
int vcpu_exit_reason_init(struct nbl_tracer_data *data);
int vcpu_exec_accum_init(struct nbl_tracer_data *data);
int vcpu_sched_delay_init(struct nbl_tracer_data *data);
int irq_delay_init(struct nbl_tracer_data *data);
int comcat_trace_init(struct nbl_tracer_data *data);
int cpu_ipi_delay_init(struct nbl_tracer_data *data);
int nebula_version_init(struct nbl_tracer_data *data);

void *nbl_trace_get_tracer_buf(nbl_tracer_info_t *tracer);

#endif /* _NBL_TRACE_H_ */

