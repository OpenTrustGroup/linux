/* SPDX-License-Identifier: GPL-2.0-only */

#define pr_fmt(fmt) "nbl_trace: " fmt

#include <linux/debugfs.h>
#include "trace.h"
#include "cpu_ipi_delay.h"

cpu_ipi_delay_buf_t *_gl_cpu_ipi_delay_buf = NULL;

static inline cpu_ipi_delay_buf_t *_get_cpu_ipi_delay_buf(void)
{
	return _gl_cpu_ipi_delay_buf;
}

int start_record_cpu_ipi_delay(void)
{
	cpu_ipi_delay_buf_t *buf = _get_cpu_ipi_delay_buf();
	if (!buf)
		return -EFAULT;

	if (buf->enable) {
		pr_info("Trace vcpu sched delay already started!\n");
		return 0;
	}

	memset(buf, 0, sizeof(cpu_ipi_delay_buf_t));
	buf->enable = true;
	return 0;
}

int stop_record_cpu_ipi_delay(void)
{
	cpu_ipi_delay_buf_t *buf = _get_cpu_ipi_delay_buf();
	if (!buf)
		return -EFAULT;

	if (!buf->enable) {
		pr_info("Trace cpu ipi delay already stoped!\n");
		return 0;
	}

	buf->enable = false;
	wmb();
	return 0;
}

cpu_ipi_delay_buf_t *get_cpu_ipi_delay_buf(void)
{
	return _get_cpu_ipi_delay_buf();
}

static int cpu_ipi_delay_enable_get(void *data, u64 *val)
{
	if (!data || !val) {
		return -1;
	}

	cpu_ipi_delay_buf_t *delay = data;
	*val = delay->enable;
	return 0;
}

static int cpu_ipi_delay_enable_set(void *data, u64 val)
{
	if (!data) {
		return -1;
	}

	cpu_ipi_delay_buf_t *delay = data;
	int ret = 0;

	if (delay->enable == !!val) {
		pr_info("Trace already %s!\n",
			delay->enable ? "enabled" : "disabled");
		return 0;
	}

	if (val == 0) {
		memset(delay, 0, sizeof(cpu_ipi_delay_buf_t));
		delay->enable = 0;
	} else {
		delay->enable = 1;
	}

	pr_info("%s cpu ipi delay!\n",
		delay->enable ? "Start tracing" : "Stop tracing");
	return ret;
}

DEFINE_SIMPLE_ATTRIBUTE(cpu_ipi_delay_enable_ops, cpu_ipi_delay_enable_get,
			cpu_ipi_delay_enable_set, "%llu\n");

static inline void get_time_detail(u64 ticks, u64 *p_s, u64 *p_ms, u64 *p_us,
				   u64 *p_ns, u64 cntfrq)
{
	if (!p_s || !p_ms || !p_us || !p_ns) {
		return;
	}

	u64 ns, us, ms, s;

	//calc total ns
	ns = (ticks * 1000000000LL) / cntfrq;

	s = ns / 1000000000LL;
	ms = (ns % 1000000000) / 1000000LL;
	us = (ns % 1000000) / 1000;
	ns = ns % 1000;

	*p_ns = ns;
	*p_s = s;
	*p_ms = ms;
	*p_us = us;

	return;
}

static int cpu_ipi_delay_show(struct seq_file *s, void *data)
{
	if (!s || !data) {
		return -1;
	}

	cpu_ipi_delay_buf_t *prb = s->private;
	int i;

	unsigned long long freq;
	__asm__ volatile("mrs %0, cntfrq_el0" : "=r"(freq));

	if (!prb->enable)
		return 0;

	uint8_t src_cpu;
	uint8_t target_cpu;

	uint64_t time_diff;
	uint64_t p_s, p_ms, p_us, p_ns;

	//calc delay
	for (i = 0; i < MAX_BUF_SIZE; i++) {
		received_timestamp_t *prsv = &prb->receive_ipi[i];
		send_timestamp_t *psnd = &prb->send_ipi[i];

		src_cpu = psnd->src_cpu;
		target_cpu = psnd->target_cpu;

		time_diff = prsv->timestamp - psnd->timestamp;
		get_time_detail(time_diff, &p_s, &p_ms, &p_us, &p_ns, freq);

		seq_printf(s, "[%d]->[%d]:%03llu.%03llu.%03llu.%03llu\n",
			   src_cpu, target_cpu, p_s, p_ms, p_us, p_ns);
	}

	return 0;
}

static int cpu_ipi_delay_open(struct inode *inode, struct file *file)
{
	return single_open(file, cpu_ipi_delay_show, inode->i_private);
}

static const struct file_operations cpu_ipi_delay_ops = {
	.open = cpu_ipi_delay_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

int cpu_ipi_delay_init(struct nbl_tracer_data *data)
{
	if (!data) {
		return -1;
	}

	struct dentry *dbgfs_delay;
	cpu_ipi_delay_buf_t *delay;
	_gl_cpu_ipi_delay_buf = delay = nbl_trace_get_tracer_buf(data->tracer);

	dbgfs_delay = debugfs_create_dir(data->tracer->name, data->dbgfs_root);
	debugfs_create_file("enable", 0600, dbgfs_delay, delay,
			    &cpu_ipi_delay_enable_ops);
	debugfs_create_file(data->tracer->name, 0444, dbgfs_delay, delay,
			    &cpu_ipi_delay_ops);
	return 0;
}
