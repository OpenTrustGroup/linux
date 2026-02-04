/* SPDX-License-Identifier: GPL-2.0-only */

#include <linux/slab.h>
#include <linux/module.h>
#include <linux/ktime.h>
#include <linux/debugfs.h>
#include <linux/proc_fs.h>

#define NODE_NAME	"bootticks"

static int do_boot_ticks_calibration(struct seq_file *s, u64 *ticks,
		u64 *freq_out)
{
	int i, cali_cnt;
	unsigned long flags;
	u64 ns, tk, offs, max, min, off, freq, sec, rem;

	min = -1ULL;
	max = 0ULL;
	cali_cnt = 100;
	__asm__ volatile("mrs %0, cntfrq_el0" : "=r" (freq));
	if (!freq)
		return -EINVAL;

	for (i = offs = 0; i < cali_cnt; i++) {
		/*
		 * Minimize the measurement time delay caused by
		 * preemption due to system scheduling or interrupts.
		 */
		local_irq_save(flags);
		preempt_disable();

		ns = ktime_to_ns(ktime_get());
		__asm__ volatile("mrs %0, cntvct_el0" : "=r" (tk));

		local_irq_restore(flags);
		preempt_enable();

		/*
		 * To avoid losing precision, ticks will be calculated
		 * using the following formula:
		 *   off = tk - ns * freq / 1000000000;
		 * However, ns * freq will quickly overflow. For example,
		 * when freq is 13MHz, it will overflow after 1418 seconds.
		 * Therefore, we need to split the calculation into seconds
		 * and remainders for separate processing.
		 */
		sec = ns / 1000000000;
		rem = ns % 1000000000;
		off = tk - (sec * freq + rem * freq / 1000000000);
		/* The offset should not overflow for 100 loops */
		offs += off;
		min = (off < min) ? off : min;
		max = (off > max) ? off : max;

		cpu_relax();
	}

	if (max - min > freq / 1000)
		seq_printf(s,
			"Warning: time jitter is larger than 1us, max=%llu min=%llu\n",
			max, min);

	*ticks = offs / cali_cnt;
	*freq_out = freq;

	return 0;
}

static int bootticks_proc_show(struct seq_file *s, void *p)
{
	u64 ticks, freq;
	int ret;

	ret = do_boot_ticks_calibration(s, &ticks, &freq);
	if (ret) {
		seq_printf(s, "Error: calibration failed! (%d)\n", ret);
		return ret;
	}

	/* print the ticks when the system start to boot */
	seq_printf(s, "%llu %llu\n", ticks, freq);

	return 0;
}

static int bootticks_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, bootticks_proc_show, NULL);
}

static const struct proc_ops bootticks_proc_fops = {
	.proc_open	= bootticks_proc_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

static int boot_ticks_show(struct seq_file *s, void *data)
{
	u64 ticks, freq;
	int ret;

	ret = do_boot_ticks_calibration(s, &ticks, &freq);
	if (ret) {
		seq_printf(s, "Error: calibration failed! (%d)\n", ret);
		return ret;
	}

	/* print the ticks when the system start to boot */
	seq_printf(s, "%llu %llu\n", ticks, freq);

	return 0;
}

static int boot_ticks_open(struct inode *inode, struct file *file)
{
	return single_open(file, boot_ticks_show, inode->i_private);
}

static const struct file_operations boot_ticks_ops = {
	.open	 = boot_ticks_open,
	.read		  = seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int __init boot_ticks_init(void)
{
	struct dentry *boot_ticks_ent = NULL;
	struct proc_dir_entry *entry;

	entry = proc_create(NODE_NAME, 0, NULL, &bootticks_proc_fops);
	if (!entry) {
		pr_err("Failed to create /proc/%s\n", NODE_NAME);
		return -ENOMEM;
	}

	boot_ticks_ent = debugfs_create_file(NODE_NAME, 0644, NULL, NULL,
			  &boot_ticks_ops);
	if (!boot_ticks_ent) {
		pr_info("create /sys/kernel/debug/%s failed\n", NODE_NAME);
		return -ENOMEM;
	}

	return 0;
}

static void __exit boot_ticks_exit(void)
{
	remove_proc_entry(NODE_NAME, NULL);
	return;
}

module_init(boot_ticks_init)
module_exit(boot_ticks_exit)

MODULE_DESCRIPTION("Boot time ticks calibration");
MODULE_LICENSE("GPL v2");
