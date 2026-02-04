/*
 * Copyright 2020 GoldenRiver Technologies Co., Ltd. All rights reserved.
 * Copyright (C) 2015 Google, Inc.
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
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/delay.h>
#include <asm/uaccess.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <asm/irq.h>
#include <asm/io.h>

#include "trace.h"
#include "nbl_rev.h"

#define NEBULA_REV_NAME        "nbl_rev"
#define NEBULA_REV_BUF_LEN     128

static char nbl_rev_buf[NEBULA_REV_BUF_LEN];
static nbl_rev_buf_t *g_nbl_rev_buf = NULL;
static struct proc_dir_entry *proc_file;

static ssize_t nebula_rev_read(struct file *file, char __user *user_buf,
             size_t count, loff_t *ppos)
{
    int len = strlen(nbl_rev_buf);
    if (*ppos > 0 || count < len)
        return 0;

    if (copy_to_user(user_buf, nbl_rev_buf, len)) {
		return -EFAULT;
	}
    *ppos += len;

    return len;
}

static const struct proc_ops nebula_rev_fops = {
    .proc_read = nebula_rev_read,
};

int nebula_version_init(struct nbl_tracer_data *data)
{
    g_nbl_rev_buf = nbl_trace_get_tracer_buf(data->tracer);
    if (!g_nbl_rev_buf)
        return -ENOMEM;

    proc_file = proc_create(NEBULA_REV_NAME, S_IRUSR, NULL, &nebula_rev_fops);
	if (!proc_file) {
        printk(KERN_ERR "/proc/%s created fail.\n", NEBULA_REV_NAME);
        return -ENOMEM;
    }

    strncpy(nbl_rev_buf, g_nbl_rev_buf->nebula_rev, NEBULA_REV_BUF_LEN - 1);
    return 0;
}
