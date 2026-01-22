/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _USER_LOG_DEV_H_
#define _USER_LOG_DEV_H_

#include <linux/cdev.h>
#include <linux/circ_buf.h>

#define USER_LOG_NODE_NAME_LEN 64

struct user_log_state {
	struct device *dev;
	struct cdev cdev;
	int minor;
	struct mutex read_lock;
	wait_queue_head_t fifo_event;
	struct circ_buf fifo;
	char *fifo_buf;
};

int user_log_dev_init(const char* dev_name);
void user_log_dev_exit(void);
struct user_log_state *user_log_dev_add(const char* node_name);
void user_log_dev_remove(struct user_log_state *s);
void user_log_dev_fifo_write(struct user_log_state *s, void *buf, size_t sz);

#endif
