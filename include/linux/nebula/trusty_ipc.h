/* SPDX-License-Identifier: GPL-2.0-only */

/*
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
#ifndef __LINUX_NEBULA_TRUSTY_IPC_H
#define __LINUX_NEBULA_TRUSTY_IPC_H

#include <linux/device.h>

struct tipc_chan;

struct tipc_msg_buf {
	void *buf_va;
	phys_addr_t buf_pa;
	size_t buf_sz;
	size_t wpos;
	size_t rpos;
	struct list_head node;
};

struct tipc_shmem {
	__u32 flags;
	__u32 size[3];
	__u64 base[3];
};

enum tipc_chan_event {
	TIPC_CHANNEL_CONNECTED = 1,
	TIPC_CHANNEL_DISCONNECTED,
	TIPC_CHANNEL_SHUTDOWN,
};

struct tipc_chan_ops {
	void (*handle_event)(void *cb_arg, int event);
	struct tipc_msg_buf *(*handle_msg)(void *cb_arg,
					   struct tipc_msg_buf *mb);
	void (*handle_release)(void *cb_arg);
};

struct tipc_chan *nebula_tipc_create_channel(struct device *dev,
				      const struct tipc_chan_ops *ops,
				      void *cb_arg);

int nebula_tipc_chan_connect(struct tipc_chan *chan, const char *port);

int nebula_tipc_chan_queue_msg(struct tipc_chan *chan, struct tipc_msg_buf *mb,
			struct tipc_shmem *shmv, uint shmv_cnt);

int nebula_tipc_chan_shutdown(struct tipc_chan *chan);

void nebula_tipc_chan_destroy(struct tipc_chan *chan);

struct tipc_msg_buf *nebula_tipc_chan_get_rxbuf(struct tipc_chan *chan);

void nebula_tipc_chan_put_rxbuf(struct tipc_chan *chan, struct tipc_msg_buf *mb);

struct tipc_msg_buf *
nebula_tipc_chan_get_txbuf_timeout(struct tipc_chan *chan, long timeout);

#if defined(CONFIG_NEBULA_SECCAM_ION) || defined(CONFIG_NEBULA_SECCAM_ION_MODULE)
int nebula_tipc_register_ion_buffer(uint32_t handle, uint64_t phys_addr, uint32_t size);

int nebula_tipc_deregister_ion_buffer(uint32_t handle);
#endif

void nebula_tipc_chan_put_txbuf(struct tipc_chan *chan, struct tipc_msg_buf *mb);

static inline size_t mb_avail_space(struct tipc_msg_buf *mb)
{
	return mb->buf_sz - mb->wpos;
}

static inline size_t mb_avail_data(struct tipc_msg_buf *mb)
{
	return mb->wpos - mb->rpos;
}

static inline void *mb_put_data(struct tipc_msg_buf *mb, size_t len)
{
	void *pos = (u8 *)mb->buf_va + mb->wpos;
	BUG_ON(mb->wpos + len > mb->buf_sz);
	mb->wpos += len;
	return pos;
}

static inline void *mb_get_data(struct tipc_msg_buf *mb, size_t len)
{
	void *pos = (u8 *)mb->buf_va + mb->rpos;
	BUG_ON(mb->rpos + len > mb->wpos);
	mb->rpos += len;
	return pos;
}

struct notifier_block;
enum {
	TIPC_STATE_ONLINE,
	TIPC_STATE_OFFLINE,
};
int nebula_tipc_state_notifier_register(struct notifier_block *n);
int nebula_tipc_state_notifier_unregister(struct notifier_block *n);

#endif /* __LINUX_NEBULA_TRUSTY_IPC_H */

