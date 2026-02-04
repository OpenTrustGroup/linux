/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright 2018 GoldenRiver Technologies Co., Ltd. All rights reserved.
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
#ifndef _NBL_TUI_H_
#define _NBL_TUI_H_

#include <linux/ioctl.h>
#include <linux/fcntl.h>
#include <linux/nebula/trusty_kern_ipc.h>

#define DEVICE_NAME "nbl-tui"
#define DEVICE_NAME_KEVENT "nbl-tui-kevent"

#define ACTIVITY_MSG_MAGIC      (0x47534d41) /* 'AMSG' */
#define ACTIVITY_MSG_PARAM_NUM  (4)
#define ACTIVITY_MSG_TYPE_INIT  (1)
#define ACTIVITY_MSG_TYPE_STATE (2)

struct activity_msg {
	struct {
		__u32 magic;
		__u32 type;
	} hdr;
	struct {
		union {
			__u8 bytes[ACTIVITY_MSG_PARAM_NUM * sizeof(__u64)];
			__u64 params[ACTIVITY_MSG_PARAM_NUM];
		};
	} data;
} __packed;

struct tui_ion_buffer {
	__u32 fd;
};

struct tui_ssvp_buffer {
	__u64 addr;
	__u64 size;
};

struct tui_buffer_info {
	__u32 type;
	union {
		struct tui_ion_buffer ion;
		struct tui_ssvp_buffer ssvp;
		struct tipc_memref mref;
	};
};

enum TuiBufferType {
	TUI_BUFFER_TYPE_ION,
	TUI_BUFFER_TYPE_MEMREF,
	TUI_BUFFER_TYPE_SSVP,
};

struct tui_init_req {
	__u32 display_width;
	__u32 display_height;
	struct tui_buffer_info info;
};

#define NBL_TUI_IOC_MAGIC			't'
#define NBL_TUI_IOC_INIT		_IOW(NBL_TUI_IOC_MAGIC, 0x1, \
						struct tui_init_req)
#define NBL_TUI_IOC_STATE		_IOW(NBL_TUI_IOC_MAGIC, 0x2, char *)
#define NBL_TUI_IOC_READ_POWER_KEY	_IOR(NBL_TUI_IOC_MAGIC, 0x3, int)

struct tui_ctx {
	int fd;
} __packed;

#endif /* _NBL_TUI_H_ */
