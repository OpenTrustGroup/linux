/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * Copyright 2019 GoldenRiver Technologies Co., Ltd. All rights reserved.
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

#ifndef __LINUX_NEBULA_TRUSTY_KERN_IPC_H
#define __LINUX_NEBULA_TRUSTY_KERN_IPC_H

int tipc_connect(const char *dev_name, const char *srv_name);
int tipc_close(int fd);
ssize_t tipc_read(int fd, void *buf, size_t count);
ssize_t tipc_write(int fd, const void *buf, size_t count);
ssize_t tipc_poll(int fd, struct poll_table_struct *wait);

#define MAX_SHRMEM_COUNT 8
struct tipc_shmem {
    __u32 flags;
    __u32 size[3];
    __u64 base[3];
};

struct tipc_send_msg_req {
    __u64 msgiov;
    __u64 shmemv;
    __u32 msgiov_cnt;
    __u32 shmemv_cnt;
};

struct tipc_memref {
    uint32_t shr_mmap;
    uintptr_t shr_base;
    uint32_t shr_size;
    uint32_t data_off;
    uint32_t data_size;
    uint32_t page_size;
    struct tipc_shmem shmem;
};
int tipc_send_msg(int fd, const struct iovec *iov, unsigned int iov_cnt,
                  const struct tipc_memref *mrefv, unsigned int mrefv_cnt);
int tipc_recv_msg(int fd, const struct iovec *iov, unsigned int iovcnt);

#define TIPC_IOC_MAGIC			'r'
#define TIPC_IOC_CONNECT		_IOW(TIPC_IOC_MAGIC, 0x80, char *)

#if defined(CONFIG_COMPAT)
#define TIPC_IOC_CONNECT_COMPAT		_IOW(TIPC_IOC_MAGIC, 0x80, \
					     compat_uptr_t)

#endif

#define TIPC_IOC_SEND_MSG _IOW(TIPC_IOC_MAGIC, 0x81, struct tipc_send_msg_req)

#endif /* __LINUX_NEBULA_TRUSTY_KERN_IPC_H */
