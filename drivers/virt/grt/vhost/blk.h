/* SPDX-License-Identifier: GPL-2.0-only */

#include <linux/vhost.h>

struct vhost_guest_memory_info {
	__u64 phys_base;
	__u64 userspace_base;
	__u64 size;
};

/* VHOST_BLK specific defines */
#define VHOST_BLK_SET_BACKEND _IOW(VHOST_VIRTIO, 0x50, struct vhost_vring_file)
#define VHOST_BLK_SET_GUEST_MEMORY_INFO _IOW(VHOST_VIRTIO, 0x51, struct vhost_guest_memory_info)
#define VHOST_BLK_SET_SERIAL _IOW(VHOST_VIRTIO, 0x52, struct vhost_guest_memory_info)
