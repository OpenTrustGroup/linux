/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2021 GoldenRiver Technologies Co., Ltd.
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

#ifndef __NEBULA_BASE_RPC_PROTO_H__
#define __NEBULA_BASE_RPC_PROTO_H__

#define RPC_TARGET_KERNEL 1u
#define RPC_TARGET_USER	  0u
#define RPC_TARGET_SHIFT  31

#define RPC_OWNER_MASK	   0xFF
#define RPC_OWNER_SHIFT	   12
#define RPC_FUNCTION_MASK  0xFF
#define RPC_FUNCTION_SHIFT 0

#define RPC_IS_KERNEL(ordinal)                                                 \
	((ordinal) & (RPC_TARGET_KERNEL << RPC_TARGET_SHIFT))
#define RPC_IS_USER(ordinal) (!RPC_IS_KERNEL(ordinal))

#define RPC_GET_OWNER(ordinal) (((ordinal) >> RPC_OWNER_SHIFT) & RPC_OWNER_MASK)
#define RPC_GET_FUNCTION(ordinal)                                              \
	(((ordinal) >> RPC_FUNCTION_SHIFT) & RPC_FUNCTION_MASK)

enum {
	RPC_OWNER_NEBULA = 0,
	RPC_OWNER_NEBULA_RESERVED_MAX = 0x3f, /* 0x63 */
	RPC_OWNER_CUSTOM_FIRST,
	RPC_OWNER_CUSTOM_LAST = 0xff,
};

#define DEFINE_RPC_CALL(target, owner, fn)                                     \
	(((target) << RPC_TARGET_SHIFT) |                                      \
	 (((owner)&RPC_OWNER_MASK) << RPC_OWNER_SHIFT) |                       \
	 (((fn)&RPC_FUNCTION_MASK) << RPC_FUNCTION_SHIFT))

// KRPC: RPC targeting Kernel space
// URPC: RPC targeting User space
// Macro format: [OWNER]_[TYPE]RPC_CALL
#define NBL_KRPC_CALL(fn)                                                      \
	DEFINE_RPC_CALL(RPC_TARGET_KERNEL, RPC_OWNER_NEBULA, (fn))
#define NBL_URPC_CALL(fn)                                                      \
	DEFINE_RPC_CALL(RPC_TARGET_USER, RPC_OWNER_NEBULA, (fn))

//    0      000 0000 0000    0000 0000    0000     0000 0000
//  TARGET |     RES0      |   OWNER    |   RES   |   FUNC
//    31        30-20          19-12       11-8       7-0

#define KRPC_FUNC_TABLE                                                        \
	/* 0 */                                                                \
	KRPC_FUNC(ECHO)                                                        \
	KRPC_FUNC(UNITTEST)                                                    \
	/* 15 */                                                               \
	KRPC_FUNC_RESERVED(15)                                                 \
	KRPC_FUNC(MEMPOOL_ACQUIRE)                                             \
	KRPC_FUNC(MEMPOOL_RELEASE)                                             \
	KRPC_FUNC(TUI_START_POWERKEY_OBSERVER)                                 \
	KRPC_FUNC(TUI_STOP_POWERKEY_OBSERVER)                                  \
	/* 20 */                                                               \
	KRPC_FUNC(TUI_TPD_OFF)                                                 \
	KRPC_FUNC(TUI_TPD_ON)                                                  \
	KRPC_FUNC(TUI_TPD_DEVID)                                               \
	KRPC_FUNC(TUI_I2C_CLK_ON)                                              \
	KRPC_FUNC(TUI_I2C_CLK_OFF)                                             \
	/* 25 */                                                               \
	KRPC_FUNC(TUI_DISP_OFF)                                                \
	KRPC_FUNC(TUI_DISP_ON)                                                 \
	KRPC_FUNC(SMMU_ALLOC)                                                  \
	KRPC_FUNC(SMMU_FREE)                                                   \
	KRPC_FUNC_RESERVED(255)

enum KrpcFuncType {
#define KRPC_FUNC(name)	       KRPC_FUNCTION_##name,
#define KRPC_FUNC_RESERVED(id) KRPC_FUNCTION_RESERVED##id = id,
	KRPC_FUNC_TABLE
#undef KRPC_FUNC
#undef KRPC_FUNC_RESERVED
};

enum KrpcCallType {
#define KRPC_FUNC(name) NBL_KRPC_##name = NBL_KRPC_CALL(KRPC_FUNCTION_##name),
#define KRPC_FUNC_RESERVED(id)
	KRPC_FUNC_TABLE
#undef KRPC_FUNC
#undef KRPC_FUNC_RESERVED
};

#define URPC_FUNC_TABLE                                                        \
	/* 0 */                                                                \
	URPC_FUNC(ECHO)                                                        \
	/* 15 */                                                               \
	URPC_FUNC_RESERVED(15)                                                 \
	URPC_FUNC(MEM_ALLOC)                                                   \
	URPC_FUNC(MEM_FREE)                                                    \
	URPC_FUNC(TUI_START)                                                   \
	URPC_FUNC(TUI_STOP)                                                    \
	/* 20 */                                                               \
	URPC_FUNC(TUI_POWER_KEY_PRESSED)                                       \
	URPC_FUNC_RESERVED(255)

enum UrpcFuncType {
#define URPC_FUNC(name)	       URPC_FUNCTION_##name,
#define URPC_FUNC_RESERVED(id) URPC_FUNCTION_RESERVED##id = id,
	URPC_FUNC_TABLE
#undef URPC_FUNC
#undef URPC_FUNC_RESERVED
};

enum UrpcCallType {
#define URPC_FUNC(name) NBL_URPC_##name = NBL_URPC_CALL(URPC_FUNCTION_##name),
#define URPC_FUNC_RESERVED(id)
	URPC_FUNC_TABLE
#undef URPC_FUNC
#undef URPC_FUNC_RESERVED
};

enum {
	RPC_FLAG_RESP_BIT = 1u << 0,
	RPC_FLAG_STOP_BIT = 1u << 1,
	RPC_FLAG_ACK_BIT = 1u << 2,
};

struct rpc_message_header_t {
	uint32_t txid;
	uint32_t reserved0;
	uint32_t flags;
	uint32_t ordinal;
} __attribute__((packed));

struct rpc_message_t {
	struct rpc_message_header_t header;
	uint8_t payload[];
} __attribute__((packed));

#define RPC_MESSAGE_HEADER_SIZE (sizeof(struct rpc_message_header_t))
#define MAX_RPC_MESSAGE_SIZE	4080
#define MAX_RPC_PAYLOAD_SIZE	(MAX_RPC_MESSAGE_SIZE - RPC_MESSAGE_HEADER_SIZE)

#endif // __NEBULA_BASE_RPC_PROTO_H__
