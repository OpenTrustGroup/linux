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

#ifndef _NBL_VERSION_H_
#define _NBL_VERSION_H_

#define NEBULA_REV_BUF_LEN 128
typedef struct {
    uint8_t nebula_rev[NEBULA_REV_BUF_LEN];
} nbl_rev_buf_t;

#endif