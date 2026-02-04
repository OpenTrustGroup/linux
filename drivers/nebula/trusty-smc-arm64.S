/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2020 Google, Inc.
 */

#include <linux/linkage.h>
#include <linux/version.h>
.macro push ra, rb
stp \ra, \rb, [sp,#-16]!
.endm

.macro pop ra, rb
ldp \ra, \rb, [sp], #16
.endm

lr .req x30
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
ENTRY(trusty_smc8)
#else
SYM_START(trusty_smc8, SYM_L_GLOBAL, SYM_A_ALIGN)
#endif
    /*
     * Save x8 (return value ptr) and lr. The SMC calling convention says el3
     * does not need to preserve x8. The normal ABI does not require either x8
     * or lr to be preserved.
     */
    push    x8, lr
    smc     #0
    pop     x8, lr

    /* Copy 8-register smc return value to struct smc_ret8 return value */
    stp     x0, x1, [x8], #16
    stp     x2, x3, [x8], #16
    stp     x4, x5, [x8], #16
    stp     x6, x7, [x8], #16

    ret
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
ENDPROC(trusty_smc8)
#else
SYM_END(trusty_smc8, SYM_T_FUNC)
#endif