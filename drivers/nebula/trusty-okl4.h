/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2012-2018 General Dynamics
 * Copyright (c) 2014 Open Kernel Labs, Inc
 * Copyright (c) 2018 GoldenRiver Technologies Co., Ltd. All rights reserved.
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

#ifndef _TRUSTY_OKL4_H_
#define _TRUSTY_OKL4_H_

// Original Header File: include/microvisor/microvisor.h

#if defined(_lint) || defined(_splint)
#define OKL4_FORCE_INLINE static
#else
#define OKL4_FORCE_INLINE static inline __attribute__((always_inline))
#endif


// Original Header File: include/microvisor/kernel/types.h

/**
    The `okl4_error_t` type represents an error condition returned by the
    OKL4 API.

    See OKL4_ERROR_*

    - @ref OKL4_ERROR_KSP_OK
    - @ref OKL4_ERROR_OK
    - @ref OKL4_ERROR_ALREADY_STARTED
    - @ref OKL4_ERROR_ALREADY_STOPPED
    - @ref OKL4_ERROR_AXON_AREA_TOO_BIG
    - @ref OKL4_ERROR_AXON_BAD_MESSAGE_SIZE
    - @ref OKL4_ERROR_AXON_INVALID_OFFSET
    - @ref OKL4_ERROR_AXON_QUEUE_NOT_MAPPED
    - @ref OKL4_ERROR_AXON_QUEUE_NOT_READY
    - @ref OKL4_ERROR_AXON_TRANSFER_LIMIT_EXCEEDED
    - @ref OKL4_ERROR_CANCELLED
    - @ref OKL4_ERROR_EXISTING_MAPPING
    - @ref OKL4_ERROR_INSUFFICIENT_SEGMENT_RIGHTS
    - @ref OKL4_ERROR_INTERRUPTED
    - @ref OKL4_ERROR_INTERRUPT_ALREADY_ATTACHED
    - @ref OKL4_ERROR_INTERRUPT_INVALID_IRQ
    - @ref OKL4_ERROR_INTERRUPT_NOT_ATTACHED
    - @ref OKL4_ERROR_INVALID_ARGUMENT
    - @ref OKL4_ERROR_INVALID_DESIGNATOR
    - @ref OKL4_ERROR_INVALID_SEGMENT_INDEX
    - @ref OKL4_ERROR_MEMORY_FAULT
    - @ref OKL4_ERROR_MISSING_MAPPING
    - @ref OKL4_ERROR_NON_EMPTY_MMU_CONTEXT
    - @ref OKL4_ERROR_NOT_IN_SEGMENT
    - @ref OKL4_ERROR_NO_RESOURCES
    - @ref OKL4_ERROR_PIPE_BAD_STATE
    - @ref OKL4_ERROR_PIPE_EMPTY
    - @ref OKL4_ERROR_PIPE_FULL
    - @ref OKL4_ERROR_PIPE_NOT_READY
    - @ref OKL4_ERROR_PIPE_RECV_OVERFLOW
    - @ref OKL4_ERROR_SEGMENT_USED
    - @ref OKL4_ERROR_THREAD_ALREADY_WATCHING_SUSPENDED
    - @ref OKL4_ERROR_TIMER_ACTIVE
    - @ref OKL4_ERROR_TIMER_CANCELLED
    - @ref OKL4_ERROR_TRY_AGAIN
    - @ref OKL4_ERROR_WOULD_BLOCK
    - @ref OKL4_ERROR_ALLOC_EXHAUSTED
    - @ref OKL4_ERROR_INVALID_AFFINITY
    - @ref OKL4_ERROR_KSP_ERROR_0
    - @ref OKL4_ERROR_KSP_ERROR_1
    - @ref OKL4_ERROR_KSP_ERROR_2
    - @ref OKL4_ERROR_KSP_ERROR_3
    - @ref OKL4_ERROR_KSP_ERROR_4
    - @ref OKL4_ERROR_KSP_ERROR_5
    - @ref OKL4_ERROR_KSP_ERROR_6
    - @ref OKL4_ERROR_KSP_ERROR_7
    - @ref OKL4_ERROR_KSP_INVALID_ARG
    - @ref OKL4_ERROR_KSP_NOT_IMPLEMENTED
    - @ref OKL4_ERROR_KSP_INSUFFICIENT_RIGHTS
    - @ref OKL4_ERROR_KSP_INTERRUPT_REGISTERED
    - @ref OKL4_ERROR_NOT_IMPLEMENTED
    - @ref OKL4_ERROR_MAX
*/

typedef uint32_t okl4_error_t;

#define OKL4_ERROR_OK ((okl4_error_t)0x0U)

#define OKL4_OK OKL4_ERROR_OK


/**
    The `okl4_count_t` type represents a natural number of items or
    iterations. This type is unsigned and cannot represent error values; use
    `okl4_scount_t` if an error representation is required.
*/

typedef uint32_t okl4_count_t;


/**
    The `okl4_kcap_t` type represents a kernel object capability identifier
    (otherwise known as *designator* or *cap*) that addresses a kernel
    capability. A capability encodes rights to perform particular operations on
    a kernel object.
*/

typedef okl4_count_t okl4_kcap_t;

/*lint -esym(621, OKL4_KCAP_INVALID) */
#define OKL4_KCAP_INVALID ((okl4_kcap_t)(0xffffffffU))

/**
    The `okl4_register_t` type represents an unsigned, machine-native
    register-sized integer value.
*/

typedef uint64_t okl4_register_t;


typedef okl4_register_t okl4_virq_flags_t;

/**
    The `okl4_interrupt_number_t` type is an index into the interrupt ID
    space. For platforms with a single simple interrupt controller, this is
    the physical interrupt number. When there are multiple interrupt
    controllers, or a large and sparse interrupt ID space, the mapping from
    this type to the physical interrupt is defined by the KSP.
*/

typedef okl4_count_t okl4_interrupt_number_t;

/*lint -esym(621, OKL4_INTERRUPT_INVALID_IRQ) */
#define OKL4_INTERRUPT_INVALID_IRQ ((okl4_interrupt_number_t)(1023U))

/*lint -esym(621, OKL4_INVALID_VIRQ) */
#define OKL4_INVALID_VIRQ ((okl4_interrupt_number_t)(1023U))


typedef okl4_interrupt_number_t okl4_irq_t;


struct _okl4_sys_interrupt_get_payload_return {
    okl4_error_t error;
    okl4_virq_flags_t payload;
};


// Original Header File: include/microvisor/kernel/syscalls.h

#if defined(ASSEMBLY)
#define __hvc_str(x) x
#else
#define _hvc_str(x) #x
#define __hvc_str(x) _hvc_str(x)
#endif
#if (defined(__GNUC__) && !defined(__clang__)) && \
    (__GNUC__ < 4 || ((__GNUC__ == 4) && (__GNUC_MINOR__ < 5)))
#if defined(__thumb2__)
#define hvc(i) __hvc_str(.hword 0xf7e0 | (i & 0xf); .hword 8000 | (i >> 4) @ HVC)
#else
#define hvc(i) __hvc_str(.word 0xe1400070 | (i & 0xf) | (i >> 4 << 8) @ HVC)
#endif
#else
#if defined(__ARM_EABI__)
#if defined(ASSEMBLY) && !defined(__clang__)
    .arch_extension virt
#elif !defined(__clang__)
__asm__(
    ".arch_extension virt\n"
);
#endif
#endif
#define hvc(i) __hvc_str(hvc i)
#endif

/**
 *
 * @brief Raise a virtual interrupt, setting specified payload flags.
 *
 *    @details
 *    This triggers a virtual interrupt by raising a virtual interrupt
 *        source. A
 *    virtual interrupt source object is distinct from a virtual interrupt.
 *        A
 *    virtual interrupt source is always linked to a virtual interrupt, but
 *        the
 *    reverse is not true.
 *
 *    Each Microvisor virtual interrupt carries a payload of flags which
 *        may be
 *    fetched by the recipient of the interrupt. An interrupt payload is a
 *        @ref
 *    okl4_word_t sized array of flags, packed into a single word. Flags
 *        are
 *    cleared whenever the interrupt recipient fetches the payload with the
 *        @ref
 *    okl4_sys_interrupt_get_payload API.
 *
 *    The interrupt-raise API allows the caller to pass in a new set of
 *        flags in
 *    the \p payload field. If the interrupt has previously been raised and
 *        not
 *    yet delivered, the flags accumulate; that is, each flag is the
 *        boolean OR
 *    of its previous value and the specified value.
 *
 *    When the recipient has configured the interrupt for edge triggering,
 *        an
 *    invocation of this API is counted as a single edge; this triggers
 *        interrupt
 *    delivery if the interrupt is not already pending, irrespective of the
 *    payload. If the interrupt is configured for level triggering, then
 *        its
 *    pending state is the boolean OR of its payload flags after any
 *        specified
 *    flags are raised; at least one flag must be set in the new payload to
 *    permit delivery of a level-triggered interrupt.
 *
 *    @note Invoking this API is equivalent to invoking the @ref
 *    okl4_sys_vinterrupt_modify API with all bits set in the \p mask
 *        value.
 *
 *    @note This API is distinct from the @ref okl4_sys_interrupt_raise
 *        API,
 *    which raises a local software-generated interrupt without requiring
 *        an
 *    explicit capability.
 *
 * @param virqline
 *    A virtual interrupt line capability.
 * @param payload
 *    A machine-word-sized array of payload flags to set.
 *
 * @retval error
 *    The resulting error value.
 *
 */

#if defined(__ARM_EABI__)

#if defined(__RVCT__) || defined(__RVCT_GNU__)
#elif defined(__ADS__)
#else
OKL4_FORCE_INLINE okl4_error_t
_okl4_sys_vinterrupt_raise(okl4_kcap_t virqline, okl4_virq_flags_t payload)
{
    register uint32_t r0 asm("r0") = (uint32_t)virqline;
    register uint32_t r1 asm("r1") = (uint32_t)(payload        & 0xffffffff);
    register uint32_t r2 asm("r2") = (uint32_t)((payload >> 32) & 0xffffffff);
    __asm__ __volatile__(
            ""hvc(5196)"\n\t"
            : "+r"(r0), "+r"(r1), "+r"(r2)
            :
            : "cc", "memory", "r3", "r4", "r5"
            );


    return (okl4_error_t)r0;
}
#endif

#else

OKL4_FORCE_INLINE okl4_error_t
_okl4_sys_vinterrupt_raise(okl4_kcap_t virqline, okl4_virq_flags_t payload)
{
    register okl4_register_t x0 asm("x0") = (okl4_register_t)virqline;
    register okl4_register_t x1 asm("x1") = (okl4_register_t)payload;
    __asm__ __volatile__(
            "" hvc(5196) "\n\t"
            : "+r"(x0), "+r"(x1)
            :
            : "cc", "memory", "x2", "x3", "x4", "x5", "x6", "x7"
            );


    return (okl4_error_t)x0;
}

#endif

/**
 *
 * @brief Fetch the payload flags of a virtual interrupt.
 *
 *    @details
 *    This fetches and clears the accumulated payload flags for a virtual
 *    interrupt that has been raised by the Microvisor, or by a vCPU
 *        invoking
 *    the @ref okl4_sys_vinterrupt_raise API.
 *
 *    If the virtual interrupt is configured for level triggering, clearing
 *        the
 *    accumulated flags by calling this function will also clear the
 *        pending state
 *    of the interrupt.
 *
 * @param irq
 *    An interrupt line number for the virtual GIC.
 *
 * @retval error
 *    The resulting error value.
 * @retval payload
 *    Accumulated virtual interrupt payload flags.
 *
 */

#if defined(__ARM_EABI__)

#if defined(__RVCT__) || defined(__RVCT_GNU__)
#elif defined(__ADS__)
#else
OKL4_FORCE_INLINE struct _okl4_sys_interrupt_get_payload_return
_okl4_sys_interrupt_get_payload(okl4_interrupt_number_t irq)
{
    typedef union {
        struct uint64 {
            uint32_t lo;
            uint32_t hi;
        } words;
        uint64_t val;
    } okl4_uint64_tmp;
    okl4_uint64_tmp payload_tmp;
    struct _okl4_sys_interrupt_get_payload_return result;

    register uint32_t r0 asm("r0") = (uint32_t)irq;
    register uint32_t r1 asm("r1");
    register uint32_t r2 asm("r2");
    __asm__ __volatile__(
            ""hvc(5132)"\n\t"
            : "=r"(r1), "=r"(r2), "+r"(r0)
            :
            : "cc", "memory", "r3", "r4", "r5"
            );


    result.error = (okl4_error_t)(r0);
    payload_tmp.words.lo = r1;
    payload_tmp.words.hi = r2;
    result.payload = (okl4_virq_flags_t)(payload_tmp.val);
    return result;
}
#endif

#else

OKL4_FORCE_INLINE struct _okl4_sys_interrupt_get_payload_return
_okl4_sys_interrupt_get_payload(okl4_interrupt_number_t irq)
{
    struct _okl4_sys_interrupt_get_payload_return result;

    register okl4_register_t x0 asm("x0") = (okl4_register_t)irq;
    register okl4_register_t x1 asm("x1");
    __asm__ __volatile__(
            "" hvc(5132) "\n\t"
            : "=r"(x1), "+r"(x0)
            :
            : "cc", "memory", "x2", "x3", "x4", "x5", "x6", "x7"
            );


    result.error = (okl4_error_t)(x0);
    result.payload = (okl4_virq_flags_t)(x1);
    return result;
}

#endif


#endif /* _TRUSTY_OKL4_H_ */
