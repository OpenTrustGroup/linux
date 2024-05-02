/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_ARM64_ACRN_H
#define _ASM_ARM64_ACRN_H

#include <linux/arm-smccc.h>
#include <linux/nebula/hvcall.h>

void acrn_setup_intr_handler(void (*handler)(void));
void acrn_remove_intr_handler(void);

static inline long acrn_hypercall0(unsigned long hcall_id)
{
	struct arm_smccc_res res;
	arm_smccc_smc(SMC_SC_NBL_VHM_REQ, hcall_id, 0, 0, 0, 0, 0, 0, &res);
	return res.a0;
}

static inline long acrn_hypercall1(unsigned long hcall_id, unsigned long param1)
{
	struct arm_smccc_res res;
	arm_smccc_smc(SMC_SC_NBL_VHM_REQ, hcall_id, param1, 0, 0, 0, 0, 0,
		      &res);
	return res.a0;
}

static inline long acrn_hypercall2(unsigned long hcall_id, unsigned long param1,
				   unsigned long param2)
{
	struct arm_smccc_res res;
	arm_smccc_smc(SMC_SC_NBL_VHM_REQ, hcall_id, param1, param2, 0, 0, 0, 0,
		      &res);
	return res.a0;
}

static inline long acrn_hypercall3(unsigned long hcall_id, unsigned long param1,
				   unsigned long param2, unsigned long param3)
{
	struct arm_smccc_res res;
	arm_smccc_smc(SMC_SC_NBL_VHM_REQ, hcall_id, param1, param2, param3, 0,
		      0, 0, &res);
	return res.a0;
}

static inline long acrn_hypercall4(unsigned long hcall_id, unsigned long param1,
				   unsigned long param2, unsigned long param3,
				   unsigned long param4)
{
	struct arm_smccc_res res;
	arm_smccc_smc(SMC_SC_NBL_VHM_REQ, hcall_id, param1, param2, param3,
		      param4, 0, 0, &res);
	return res.a0;
}

static inline long acrn_hypercall5(unsigned long hcall_id, unsigned long param1,
				   unsigned long param2, unsigned long param3,
				   unsigned long param4, unsigned long param5)
{
	struct arm_smccc_res res;
	arm_smccc_smc(SMC_SC_NBL_VHM_REQ, hcall_id, param1, param2, param3,
		      param4, param5, 0, &res);
	return res.a0;
}

#endif /* _ASM_ARM64_ACRN_H */
