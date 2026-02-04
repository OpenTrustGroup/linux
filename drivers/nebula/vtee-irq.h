/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2023 Google, Inc.
 */

#if !defined(_TRUSTY_IRQ_H)
#define _TRUSTY_IRQ_H

int vtee_irq_driver_init(void);
void vtee_irq_driver_exit(void);

#endif /* _TRUSTY_IRQ_H */