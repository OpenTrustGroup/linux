#ifndef __ACRN_IRQ_NOTIFY_H
#define __ACRN_IRQ_NOTIFY_H

#include "acrn_drv.h"

#include <linux/eventfd.h>

void acrn_init_irq_notify(void);

void acrn_register_irq_notify(struct eventfd_ctx *ioevent_fd, uint32_t irq);
void acrn_unregister_irq_notify(struct eventfd_ctx *ioevent_fd);

#endif