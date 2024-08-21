#include "irq_notify.h"

#include <linux/of.h>
#include <linux/of_irq.h>
#include <linux/interrupt.h>

struct irq_notify {
	struct eventfd_ctx *ioevent_fd;
	uint32_t irq;
	spinlock_t lock;
};

static struct irq_notify s_irq_notify;

static irqreturn_t irq_notify_handler(int irq, void *data)
{
	struct irq_notify *notify;

	notify = (struct irq_notify *)data;
	spin_lock(&notify->lock);
	if (notify->ioevent_fd) {
		eventfd_signal(notify->ioevent_fd, 1);
	}
	spin_unlock(&notify->lock);

	return IRQ_HANDLED;
}

void acrn_init_irq_notify(void)
{
	struct device_node *notify_node;
	struct irq_desc *desc;
	int irq;
	int ret;

	notify_node = of_find_compatible_node(NULL, NULL, "acrn,irq_notify");
	if (notify_node == NULL) {
		pr_err("Failed to find acrn,irq_notify node.\n");
		return;
	}

	irq = of_irq_get(notify_node, 0);
	if (!irq) {
		pr_err("Failed to parse acrn,irq_notify's irq:%d\n", irq);
		return;
	}

	desc = irq_to_desc(irq);
	if (desc == NULL) {
		pr_err("Failed to find irq desc:%d\n", irq);
		return;
	}
	s_irq_notify.irq = desc->irq_data.hwirq;
	spin_lock_init(&s_irq_notify.lock);
	ret = request_irq(irq, irq_notify_handler, IRQF_TRIGGER_HIGH,
			  "acrn,irq-notify", (void *)&s_irq_notify);
	if (ret) {
		pr_err("Failed to request irq handler:%d\n", ret);
	}

	return;
}

void acrn_register_irq_notify(struct eventfd_ctx *ioevent_fd, uint32_t irq)
{
	ulong flags;

	if (s_irq_notify.irq == irq) {
		if (s_irq_notify.ioevent_fd != NULL) {
			pr_err("Failed to register irq notify:%u\n", irq);
			return;
		}
		spin_lock_irqsave(&s_irq_notify.lock, flags);
		s_irq_notify.ioevent_fd = ioevent_fd;
		spin_unlock_irqrestore(&s_irq_notify.lock, flags);
	}
}

void acrn_unregister_irq_notify(struct eventfd_ctx *ioevent_fd)
{
	ulong flags;

	if (s_irq_notify.ioevent_fd == ioevent_fd) {
		spin_lock_irqsave(&s_irq_notify.lock, flags);
		s_irq_notify.ioevent_fd = NULL;
		spin_unlock_irqrestore(&s_irq_notify.lock, flags);
	}
}
