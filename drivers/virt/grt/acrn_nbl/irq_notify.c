#include "irq_notify.h"

#include <linux/of.h>
#include <linux/of_irq.h>
#include <linux/interrupt.h>

struct irq_notify {
	struct eventfd_ctx *ioevent_fd;
	uint32_t irq;
	spinlock_t lock;
	struct list_head node;
};

static LIST_HEAD(s_notify_irqs);
static DEFINE_MUTEX(s_notify_irqs_lock);

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
	struct device_node *np = NULL;
	struct irq_desc *desc;

	while ((np = of_find_compatible_node(np, NULL, "acrn,irq_notify")) !=
	       NULL) {
		struct irq_notify *irq_notify;
		int i, irq, ret;
		int irq_count = of_irq_count(np);

		for (i = 0; i < irq_count; i++) {
			irq = of_irq_get(np, i);
			BUG_ON(irq < 0);

			desc = irq_to_desc(irq);
			BUG_ON(desc == NULL);

			irq_notify = kzalloc(sizeof(*irq_notify), GFP_KERNEL);
			BUG_ON(irq_notify == NULL);

			irq_notify->irq = desc->irq_data.hwirq;
			spin_lock_init(&irq_notify->lock);

			mutex_lock(&s_notify_irqs_lock);
			list_add(&irq_notify->node, &s_notify_irqs);
			mutex_unlock(&s_notify_irqs_lock);

			ret = request_irq(irq, irq_notify_handler,
					  IRQF_TRIGGER_HIGH, "acrn,irq-notify",
					  (void *)irq_notify);
			BUG_ON(ret != 0);
		}

		of_node_put(np);
	}
}

void acrn_register_irq_notify(struct eventfd_ctx *ioevent_fd, uint32_t irq)
{
	ulong flags;
	struct irq_notify *irq_notify;

	list_for_each_entry(irq_notify, &s_notify_irqs, node) {
		if (irq_notify->irq == irq) {
			if (irq_notify->ioevent_fd != NULL) {
				pr_err("Failed to register irq notify:%u\n",
				       irq);
				return;
			}
			spin_lock_irqsave(&irq_notify->lock, flags);
			irq_notify->ioevent_fd = ioevent_fd;
			spin_unlock_irqrestore(&irq_notify->lock, flags);

			dev_dbg(acrn_dev.this_device,
				"regsitered hwirq %d for ioeventfd\n", irq);
			return;
		}
	}
}

void acrn_unregister_irq_notify(struct eventfd_ctx *ioevent_fd)
{
	ulong flags;
	struct irq_notify *irq_notify;

	list_for_each_entry(irq_notify, &s_notify_irqs, node) {
		if (irq_notify->ioevent_fd == ioevent_fd) {
			spin_lock_irqsave(&irq_notify->lock, flags);
			irq_notify->ioevent_fd = NULL;
			spin_unlock_irqrestore(&irq_notify->lock, flags);
		}
	}
}
