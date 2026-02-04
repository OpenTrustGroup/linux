/* SPDX-License-Identifier: GPL-2.0-only */
#define pr_fmt(fmt) "nbl-tui-input: " fmt

#include <linux/kthread.h>
#include <linux/kfifo.h>
#include <linux/mutex.h>
#include <linux/nebula/nbl-tui.h>
#include <linux/nebula/trusty_ipc.h>
#include <linux/delay.h>
#include <linux/input.h>

static char *service_name = "tipc_touch";

#define DEFAULT_WAIT_TIMEOUT_MS 1000
#define MAX_INPUT_EVENT_COUNT 64
#define ABS_EVENT_MAX 0x7FFF

enum input_abs_event_code {
	INPUT_EV_ABS_X = 0,
	INPUT_EV_ABS_Y = 1,
};

enum input_event_type {
	INPUT_EV_SYN = 0x00,
	INPUT_EV_KEY = 0x01,
	INPUT_EV_ABS = 0x03,
};

struct private_data {
	wait_queue_head_t wait_queue;
	DECLARE_KFIFO(input_event_fifo, struct input_value,
		      MAX_INPUT_EVENT_COUNT);
	struct mutex mutex;
	uint16_t x_max;
	uint16_t y_max;

	struct tipc_chan *tipc_chan;
	struct completion reply_comp;
	bool tipc_connected;
};
static struct private_data g_priv;

static void handle_event(void *cb_arg, int event)
{
	mutex_lock(&g_priv.mutex);

	switch (event) {
	case TIPC_CHANNEL_CONNECTED:
		pr_info("tipc channel connected\n");
		g_priv.tipc_connected = true;
		break;
	case TIPC_CHANNEL_DISCONNECTED:
		pr_info("tipc channel disconnected\n");
		g_priv.tipc_connected = false;
		break;
	case TIPC_CHANNEL_SHUTDOWN:
		pr_info("tipc channel shutdown\n");
		g_priv.tipc_connected = false;
		break;
	}

	mutex_unlock(&g_priv.mutex);
	complete(&g_priv.reply_comp);
}

static struct tipc_msg_buf *handle_msg(void *cb_arg, struct tipc_msg_buf *mb)
{
	return NULL;
}

static void handle_release(void *data)
{
}

static struct tipc_chan_ops tipc_ops = {
	.handle_event = handle_event,
	.handle_msg = handle_msg,
	.handle_release = handle_release,
};

static int wait_for_reply(int timeout)
{
	return wait_for_completion_interruptible_timeout(
		&g_priv.reply_comp, msecs_to_jiffies(timeout));
}

static bool is_tipc_connected(void)
{
	bool result;

	mutex_lock(&g_priv.mutex);
	result = (g_priv.tipc_chan && g_priv.tipc_connected);
	mutex_unlock(&g_priv.mutex);
	return result;
}

static void connect_tui_input(struct work_struct *work)
{
	int retry = 10;

	BUG_ON(g_priv.tipc_chan);
	g_priv.tipc_chan = nebula_tipc_create_channel(NULL, &tipc_ops, NULL);
	if (!g_priv.tipc_chan) {
		pr_warn("failed to create tipc channel\n");
		return;
	}

	while (retry > 0) {
		int ret = nebula_tipc_chan_connect(g_priv.tipc_chan, service_name);
		if (ret == 0) {
			ret = wait_for_reply(DEFAULT_WAIT_TIMEOUT_MS);
			if (ret > 0) {
				if (is_tipc_connected())
					return;

				ret = -ENOENT;
			} else if (ret == 0) {
				ret = -ETIMEDOUT;
			}
		}
		pr_warn("failed to connect touch service: %d, retry after 10ms\n",
			ret);
		msleep(10);
		retry--;
	}

	if (retry == 0) {
		pr_warn("failed to connect touch service after retries. give up\n");
	}
}
static DECLARE_WORK(tipc_worker, connect_tui_input);

int nbl_tui_input_connect(void)
{
	schedule_work(&tipc_worker);
	return 0;
}
EXPORT_SYMBOL(nbl_tui_input_connect);

void nbl_tui_input_disconnect(void)
{
	mutex_lock(&g_priv.mutex);

	nebula_tipc_chan_shutdown(g_priv.tipc_chan);
	nebula_tipc_chan_destroy(g_priv.tipc_chan);
	g_priv.tipc_chan = NULL;
	g_priv.tipc_connected = false;

	mutex_unlock(&g_priv.mutex);
}
EXPORT_SYMBOL(nbl_tui_input_disconnect);

void nbl_tui_input_set_abs_max(uint16_t x_max, uint16_t y_max)
{
	mutex_lock(&g_priv.mutex);

	g_priv.x_max = x_max;
	g_priv.y_max = y_max;

	mutex_unlock(&g_priv.mutex);
}
EXPORT_SYMBOL(nbl_tui_input_set_abs_max);

static int report_input_event(uint16_t type, uint16_t code, uint32_t value)
{
	int copied;
	struct input_value event = {
		.type = type,
		.code = code,
		.value = value,
	};

	copied = kfifo_put(&g_priv.input_event_fifo, event);
	if (copied) {
		wake_up(&g_priv.wait_queue);
	} else {
		pr_warn("input event fifo overrun\n");
		return -EBUSY;
	}

	return 0;
}

void nbl_tui_input_report_abs(uint16_t x, uint16_t y, uint8_t down)
{
	uint16_t calibrated_x, calibrated_y;

	calibrated_x = (uint64_t)x * ABS_EVENT_MAX / g_priv.x_max;
	calibrated_y = (uint64_t)y * ABS_EVENT_MAX / g_priv.y_max;

	report_input_event(INPUT_EV_ABS, INPUT_EV_ABS_X, calibrated_x);
	report_input_event(INPUT_EV_ABS, INPUT_EV_ABS_Y, calibrated_y);
	report_input_event(INPUT_EV_KEY, 0x110, down);
	report_input_event(INPUT_EV_SYN, 0, 0);
}
EXPORT_SYMBOL(nbl_tui_input_report_abs);

static void dump_events(struct input_value *events, int num_events)
{
	int i;
	for (i = 0; i < num_events; i++) {
		pr_debug("report input event, type:%x, code:%x: value %x\n",
			 events[i].type, events[i].code, events[i].value);
	}
}

static int input_event_thread(void *__unused)
{
	int ret;
	struct input_value events[MAX_INPUT_EVENT_COUNT];

	while (!kthread_should_stop()) {
		struct tipc_msg_buf *msg;
		size_t bytes_to_write;
		int num_events = 0;

		ret = wait_event_interruptible(
			g_priv.wait_queue,
			!kfifo_is_empty(&g_priv.input_event_fifo));
		WARN_ON(ret < 0);

		while (kfifo_get(&g_priv.input_event_fifo,
				 &events[num_events])) {
			num_events++;
		}

		if (!is_tipc_connected()) {
			pr_warn("nbl touch service is not connected. Input events dropped\n");
			continue;
		}

		dump_events(events, num_events);

		msg = nebula_tipc_chan_get_txbuf_timeout(g_priv.tipc_chan,
						  /*timeout=*/1000);
		if (IS_ERR(msg)) {
			pr_warn("failed to get tipc txbuf: %ld\n",
				PTR_ERR(msg));
			continue;
		}

		bytes_to_write = sizeof(struct input_value) * num_events;
		memcpy(mb_put_data(msg, bytes_to_write), events,
		       bytes_to_write);
		ret = nebula_tipc_chan_queue_msg(g_priv.tipc_chan, msg, NULL, 0);
		WARN_ON(ret < 0);
	}
	return 0;
}

static int nbl_tui_input_init(void)
{
	struct task_struct *p;

	init_waitqueue_head(&g_priv.wait_queue);
	mutex_init(&g_priv.mutex);
	init_completion(&g_priv.reply_comp);
	g_priv.tipc_chan = NULL;
	g_priv.tipc_connected = false;
	g_priv.x_max = ABS_EVENT_MAX;
	g_priv.y_max = ABS_EVENT_MAX;
	INIT_KFIFO(g_priv.input_event_fifo);

	p = kthread_create(input_event_thread, NULL, "nbl_tui_input");
	if (!IS_ERR(p))
		wake_up_process(p);
	else
		WARN_ON(1);

	return 0;
}

subsys_initcall(nbl_tui_input_init);
