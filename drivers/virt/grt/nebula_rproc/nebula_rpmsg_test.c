#include <linux/rpmsg.h>
#include <linux/module.h>
#include <linux/dma-mapping.h>
#include <linux/list.h>
#include <linux/delay.h>

#include <kunit/test.h>

static DECLARE_WAIT_QUEUE_HEAD(probe_waitq);
static volatile bool probed;

static struct rpmsg_device_id echo_id_table[] = {
	{ .name = "echo" },
	{},
};

#define WAIT_TIMEOUT 5
#define MSG_SIZE 64
#define MSG_COUNT 10

struct msg_item {
	struct list_head node;
	uint8_t data[MSG_SIZE];
};

struct rpmsg_private {
	struct list_head msg_items;
	struct mutex mutex;
	atomic_t recevied_msg_count;
};

static struct msg_item *create_msg_item(void *data, int len)
{
	struct msg_item *msg;

	msg = kzalloc(sizeof(struct msg_item), GFP_KERNEL);
	if (msg == NULL)
		return NULL;

	if (len > MSG_SIZE)
		len = MSG_SIZE;
	memcpy(msg->data, data, len);
	INIT_LIST_HEAD(&msg->node);

	return msg;
}

static int rpmsg_probe(struct rpmsg_device *rpdev)
{
	struct rpmsg_private *priv;

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (priv == NULL)
		return -ENOMEM;

	INIT_LIST_HEAD(&priv->msg_items);
	mutex_init(&priv->mutex);

	dev_set_drvdata(&rpdev->dev, priv);

	probed = true;
	wake_up_interruptible(&probe_waitq);

	return 0;
}

static void rpmsg_remove(struct rpmsg_device *rpdev)
{
	struct rpmsg_private *priv;
	struct msg_item *msg, *tmp;

	priv = dev_get_drvdata(&rpdev->dev);
	list_for_each_entry_safe(msg, tmp, &priv->msg_items, node) {
		list_del(&msg->node);
		kfree(msg);
	}
	kfree(priv);
}

static int rpmsg_cb(struct rpmsg_device *rpdev, void *data, int len,
		   void *ununsed, u32 src)
{
	struct rpmsg_private *priv;
	struct msg_item *msg;

	priv = dev_get_drvdata(&rpdev->dev);
	msg = create_msg_item(data, len);
	if (msg == NULL)
		return -ENOMEM;

	mutex_lock(&priv->mutex);
	list_add_tail(&msg->node, &priv->msg_items);
	mutex_unlock(&priv->mutex);

	atomic_inc(&priv->recevied_msg_count);
	return 0;
}

static struct rpmsg_driver echo_driver = {
	.drv = { .name = KBUILD_MODNAME "-echo" },
	.id_table = echo_id_table,
	.probe = rpmsg_probe,
	.callback = rpmsg_cb,
	.remove = rpmsg_remove,
};

static struct rpmsg_device_id sink_id_table[] = {
	{ .name = "sink" },
	{},
};

static struct rpmsg_driver sink_driver = {
	.drv = { .name = KBUILD_MODNAME "-sink" },
	.id_table = sink_id_table,
	.probe = rpmsg_probe,
	.callback = rpmsg_cb,
	.remove = rpmsg_remove,
};

struct rpmsg_test_priv {
	struct rpmsg_device *echo_rpdev;
};

static int wait_for_response(struct rpmsg_private *priv, size_t expected)
{
	u64 now = get_jiffies_64();

	while (true) {
		if ((get_jiffies_64() - now) > (WAIT_TIMEOUT * HZ))
			return -ETIMEDOUT;

		if (atomic_read(&priv->recevied_msg_count) == expected)
			break;

		usleep_range(1000, 2000);
	}

	return 0;
}

static void echo_test(struct kunit *test)
{
	struct rpmsg_test_priv *priv = test->priv;
	int i, ret;
	char expected_msg[MSG_COUNT][MSG_SIZE];
	struct rpmsg_private *echo_priv;
	struct msg_item *msg;

	for (i = 0; i < MSG_COUNT; i++) {
		memset(expected_msg[i], 0, MSG_SIZE);
		snprintf(expected_msg[i], MSG_SIZE, "hello from host %d!", i);
		ret = rpmsg_trysend(priv->echo_rpdev->ept, expected_msg[i],
				    MSG_SIZE);
		KUNIT_ASSERT_TRUE(test, ret == 0);
	}

	echo_priv = dev_get_drvdata(&priv->echo_rpdev->dev);
	ret = wait_for_response(echo_priv, MSG_COUNT);
	KUNIT_ASSERT_TRUE(test, ret == 0);

	i = 0;
	list_for_each_entry(msg, &echo_priv->msg_items, node) {
		KUNIT_EXPECT_STREQ(test, msg->data, expected_msg[i++]);
	}
}

struct rpmsg_device *rpmsg_create_channel(struct rpmsg_device *rpdev,
					  struct rpmsg_channel_info *chinfo);
int rpmsg_release_channel(struct rpmsg_device *rpdev,
			  struct rpmsg_channel_info *chinfo);

static void sink_test(struct kunit *test)
{
	struct rpmsg_test_priv *priv = test->priv;
	int i, ret;
	char expected_msg[MSG_COUNT][MSG_SIZE];
	struct rpmsg_private *sink_priv;
	struct rpmsg_device *sink_rpdev;
	struct msg_item *msg;
	struct rpmsg_channel_info chinfo;
	char channel_name[] = "sink";

	// create a new channel: this will announce a new service named "sink"
	// to remote processor. The remote processor will bind the service, and
	// then send serveral messages to the endpoint.
	memcpy(chinfo.name, channel_name, sizeof(channel_name));
	chinfo.src = 0x200;
	chinfo.dst = RPMSG_ADDR_ANY;
	sink_rpdev = rpmsg_create_channel(priv->echo_rpdev, &chinfo);
	KUNIT_ASSERT_TRUE(test, sink_rpdev != NULL);

	probed = false;
	ret = register_rpmsg_driver(&sink_driver);
	KUNIT_ASSERT_TRUE(test, ret == 0);

	// wait for sink driver probes the device
	wait_event_interruptible_timeout(probe_waitq, probed,
					HZ * WAIT_TIMEOUT);

	// remote side should send some msg to us, just way for it
	sink_priv = dev_get_drvdata(&sink_rpdev->dev);
	ret = wait_for_response(sink_priv, MSG_COUNT);
	KUNIT_ASSERT_TRUE(test, ret == 0);

	i = 0;
	list_for_each_entry(msg, &sink_priv->msg_items, node) {
		memset(expected_msg[i], 0, MSG_SIZE);
		snprintf(expected_msg[i], MSG_SIZE, "hello from remote %d!", i);
		KUNIT_EXPECT_STREQ(test, msg->data, expected_msg[i++]);
	}

	ret = rpmsg_release_channel(sink_rpdev, &chinfo);
	KUNIT_ASSERT_TRUE(test, ret == 0);

	unregister_rpmsg_driver(&sink_driver);
}

static int rpmsg_dev_match(struct device *dev, const void *name)
{
	struct rpmsg_device *rpdev =
		container_of(dev, struct rpmsg_device, dev);
	return strncmp(name, rpdev->id.name, RPMSG_NAME_SIZE) == 0;
}

static int rpmsg_test_init(struct kunit *test)
{
	int ret;
	struct device *dev;
	struct rpmsg_device *rpdev;

	struct rpmsg_test_priv *priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	KUNIT_ASSERT_TRUE(test, priv != NULL);

	// Echo channel will be announced by remote processor, and this event
	// creates the echo channel implicitly. After the driver registration,
	// rpmsg core will create a new endpoint automatically.
	probed = false;
	ret = register_rpmsg_driver(&echo_driver);
	KUNIT_ASSERT_TRUE(test, ret == 0);

	// wait for the echo endpoint is created by rpmsg core.
	wait_event_interruptible_timeout(probe_waitq, probed,
					HZ * WAIT_TIMEOUT);

	dev = bus_find_device(echo_driver.drv.bus, NULL, "echo",
			      rpmsg_dev_match);
	KUNIT_ASSERT_TRUE(test, dev != NULL);

	rpdev = container_of(dev, struct rpmsg_device, dev);
	priv->echo_rpdev = rpdev;
	test->priv = priv;

	return 0;
}

static void rpmsg_test_exit(struct kunit *test)
{
	unregister_rpmsg_driver(&echo_driver);
	kfree(test->priv);
}

// clang-format off
static struct kunit_case test_cases[] = {
	KUNIT_CASE(echo_test),
	KUNIT_CASE(sink_test),
	{}
};
// clang-format on

static struct kunit_suite rpmsg_test_suite = {
	.name = "nebula_rpmsg",
	.init = rpmsg_test_init,
	.exit = rpmsg_test_exit,
	.test_cases = test_cases,
};
kunit_test_suites(&rpmsg_test_suite);
MODULE_LICENSE("Dual BSD/GPL");
