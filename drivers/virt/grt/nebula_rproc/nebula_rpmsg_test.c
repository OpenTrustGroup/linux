// SPDX-License-Identifier: GPL-2.0-only
#include <linux/rpmsg.h>
#include <linux/module.h>
#include <linux/dma-mapping.h>
#include <linux/list.h>
#include <linux/delay.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>

#define WAIT_TIMEOUT		5
#define MSG_SIZE		64
#define MSG_COUNT		10

static DECLARE_WAIT_QUEUE_HEAD(probe_waitq);
static struct dentry *rpmsg_test_dir;
static struct dentry *echo_test_file;
static struct dentry *sink_test_file;
static volatile bool probed;
static int test_host = -1;

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

static struct rpmsg_device_id echo_id_table[] = {
	{ .name = "echo-alps" },
	{ .name = "echo-tbox" },
	{ .name = "echo-yocto" },
	{},
};

static struct rpmsg_driver echo_driver = {
	.drv = { .name = KBUILD_MODNAME "-echo-test" },
	.id_table = echo_id_table,
	.probe = rpmsg_probe,
	.callback = rpmsg_cb,
	.remove = rpmsg_remove,
};

static struct rpmsg_device_id sink_id_table[] = {
	{ .name = "sink-alps" },
	{ .name = "sink-tbox" },
	{ .name = "sink-yocto" },
	{},
};

static struct rpmsg_driver sink_driver = {
	.drv = { .name = KBUILD_MODNAME "-sink-test" },
	.id_table = sink_id_table,
	.probe = rpmsg_probe,
	.callback = rpmsg_cb,
	.remove = rpmsg_remove,
};

struct rpmsg_test_priv {
	struct rpmsg_device *echo_rpdev;
};

struct rpmsg_test_priv *priv = NULL;

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

static int rpmsg_dev_match(struct device *dev, const void *name)
{
	struct rpmsg_device *rpdev =
		container_of(dev, struct rpmsg_device, dev);

	return strncmp(name, rpdev->id.name, RPMSG_NAME_SIZE) == 0;
}

static void echo_test(void)
{
	int i, ret;
	char expected_msg[MSG_COUNT][MSG_SIZE];
	struct rpmsg_private *echo_priv;
	struct msg_item *msg;
	struct device *dev;
	struct rpmsg_device *rpdev;

		// wait for the echo endpoint is created by rpmsg core.
	wait_event_interruptible_timeout(probe_waitq, probed,
					HZ * WAIT_TIMEOUT);

	for (i = 0; i < ARRAY_SIZE(echo_id_table); i++) {
		dev = bus_find_device(echo_driver.drv.bus, NULL, echo_id_table[i].name,
				rpmsg_dev_match);
		if(dev) {
			test_host = i;
			break;
		}else if (!dev && (i == (ARRAY_SIZE(echo_id_table) - 1))) {
			pr_err("%s: bus_find_device failed\n", __func__);
			WARN_ON(1);
			return;
		}
	}

	rpdev = container_of(dev, struct rpmsg_device, dev);

	priv->echo_rpdev = rpdev;

	for (i = 0; i < MSG_COUNT; i++) {
		memset(expected_msg[i], 0, MSG_SIZE);
		snprintf(expected_msg[i], MSG_SIZE, "hello from host %d!", i);
		ret = rpmsg_trysend(priv->echo_rpdev->ept, expected_msg[i],
				    MSG_SIZE);
		if(ret) {
			pr_err("%s: Try send msg to remote failed\n", __func__);
			return;
		}
	}

	echo_priv = dev_get_drvdata(&priv->echo_rpdev->dev);
	ret = wait_for_response(echo_priv, MSG_COUNT);
	if(ret) {
		pr_err("%s: wait response timeout\n", __func__);
		return;
	}

	i = 0;
	list_for_each_entry(msg, &echo_priv->msg_items, node) {
		pr_info("%s: receive msg [%s]\n", __func__, msg->data);
		if (strcmp(msg->data, expected_msg[i++]) != 0) {
			pr_err("Test failed: expected '%s', got '%s'\n", expected_msg[i-1], msg->data);
			WARN_ON(1);
		}
	}

	pr_info("%s done\n", __func__);
}

struct rpmsg_device *rpmsg_create_channel(struct rpmsg_device *rpdev,
					  struct rpmsg_channel_info *chinfo);
int rpmsg_release_channel(struct rpmsg_device *rpdev,
			  struct rpmsg_channel_info *chinfo);

static void sink_test(void)
{
	int i, ret;
	char expected_msg[MSG_COUNT][MSG_SIZE];
	struct rpmsg_private *sink_priv;
	struct rpmsg_device *sink_rpdev;
	struct msg_item *msg;
	struct rpmsg_channel_info chinfo;

	if (test_host < 0) {
		pr_err("The echo test not run or test failed\n");
		return;
	}

	// create a new channel: this will announce a new service named "sink"
	// to remote processor. The remote processor will bind the service, and
	// then send serveral messages to the endpoint.
	memcpy(chinfo.name, sink_id_table[test_host].name, sizeof(sink_id_table[test_host].name));
	chinfo.src = 0x200;
	chinfo.dst = RPMSG_ADDR_ANY;
	sink_rpdev = rpmsg_create_channel(priv->echo_rpdev, &chinfo);
	if(!sink_rpdev) {
		pr_err("%s: rpmsg_create_channel failed\n", __func__);
		return;
	}

	probed = false;
	ret = register_rpmsg_driver(&sink_driver);
	if(ret) {
		pr_err("%s: register_rpmsg_driver failed\n", __func__);
		return;
	}

	// wait for sink driver probes the device
	wait_event_interruptible_timeout(probe_waitq, probed,
					HZ * WAIT_TIMEOUT);

	// remote side should send some msg to us, just way for it
	sink_priv = dev_get_drvdata(&sink_rpdev->dev);
	ret = wait_for_response(sink_priv, MSG_COUNT);
	if(ret) {
		pr_err("%s: wait_for_response timeout\n", __func__);
		return;
	}

	i = 0;
	list_for_each_entry(msg, &sink_priv->msg_items, node) {
		memset(expected_msg[i], 0, MSG_SIZE);
		snprintf(expected_msg[i], MSG_SIZE, "hello from remote %d!", i);
		pr_info("%s: msg data %s\n", __func__, msg->data);
		if (strcmp(msg->data, expected_msg[i++]) != 0) {
			pr_err("Test failed: expected '%s', got '%s'\n", expected_msg[i-1], msg->data);
		}
	}

	ret = rpmsg_release_channel(sink_rpdev, &chinfo);
	if(ret) {
		pr_err("%s: rpmsg_release_channel failed\n", __func__);
		return;
	}

	unregister_rpmsg_driver(&sink_driver);
}

// Helper function for debugfs write operations
static ssize_t test_trigger_write(struct file *file, const char __user *user_buf,
				size_t count, loff_t *ppos)
{
	char buf[32];

	if (count >= sizeof(buf))
		return -EINVAL;

	if (copy_from_user(buf, user_buf, count))
		return -EFAULT;

	buf[count] = '\0';

	if (file->f_path.dentry == echo_test_file) {
		echo_test();
		pr_info("Echo test done\n");
	} else if (file->f_path.dentry == sink_test_file) {
		sink_test();
		pr_info("Sink test done\n");
	} else {
		return -EINVAL;
	}

	return count;
}

static const struct file_operations test_fops = {
	.write = test_trigger_write,
	.owner = THIS_MODULE,
};

static int __init rpmsg_test_init(void)
{
	int ret;

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv) {
		pr_err("Failed to allocate memory for priv!\n");
		return -ENOMEM;
	}

	/*
	 * Echo channel will be announced by remote processor, and this event
	 * creates the echo channel implicitly. After the driver registration,
	 * rpmsg core will create a new endpoint automatically.
	 */
	probed = false;
	ret = register_rpmsg_driver(&echo_driver);
	if(ret) {
		pr_err("%s: register_rpmsg_driver failed\n", __func__);
		return ret;
	}

	rpmsg_test_dir = debugfs_create_dir("rpmsg_test", NULL);
	if (!rpmsg_test_dir) {
		pr_err("Failed to create debugfs directory\n");
		return -ENOMEM;
	}

	echo_test_file = debugfs_create_file("echo_test", 0666, rpmsg_test_dir,
				NULL, &test_fops);
	if (!echo_test_file) {
		pr_err("Failed to create echo_test debugfs file\n");
		return -ENOMEM;
	}

	sink_test_file = debugfs_create_file("sink_test", 0666, rpmsg_test_dir,
				NULL, &test_fops);
	if (!sink_test_file) {
		pr_err("Failed to create sink_test debugfs file\n");
		return -ENOMEM;
	}

	return 0;
}

static void __exit rpmsg_test_exit(void)
{
	unregister_rpmsg_driver(&echo_driver);
	kfree(priv);
}

module_init(rpmsg_test_init);
module_exit(rpmsg_test_exit);
MODULE_LICENSE("GPL v2");
