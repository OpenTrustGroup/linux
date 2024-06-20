// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2024 GoldenRiver Inc.

#include <linux/module.h>
#include <linux/of_address.h>

#include "rpmsg.h"
#include "nebula_rproc_remote.h"

#define MSG_COUNT 10
#define MSG_SIZE  64

struct sample_priv {
	struct rpmsg_endpoint echo_ept;
	struct rpmsg_endpoint sink_ept;
};

static int sink_endpoint_cb(struct rpmsg_endpoint *ept, void *data, size_t len,
			    uint32_t src, void *priv)
{
	return RPMSG_SUCCESS;
}

static void sink_endpoint_unbind(struct rpmsg_endpoint *ept)
{
	struct sample_priv *priv = nebula_rpmsg_backend_get_priv();

	rpmsg_destroy_ept(&priv->sink_ept);
}

static void sample_on_bind(struct rpmsg_device *rdev, const char *name,
			   uint32_t dest, void *data)
{
	int ret;
	struct sample_priv *priv = data;

	// frontend is expected to announce a service called "sink"
	const char expected[] = "sink";
	if (strncmp(expected, name, sizeof(expected)) == 0) {
		char msg[MSG_SIZE];
		int i;

		ret = rpmsg_create_ept(&priv->sink_ept, rdev, name,
				       RPMSG_ADDR_ANY, dest, sink_endpoint_cb,
				       sink_endpoint_unbind);
		if (ret != RPMSG_SUCCESS) {
			pr_err("failed to create ept, ret = %d\n", ret);
			return;
		}

		for (i = 0; i < MSG_COUNT; i++) {
			memset(msg, 0, sizeof(msg));
			snprintf(msg, MSG_SIZE, "hello from remote %d!", i);
			ret = rpmsg_trysend(&priv->sink_ept, msg, sizeof(msg));
			if (ret < 0) {
				pr_err("failed to send msg, ret = %d\n", ret);
				return;
			}
		}
	}
}

static int echo_endpoint_cb(struct rpmsg_endpoint *ept, void *data, size_t len,
			    uint32_t src, void *priv)
{
	/* Send data back to host */
	if (rpmsg_send(ept, data, len) < 0) {
		pr_err("rpmsg_send failed\r\n");
	}
	return RPMSG_SUCCESS;
}

static void echo_endpoint_unbind(struct rpmsg_endpoint *ept)
{
}

static int sample_on_create(struct rpmsg_device *rdev, void *data)
{
	struct sample_priv *priv = data;
	int ret;

	// annonce a service called "echo" to frontend
	ret = rpmsg_create_ept(&priv->echo_ept, rdev, "echo", RPMSG_ADDR_ANY,
			       RPMSG_ADDR_ANY, echo_endpoint_cb,
			       echo_endpoint_unbind);
	if (ret) {
		return ret;
	}

	return 0;
}

static struct nebula_rpmsg_backend_ops sample_ops = {
	.on_create = sample_on_create,
	.on_bind = sample_on_bind,
};

static struct nebula_rpmsg_backend sample_rpmsg = {
	.ops = &sample_ops,
};

static int __init nebula_rpmsg_sample_init(void)
{
	struct sample_priv *priv;

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	sample_rpmsg.priv = priv;
	nebula_rpmsg_backend_register(&sample_rpmsg);
	return 0;
}

module_init(nebula_rpmsg_sample_init);

static void __exit nebula_rpmsg_sample_exit(void)
{
	kfree(sample_rpmsg.priv);
	nebula_rpmsg_backend_unregister(&sample_rpmsg);
}
module_exit(nebula_rpmsg_sample_exit);
MODULE_LICENSE("Dual BSD/GPL");
