// SPDX-License-Identifier: GPL-2.0
/*
 * System Control and Management Interface (SCMI) Message Mailbox Transport
 * driver.
 *
 * Copyright (C) 2019 ARM Ltd.
 */

#include <linux/arm-smccc.h>
#include <linux/err.h>
#include <linux/device.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/processor.h>
#include <linux/slab.h>

#include "common.h"
#include "smt.h"

/**
 * struct scmi_smc - Structure representing a SCMI mailbox transport
 *
 * @func_id: SMCCC function ID to be used to invoke the SCMI server
 * @cinfo: SCMI channel info
 * @shmem: Transmit/Receive shared memory area
 */
struct scmi_smc {
	unsigned long func_id;
	struct scmi_chan_info *cinfo;
	struct scmi_shared_mem __iomem *shmem;
};

static int smc_smt_chan_setup(struct scmi_chan_info *cinfo, struct device *dev,
			      bool tx)
{
	const char *desc = tx ? "Tx" : "Rx";
	struct device *cdev = cinfo->dev;
	struct scmi_smc *smc_smt;
	struct device_node *shmem;
	resource_size_t size;
	struct resource res;
	int idx = tx ? 0 : 1;
	int ret;
	unsigned int func_id;

	if (of_property_read_u32(dev->of_node, "arm,func-id", &func_id))
		return -EINVAL;

	smc_smt = devm_kzalloc(dev, sizeof(*smc_smt), GFP_KERNEL);
	if (!smc_smt)
		return -ENOMEM;

	smc_smt->func_id = func_id;

	shmem = of_parse_phandle(cdev->of_node, "shmem", idx);
	ret = of_address_to_resource(shmem, 0, &res);
	of_node_put(shmem);
	if (ret) {
		dev_err(cdev, "failed to get SCMI %s shared memory\n", desc);
		return ret;
	}

	size = resource_size(&res);
	smc_smt->shmem = devm_ioremap(dev, res.start, size);
	if (!smc_smt->shmem) {
		dev_err(dev, "failed to ioremap SCMI %s shared memory\n", desc);
		return -EADDRNOTAVAIL;
	}

	cinfo->transport_info = smc_smt;
	smc_smt->cinfo = cinfo;

	return 0;
}

static int smc_smt_chan_free(int id, void *p, void *data)
{
	struct scmi_chan_info *cinfo = p;
	struct scmi_smc *smc_smt = cinfo->transport_info;

	cinfo->transport_info = NULL;
	smc_smt->cinfo = NULL;

	scmi_free_channel(cinfo, data, id);

	return 0;
}

static int smc_smt_send_message(struct scmi_chan_info *cinfo,
				struct scmi_xfer *xfer)
{
	struct scmi_smc *smc_smt = cinfo->transport_info;
	struct arm_smccc_res res;
	int ret = 0;

	scmi_smt_tx_prepare(smc_smt->shmem, xfer);

	arm_smccc_smc(smc_smt->func_id, 0, 0, 0, 0, 0, 0, 0, &res);
	if (res.a0)
		ret = -EIO;

	scmi_rx_callback(cinfo, scmi_smt_read_msg_header(smc_smt->shmem));

	return ret;
}

static void smt_fetch_response(struct scmi_chan_info *cinfo,
			       struct scmi_xfer *xfer)
{
	struct scmi_smc *smc_smt = cinfo->transport_info;

	scmi_smt_fetch_response(smc_smt->shmem, xfer);
}

static bool smt_poll_done(struct scmi_chan_info *cinfo, struct scmi_xfer *xfer)
{
	struct scmi_smc *smc_smt = cinfo->transport_info;

	return scmi_smt_poll_done(smc_smt->shmem, xfer);
}

static bool smc_smt_chan_available(struct device *dev, int idx)
{
	unsigned int func_id;

	return !of_property_read_u32(dev->of_node, "arm,func-id", &func_id);
}

static struct scmi_transport_ops scmi_smc_ops = {
	.chan_available = smc_smt_chan_available,
	.chan_setup = smc_smt_chan_setup,
	.chan_free = smc_smt_chan_free,
	.send_message = smc_smt_send_message,
	.fetch_response = smt_fetch_response,
	.poll_done = smt_poll_done,
};

const struct scmi_desc scmi_smc_desc = {
	.ops = &scmi_smc_ops,
	.max_rx_timeout_ms = 30, /* We may increase this if required */
	.max_msg = 1,
	.max_msg_size = 128,
};
