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

/**
 * struct scmi_smc_funcid - Structure representing a SCMI function ID transport
 *
 * @func_id: SMCCC function ID to be used to invoke the SCMI server
 * @cinfo: SCMI channel info
 * @shmem: Transmit/Receive shared memory area
 */
struct scmi_smc_funcid {
	unsigned long func_id;
	struct scmi_chan_info *cinfo;
	struct scmi_shared_mem __iomem *shmem;
};

static int smc_funcid_chan_setup(struct scmi_chan_info *cinfo,
				 struct device *dev, bool tx)
{
	const char *desc = tx ? "Tx" : "Rx";
	struct device *cdev = cinfo->dev;
	struct scmi_smc_funcid *smc_funcid;
	struct device_node *shmem;
	resource_size_t size;
	struct resource res;
	int idx = tx ? 0 : 1;
	int ret;
	unsigned int func_id;

	if (of_property_read_u32(dev->of_node, "arm,func-id", &func_id))
		return -EINVAL;

	smc_funcid = devm_kzalloc(dev, sizeof(*smc_funcid), GFP_KERNEL);
	if (!smc_funcid)
		return -ENOMEM;

	smc_funcid->func_id = func_id;

	shmem = of_parse_phandle(cdev->of_node, "shmem", idx);
	ret = of_address_to_resource(shmem, 0, &res);
	of_node_put(shmem);
	if (ret) {
		dev_err(cdev, "failed to get SCMI %s shared memory\n", desc);
		return ret;
	}

	size = resource_size(&res);
	smc_funcid->shmem = devm_ioremap(dev, res.start, size);
	if (!smc_funcid->shmem) {
		dev_err(dev, "failed to ioremap SCMI %s shared memory\n", desc);
		return -EADDRNOTAVAIL;
	}

	cinfo->transport_info = smc_funcid;
	smc_funcid->cinfo = cinfo;

	return 0;
}

static int smc_funcid_chan_free(int id, void *p, void *data)
{
	struct scmi_chan_info *cinfo = p;
	struct scmi_smc_funcid *smc_funcid = cinfo->transport_info;

	cinfo->transport_info = NULL;
	smc_funcid->cinfo = NULL;

	scmi_free_channel(cinfo, data, id);

	return 0;
}

static int smc_funcid_send_message(struct scmi_chan_info *cinfo,
				   struct scmi_xfer *xfer)
{
	struct scmi_smc_funcid *smc_funcid = cinfo->transport_info;
	struct arm_smccc_res res;
	int ret = 0;

	xfer->hdr.poll_completion = true;

	shmem_write_message(smc_funcid->shmem, xfer);

	arm_smccc_smc(smc_funcid->func_id, 0, 0, 0, 0, 0, 0, 0, &res);
	if (res.a0)
		ret = -EIO;

	scmi_rx_callback(cinfo, shmem_read_header(smc_funcid->shmem));

	return ret;
}

static void smc_funcid_fetch_response(struct scmi_chan_info *cinfo,
				      struct scmi_xfer *xfer)
{
	struct scmi_smc_funcid *smc_funcid = cinfo->transport_info;

	shmem_fetch_response(smc_funcid->shmem, xfer);
}

static bool smc_funcid_poll_done(struct scmi_chan_info *cinfo,
				 struct scmi_xfer *xfer)
{
	struct scmi_smc_funcid *smc_funcid = cinfo->transport_info;

	return shmem_poll_done(smc_funcid->shmem, xfer);
}

static struct scmi_transport_ops scmi_smc_funcid_ops = {
	.chan_setup = smc_funcid_chan_setup,
	.chan_free = smc_funcid_chan_free,
	.send_message = smc_funcid_send_message,
	.fetch_response = smc_funcid_fetch_response,
	.poll_done = smc_funcid_poll_done,
};

const struct scmi_desc scmi_smc_funcid_desc = {
	.ops = &scmi_smc_funcid_ops,
	.max_rx_timeout_ms = 30, /* We may increase this if required */
	.max_msg = 1,
	.max_msg_size = 128,
};
