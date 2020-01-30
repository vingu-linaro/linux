// SPDX-License-Identifier: GPL-2.0
/*
 * System Control and Management Interface (SCMI) Message Mailbox Transport
 * driver.
 *
 * Copyright (C) 2019 ARM Ltd.
 */

#include <linux/err.h>
#include <linux/device.h>
#include <linux/mailbox_client.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/processor.h>
#include <linux/slab.h>

#include "common.h"

/*
 * SCMI specification requires all parameters, message headers, return
 * arguments or any protocol data to be expressed in little endian
 * format only.
 */
struct scmi_shared_mem {
	__le32 reserved;
	__le32 channel_status;
#define SCMI_SHMEM_CHAN_STAT_CHANNEL_ERROR	BIT(1)
#define SCMI_SHMEM_CHAN_STAT_CHANNEL_FREE	BIT(0)
	__le32 reserved1[2];
	__le32 flags;
#define SCMI_SHMEM_FLAG_INTR_ENABLED	BIT(0)
	__le32 length;
	__le32 msg_header;
	u8 msg_payload[0];
};

/**
 * struct scmi_mailbox - Structure representing a SCMI mailbox transport
 *
 * @cl: Mailbox Client
 * @chan: Transmit/Receive mailbox channel
 * @cinfo: SCMI channel info
 * @shmem: Transmit/Receive shared memory area
 */
struct scmi_mailbox {
	struct mbox_client cl;
	struct mbox_chan *chan;
	struct scmi_chan_info *cinfo;
	struct scmi_shared_mem __iomem *shmem;
};

#define client_to_scmi_mailbox(c) container_of(c, struct scmi_mailbox, cl)

static void tx_prepare(struct mbox_client *cl, void *m)
{
	struct scmi_mailbox *smbox = client_to_scmi_mailbox(cl);
	struct scmi_shared_mem __iomem *shmem = smbox->shmem;
	struct scmi_xfer *xfer = m;

	/*
	 * Ideally channel must be free by now unless OS timeout last
	 * request and platform continued to process the same, wait
	 * until it releases the shared memory, otherwise we may endup
	 * overwriting its response with new message payload or vice-versa
	 */
	spin_until_cond(ioread32(&shmem->channel_status) &
			SCMI_SHMEM_CHAN_STAT_CHANNEL_FREE);
	/* Mark channel busy + clear error */
	iowrite32(0x0, &shmem->channel_status);
	iowrite32(xfer->hdr.poll_completion ? 0 : SCMI_SHMEM_FLAG_INTR_ENABLED,
		  &shmem->flags);
	iowrite32(sizeof(shmem->msg_header) + xfer->tx.len, &shmem->length);
	iowrite32(pack_scmi_header(&xfer->hdr), &shmem->msg_header);
	if (xfer->tx.buf)
		memcpy_toio(shmem->msg_payload, xfer->tx.buf, xfer->tx.len);
}

static void rx_callback(struct mbox_client *cl, void *m)
{
	struct scmi_mailbox *smbox = client_to_scmi_mailbox(cl);
	struct scmi_shared_mem __iomem *shmem = smbox->shmem;

	scmi_rx_callback(smbox->cinfo, ioread32(&shmem->msg_header));
}

static bool mailbox_chan_available(struct device *dev, int idx)
{
	return !of_parse_phandle_with_args(dev->of_node, "mboxes",
					   "#mbox-cells", idx, NULL);
}

static int mailbox_chan_setup(struct scmi_chan_info *cinfo, struct device *dev,
			      bool tx)
{
	const char *desc = tx ? "Tx" : "Rx";
	struct device *cdev = cinfo->dev;
	struct scmi_mailbox *smbox;
	struct device_node *shmem;
	int ret, idx = tx ? 0 : 1;
	struct mbox_client *cl;
	resource_size_t size;
	struct resource res;

	smbox = devm_kzalloc(dev, sizeof(*smbox), GFP_KERNEL);
	if (!smbox)
		return -ENOMEM;

	shmem = of_parse_phandle(cdev->of_node, "shmem", idx);
	ret = of_address_to_resource(shmem, 0, &res);
	of_node_put(shmem);
	if (ret) {
		dev_err(cdev, "failed to get SCMI %s shared memory\n", desc);
		return ret;
	}

	size = resource_size(&res);
	smbox->shmem = devm_ioremap(dev, res.start, size);
	if (!smbox->shmem) {
		dev_err(dev, "failed to ioremap SCMI %s shared memory\n", desc);
		return -EADDRNOTAVAIL;
	}

	cl = &smbox->cl;
	cl->dev = cdev;
	cl->tx_prepare = tx ? tx_prepare : NULL;
	cl->rx_callback = rx_callback;
	cl->tx_block = false;
	cl->knows_txdone = tx;

	smbox->chan = mbox_request_channel(cl, tx ? 0 : 1);
	if (IS_ERR(smbox->chan)) {
		ret = PTR_ERR(smbox->chan);
		if (ret != -EPROBE_DEFER)
			dev_err(cdev, "failed to request SCMI %s mailbox\n",
				tx ? "Tx" : "Rx");
		return ret;
	}

	cinfo->transport_info = smbox;
	smbox->cinfo = cinfo;

	return 0;
}

static int mailbox_chan_free(int id, void *p, void *data)
{
	struct scmi_chan_info *cinfo = p;
	struct scmi_mailbox *smbox = cinfo->transport_info;

	if (!IS_ERR(smbox->chan)) {
		mbox_free_channel(smbox->chan);
		cinfo->transport_info = NULL;
		smbox->chan = NULL;
		smbox->cinfo = NULL;
	}

	scmi_free_channel(cinfo, data, id);

	return 0;
}

static int mailbox_send_message(struct scmi_chan_info *cinfo,
				struct scmi_xfer *xfer)
{
	struct scmi_mailbox *smbox = cinfo->transport_info;
	int ret;

	ret = mbox_send_message(smbox->chan, xfer);

	/* mbox_send_message returns non-negative value on success, so reset */
	if (ret > 0)
		ret = 0;

	return ret;
}

static void mailbox_mark_txdone(struct scmi_chan_info *cinfo, int ret)
{
	struct scmi_mailbox *smbox = cinfo->transport_info;

	/*
	 * NOTE: we might prefer not to need the mailbox ticker to manage the
	 * transfer queueing since the protocol layer queues things by itself.
	 * Unfortunately, we have to kick the mailbox framework after we have
	 * received our message.
	 */
	mbox_client_txdone(smbox->chan, ret);
}

static void mailbox_fetch_response(struct scmi_chan_info *cinfo,
				   struct scmi_xfer *xfer)
{
	struct scmi_mailbox *smbox = cinfo->transport_info;
	struct scmi_shared_mem __iomem *shmem = smbox->shmem;

	xfer->hdr.status = ioread32(shmem->msg_payload);
	/* Skip the length of header and status in shmem area i.e 8 bytes */
	xfer->rx.len = min_t(size_t, xfer->rx.len, ioread32(&shmem->length) - 8);

	/* Take a copy to the rx buffer.. */
	memcpy_fromio(xfer->rx.buf, shmem->msg_payload + 4, xfer->rx.len);
}

static bool
mailbox_poll_done(struct scmi_chan_info *cinfo, struct scmi_xfer *xfer)
{
	struct scmi_mailbox *smbox = cinfo->transport_info;
	struct scmi_shared_mem __iomem *shmem = smbox->shmem;
	u16 xfer_id;

	xfer_id = MSG_XTRACT_TOKEN(ioread32(&shmem->msg_header));

	if (xfer->hdr.seq != xfer_id)
		return false;

	return ioread32(&shmem->channel_status) &
		(SCMI_SHMEM_CHAN_STAT_CHANNEL_ERROR |
		 SCMI_SHMEM_CHAN_STAT_CHANNEL_FREE);
}

static struct scmi_transport_ops scmi_mailbox_ops = {
	.chan_available = mailbox_chan_available,
	.chan_setup = mailbox_chan_setup,
	.chan_free = mailbox_chan_free,
	.send_message = mailbox_send_message,
	.mark_txdone = mailbox_mark_txdone,
	.fetch_response = mailbox_fetch_response,
	.poll_done = mailbox_poll_done,
};

const struct scmi_desc scmi_mailbox_desc = {
	.ops = &scmi_mailbox_ops,
	.max_rx_timeout_ms = 30, /* We may increase this if required */
	.max_msg = 20, /* Limited by MBOX_TX_QUEUE_LEN */
	.max_msg_size = 128,
};
