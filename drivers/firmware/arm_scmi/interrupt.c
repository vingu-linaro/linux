// SPDX-License-Identifier: GPL-2.0
/*
 * System Control and Management Interface (SCMI) Interrupt Protocol
 *
 * Copyright (C) 2019-2020 ARM Ltd.
 */

#define pr_fmt(fmt) "SCMI INTERRUPT - " fmt
#define SCMI_PROTOCOL_INTERRUPT 0x80

#include <linux/module.h>
#include <linux/scmi_protocol.h>

#include "common.h"
#include "notify.h"

#include <linux/interrupt.h>
#include <linux/of.h>
#include <linux/of_irq.h>

enum scmi_interrupt_protocol_cmd {
	INTERRUPT_DOMAIN_ATTRIBUTES = 0x3,
	INTERRUPT = 0x4,
};

#define NUM_INTERRUPT_DOMAIN_MASK	0xffff

struct scmi_msg_resp_interrupt_domain_attributes {
	__le32 attributes;
	    u8 name[SCMI_MAX_STR_SIZE];
};

struct scmi_msg_interrupt_domain_interrupt {
	__le32 hwid;
};

struct interrupt_dom_info {
	int hwid;
	char name[SCMI_MAX_STR_SIZE];
};

struct scmi_interrupt_info {
	u32 version;
	int num_irqs;
	struct interrupt_dom_info *dom_info;
};

static int scmi_interrupt_attributes_get(const struct scmi_protocol_handle *ph,
				     struct scmi_interrupt_info *pi)
{
	int ret;
	struct scmi_xfer *t;
	u32 attr;

	ret = ph->xops->xfer_get_init(ph, PROTOCOL_ATTRIBUTES,
				      0, sizeof(attr), &t);
	if (ret)
		return ret;

	ret = ph->xops->do_xfer(ph, t);
	if (!ret) {
		attr = get_unaligned_le32(t->rx.buf);
		pi->num_irqs = attr & NUM_INTERRUPT_DOMAIN_MASK;
	}

	ph->xops->xfer_put(ph, t);
	return ret;
}

static int
scmi_interrupt_domain_attributes_get(const struct scmi_protocol_handle *ph,
				 u32 domain, struct interrupt_dom_info *dom_info)
{
	int ret;
	struct scmi_xfer *t;
	struct scmi_msg_resp_interrupt_domain_attributes *attr;
	u32 hwid;

	ret = ph->xops->xfer_get_init(ph, INTERRUPT_DOMAIN_ATTRIBUTES,
				      sizeof(domain), sizeof(*attr), &t);
	if (ret)
		return ret;

	put_unaligned_le32(domain, t->tx.buf);
	attr = t->rx.buf;

	ret = ph->xops->do_xfer(ph, t);
	if (!ret) {
		u32 attributes = le32_to_cpu(attr->attributes);
		dom_info->hwid = attributes & NUM_INTERRUPT_DOMAIN_MASK;
		strlcpy(dom_info->name, attr->name, SCMI_MAX_STR_SIZE);
	}

	ph->xops->xfer_put(ph, t);
	return ret;
}

static int scmi_interrupt_num_irq_get(const struct scmi_protocol_handle *ph)
{
	struct scmi_interrupt_info *pi = ph->get_priv(ph);

	return pi->num_irqs;
}

static int
scmi_interrupt_hwid_get(const struct scmi_protocol_handle *ph, u32 domain)
{
	int ret;
	struct scmi_interrupt_info *pi = ph->get_priv(ph);
	struct interrupt_dom_info *rdom = pi->dom_info + domain;

	return rdom->hwid;
}


static int
scmi_interrupt_assert(const struct scmi_protocol_handle *ph, u32 domain)
{
	int ret;
	struct scmi_xfer *t;
	struct scmi_interrupt_info *pi = ph->get_priv(ph);
	struct interrupt_dom_info *rdom = pi->dom_info + domain;

	ret = ph->xops->xfer_get_init(ph, INTERRUPT, sizeof(u32), 0, &t);
	if (ret)
		return ret;

	put_unaligned_le32(rdom->hwid, t->tx.buf);

	ret = ph->xops->do_xfer(ph, t);

	ph->xops->xfer_put(ph, t);
	return ret;
}


/**
 * struct scmi_reset_ops - represents the various operations provided
 *	by SCMI Reset Protocol
 *
 * @num_domains_get: get the count of reset domains provided by SCMI
 * @assert: explicitly assert reset signal of the specified reset domain
 */
struct scmi_interrupt_ops {
	int (*num_irq_get)(const struct scmi_protocol_handle *ph);
	int (*hwid_get)(const struct scmi_protocol_handle *ph, u32 domain);
	int (*assert)(const struct scmi_protocol_handle *ph, u32 domain);
};

static const struct scmi_interrupt_ops interrupt_ops = {
	.num_irq_get = scmi_interrupt_num_irq_get,
	.hwid_get = scmi_interrupt_hwid_get,
	.assert = scmi_interrupt_assert,
};

static int scmi_interrupt_protocol_init(const struct scmi_protocol_handle *ph)
{
	int domain;
	u32 version;
	struct scmi_interrupt_info *pinfo;

	ph->xops->version_get(ph, &version);

	dev_dbg(ph->dev, "Interrupt Version %d.%d\n",
		PROTOCOL_REV_MAJOR(version), PROTOCOL_REV_MINOR(version));

	pinfo = devm_kzalloc(ph->dev, sizeof(*pinfo), GFP_KERNEL);
	if (!pinfo)
		return -ENOMEM;

	scmi_interrupt_attributes_get(ph, pinfo);

	pinfo->dom_info = devm_kcalloc(ph->dev, pinfo->num_irqs,
				       sizeof(*pinfo->dom_info), GFP_KERNEL);
	if (!pinfo->dom_info)
		return -ENOMEM;

	for (domain = 0; domain < pinfo->num_irqs; domain++) {
		struct interrupt_dom_info *dom = pinfo->dom_info + domain;

		scmi_interrupt_domain_attributes_get(ph, domain, dom);
	}

	pinfo->version = version;
	return ph->set_priv(ph, pinfo);
}

static int scmi_interrupt_protocol_deinit(const struct scmi_protocol_handle *ph)
{
	return 0;
}

static const struct scmi_protocol scmi_interrupt = {
	.id = SCMI_PROTOCOL_INTERRUPT,
	.owner = THIS_MODULE,
	.instance_init = &scmi_interrupt_protocol_init,
	.instance_deinit = &scmi_interrupt_protocol_deinit,
	.ops = &interrupt_ops,
};

module_scmi_protocol(scmi_interrupt);

MODULE_AUTHOR("Vincent Guittot");
MODULE_DESCRIPTION("ARM SCMI Interrupt Protocol");
MODULE_LICENSE("GPL v2");


static const struct scmi_interrupt_ops *irq_ops;

struct scmi_interrupt_data {
	struct scmi_protocol_handle *ph;
	int domain;
};

static irqreturn_t scmi_interrupt_handler(int irq, void *data)
{
	struct scmi_interrupt_data *irq_data = data;
	pr_info("++++++scmi_interrupt_handler %d", irq);
	irq_ops->assert(irq_data->ph, irq_data->domain);
	return IRQ_HANDLED;
}

static int scmi_irq_probe(struct scmi_device *sdev)
{
	int nr_irq, idx;
	struct device *dev = &sdev->dev;
	const struct scmi_handle *handle = sdev->handle;
	struct scmi_protocol_handle *ph;

	if (!handle)
		return -ENODEV;

	irq_ops = handle->devm_protocol_get(sdev, SCMI_PROTOCOL_INTERRUPT, &ph);
	if (IS_ERR(irq_ops))
		return PTR_ERR(irq_ops);

	nr_irq = irq_ops->num_irq_get(ph);
	if (!nr_irq)
		return -EIO;


	for (idx = 0; idx < nr_irq; idx++) {
		int ret, hwirq, irq, node_idx;
		struct scmi_interrupt_data *data;

		hwirq = irq_ops->hwid_get(ph, idx);

		for (node_idx = 0; node_idx < 16; node_idx++) {

			irq = of_irq_get(sdev->dev.of_node, node_idx);

			if (irq <= 0)
				break;

			if (hwirq !=  irq+32)
				continue;

			pr_info("scmi_interrupt idx %d hwirq %d irq %d", idx, hwirq, irq);

			data = devm_kzalloc(dev, sizeof(struct scmi_interrupt_data), GFP_KERNEL);
			if (!data)
				return -ENOMEM;

			data->ph = ph;
			data->domain = idx;

			ret = devm_request_threaded_irq(ph->dev, irq, NULL,
				scmi_interrupt_handler, IRQF_ONESHOT,
				"scmi-irq", data);
			if (ret)
				dev_err(ph->dev, "unable to get irq: %d\n", ret);
		}
	}

	return 0;
}

static const struct scmi_device_id scmi_id_table[] = {
	{ SCMI_PROTOCOL_INTERRUPT, "irq" },
	{ },
};
MODULE_DEVICE_TABLE(scmi, scmi_id_table);

static struct scmi_driver scmi_irq_driver = {
	.name = "scmi-irq",
	.probe = scmi_irq_probe,
	.id_table = scmi_id_table,
};

module_scmi_driver(scmi_irq_driver);

