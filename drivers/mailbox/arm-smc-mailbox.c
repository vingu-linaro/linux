// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2016,2017 ARM Ltd.
 * Copyright 2019 NXP
 */

#include <linux/arm-smccc.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/interrupt.h>
#include <linux/mailbox_controller.h>
#include <linux/mailbox/arm-smc-mailbox.h>
#include <linux/module.h>
#include <linux/platform_device.h>

#define ARM_SMC_MBOX_USE_HVC	BIT(0)
#define ARM_SMC_MBOX_USB_IRQ	BIT(1)

struct arm_smc_chan_data {
	u32 function_id;
	u32 flags;
	int irq;
};

static int arm_smc_send_data(struct mbox_chan *link, void *data)
{
	struct arm_smc_chan_data *chan_data = link->con_priv;
	struct arm_smccc_mbox_cmd *cmd = data;
	struct arm_smccc_res res;
	u32 function_id;

	if (chan_data->function_id != UINT_MAX)
		function_id = chan_data->function_id;
	else
		function_id = cmd->a0;

	if (chan_data->flags & ARM_SMC_MBOX_USE_HVC)
		arm_smccc_hvc(function_id, cmd->a1, cmd->a2, cmd->a3, cmd->a4,
			      cmd->a5, cmd->a6, cmd->a7, &res);
	else
		arm_smccc_smc(function_id, cmd->a1, cmd->a2, cmd->a3, cmd->a4,
			      cmd->a5, cmd->a6, cmd->a7, &res);

	if (chan_data->irq)
		return 0;

	mbox_chan_received_data(link, (void *)res.a0);

	return 0;
}

static const struct mbox_chan_ops arm_smc_mbox_chan_ops = {
	.send_data	= arm_smc_send_data,
};

static irqreturn_t chan_irq_handler(int irq, void *data)
{
	struct mbox_chan *chan = data;

	mbox_chan_received_data(chan, NULL);

	return IRQ_HANDLED;
}

static int arm_smc_mbox_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct mbox_controller *mbox;
	struct arm_smc_chan_data *chan_data;
	const char *method;
	bool use_hvc = false;
	int ret, irq_count, i;
	u32 val;

	if (!of_property_read_u32(dev->of_node, "arm,num-chans", &val)) {
		if (val < 1 || val > INT_MAX) {
			dev_err(dev, "invalid arm,num-chans value %u of %pOFn\n", val, pdev->dev.of_node);
			return -EINVAL;
		}
	}

	irq_count = platform_irq_count(pdev);
	if (irq_count == -EPROBE_DEFER)
		return irq_count;

	if (irq_count && irq_count != val) {
		dev_err(dev, "Interrupts not match num-chans\n");
		return -EINVAL;
	}

	if (!of_property_read_string(dev->of_node, "method", &method)) {
		if (!strcmp("hvc", method)) {
			use_hvc = true;
		} else if (!strcmp("smc", method)) {
			use_hvc = false;
		} else {
			dev_warn(dev, "invalid \"method\" property: %s\n",
				 method);

			return -EINVAL;
		}
	}

	mbox = devm_kzalloc(dev, sizeof(*mbox), GFP_KERNEL);
	if (!mbox)
		return -ENOMEM;

	mbox->num_chans = val;
	mbox->chans = devm_kcalloc(dev, mbox->num_chans, sizeof(*mbox->chans),
				   GFP_KERNEL);
	if (!mbox->chans)
		return -ENOMEM;

	chan_data = devm_kcalloc(dev, mbox->num_chans, sizeof(*chan_data),
				 GFP_KERNEL);
	if (!chan_data)
		return -ENOMEM;

	for (i = 0; i < mbox->num_chans; i++) {
		u32 function_id;

		ret = of_property_read_u32_index(dev->of_node,
						 "arm,func-ids", i,
						 &function_id);
		if (ret)
			chan_data[i].function_id = UINT_MAX;

		else
			chan_data[i].function_id = function_id;

		if (use_hvc)
			chan_data[i].flags |= ARM_SMC_MBOX_USE_HVC;
		mbox->chans[i].con_priv = &chan_data[i];

		if (irq_count) {
			chan_data[i].irq = platform_get_irq(pdev, i);
			if (chan_data[i].irq < 0)
				return chan_data[i].irq;

			ret = devm_request_irq(&pdev->dev, chan_data[i].irq,
					       chan_irq_handler, 0, pdev->name,
					       &mbox->chans[i]);
			if (ret)
				return ret;
		}
	}

	mbox->txdone_poll = false;
	mbox->txdone_irq = false;
	mbox->ops = &arm_smc_mbox_chan_ops;
	mbox->dev = dev;

	ret = mbox_controller_register(mbox);
	if (ret)
		return ret;

	platform_set_drvdata(pdev, mbox);
	dev_info(dev, "ARM SMC mailbox enabled with %d chan%s.\n",
		 mbox->num_chans, mbox->num_chans == 1 ? "" : "s");

	return ret;
}

static int arm_smc_mbox_remove(struct platform_device *pdev)
{
	struct mbox_controller *mbox = platform_get_drvdata(pdev);

	mbox_controller_unregister(mbox);
	return 0;
}

static const struct of_device_id arm_smc_mbox_of_match[] = {
	{ .compatible = "arm,smc-mbox", },
	{},
};
MODULE_DEVICE_TABLE(of, arm_smc_mbox_of_match);

static struct platform_driver arm_smc_mbox_driver = {
	.driver = {
		.name = "arm-smc-mbox",
		.of_match_table = arm_smc_mbox_of_match,
	},
	.probe		= arm_smc_mbox_probe,
	.remove		= arm_smc_mbox_remove,
};
module_platform_driver(arm_smc_mbox_driver);

MODULE_AUTHOR("Andre Przywara <andre.przywara@arm.com>");
MODULE_DESCRIPTION("Generic ARM smc mailbox driver");
MODULE_LICENSE("GPL v2");
