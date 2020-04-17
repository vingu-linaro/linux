// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2020, Linaro Limited
 */

#include <linux/arm-smccc.h>
#include <linux/device.h>
#include <linux/of.h>

static enum arm_smccc_conduit arm_smccc_1_0_conduit = SMCCC_CONDUIT_NONE;

/* Helpers for nice trace when called outside a device instance */
#define PRINT_INFO(dev, ...)				\
	do {						\
		if (dev)				\
			dev_info(dev, __VA_ARGS__);	\
		else					\
			pr_info(__VA_ARGS__);		\
	} while (0)

#define PRINT_WARN(dev, ...)				\
	do {						\
		if (dev)				\
			dev_warn(dev, __VA_ARGS__);	\
		else					\
			pr_warn(__VA_ARGS__);		\
	} while (0)

#define PRINT_ERROR(dev, ...)				\
	do {						\
		if (dev)				\
			dev_err(dev, __VA_ARGS__);	\
		else					\
			pr_err(__VA_ARGS__);		\
	} while (0)

static const char *conduit_str(enum arm_smccc_conduit conduit)
{
	static const char hvc_str[] = "HVC";
	static const char smc_str[] = "SMC";
	static const char unknown[] = "unknown";

	switch (conduit) {
	case SMCCC_CONDUIT_HVC:
		return hvc_str;
	case SMCCC_CONDUIT_SMC:
		return smc_str;
	default:
		return unknown;
	}
}

static int set_conduit(struct device *dev, enum arm_smccc_conduit conduit)
{
	switch (conduit) {
	case SMCCC_CONDUIT_HVC:
	case SMCCC_CONDUIT_SMC:
		break;
	default:
		return -EINVAL;
	}

	if (arm_smccc_1_0_conduit == SMCCC_CONDUIT_NONE) {
		arm_smccc_1_0_conduit = conduit;
		return 0;
	}

	if (conduit == arm_smccc_1_0_conduit)
		return 0;

	PRINT_ERROR(dev, "inconsistent conduits %u (%s) vs %u (%s)\n",
		    conduit, conduit_str(conduit),
		    arm_smccc_1_0_conduit, conduit_str(arm_smccc_1_0_conduit));

	return -EINVAL;
}

static enum arm_smccc_conduit method_to_conduit(const char *method)
{
	if (!strcmp("hvc", method))
                return SMCCC_CONDUIT_HVC;
	else if (!strcmp("smc", method))
	        return SMCCC_CONDUIT_SMC;
	else
		return SMCCC_CONDUIT_NONE;
}

static int set_conduit_from_node(struct device *dev, struct device_node *np)
{
	const char *method;

	PRINT_INFO(dev, "probing for conduit method from DT.\n");

	if (!np)
		return -EINVAL;

	if (!of_property_read_string(np, "method", &method)) {
		enum arm_smccc_conduit dev_conduit = method_to_conduit(method);

		if (dev_conduit == SMCCC_CONDUIT_NONE) {
			PRINT_WARN(dev, "invalid \"method\" property \"%s\"\n",
				   method);
			return -EINVAL;
		}

		return set_conduit(dev, dev_conduit);
	}

	if (arm_smccc_1_0_conduit != SMCCC_CONDUIT_NONE)
		return 0;

	PRINT_WARN(dev, "missing \"method\" property\n");
	return -ENXIO;
}

int devm_arm_smccc_1_0_set_conduit(struct device *dev)
{
	if (!dev || !dev->of_node)
		return -EINVAL;

	return set_conduit_from_node(dev, dev->of_node);
}
EXPORT_SYMBOL_GPL(devm_arm_smccc_1_0_set_conduit);

int of_arm_smccc_1_0_set_conduit(struct device_node *np)
{
	if (!np)
		return -EINVAL;

	return set_conduit_from_node(NULL, np);
}
EXPORT_SYMBOL_GPL(of_arm_smccc_1_0_set_conduit);

int arm_smccc_1_0_set_conduit(enum arm_smccc_conduit conduit)
{
	if (set_conduit(NULL, conduit))
		return -EINVAL;

	return 0;
}
EXPORT_SYMBOL_GPL(arm_smccc_1_0_set_conduit);

enum arm_smccc_conduit arm_smccc_1_0_get_conduit(void)
{
	return arm_smccc_1_0_conduit;
}
EXPORT_SYMBOL_GPL(arm_smccc_1_0_get_conduit);
