/*
 * Generic ION heaps creation
 *
 * Based (rather dumped) from Hisilicon Hi6220 ION Driver work.
 * Copyright (c) 2015 Hisilicon Limited.
 * Author: Chen Feng <puck.chen@hisilicon.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#define pr_fmt(fmt) "Ion: " fmt

#include <linux/err.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/of.h>
#include <linux/mm.h>
#include "ion_priv.h"
#include "ion.h"
#include "ion_of.h"

struct ion_heaps_dev {
	struct ion_heap	**heaps;
	struct ion_device *idev;
	struct ion_platform_data *data;
};

/* there can be only one ION misc device */
struct ion_device *ion_device;

#define GENERIC_PLATFORM_HEAP(name, id) PLATFORM_HEAP(name, id, id, name)

/* get any ION standard heaps defined in DT nodes */
static struct ion_of_heap ion_heaps[] = {
	GENERIC_PLATFORM_HEAP("system", ION_HEAP_TYPE_SYSTEM),
	GENERIC_PLATFORM_HEAP("system_contig", ION_HEAP_TYPE_SYSTEM_CONTIG),
	GENERIC_PLATFORM_HEAP("carveout", ION_HEAP_TYPE_CARVEOUT),
	GENERIC_PLATFORM_HEAP("chunk", ION_HEAP_TYPE_CHUNK),
	GENERIC_PLATFORM_HEAP("cma", ION_HEAP_TYPE_DMA),
	GENERIC_PLATFORM_HEAP("unmapped", ION_HEAP_TYPE_UNMAPPED),
	{}
};

static int ion_heaps_probe(struct platform_device *pdev)
{
	struct ion_heaps_dev *ipdev;
	int i;

	ipdev = devm_kzalloc(&pdev->dev, sizeof(*ipdev), GFP_KERNEL);
	if (!ipdev)
		return -ENOMEM;

pr_err("ION heap from DT\n");

	platform_set_drvdata(pdev, ipdev);

#if 1
	ipdev->idev = ion_device;
#else
	ipdev->idev = ion_device_create(NULL);
#endif
	if (IS_ERR(ipdev->idev))
		return PTR_ERR(ipdev->idev);

	ipdev->data = ion_parse_dt(pdev, ion_heaps);

	if (IS_ERR(ipdev->data))
		return PTR_ERR(ipdev->data);

pr_err("ION heap from DT: %d heaps\n", ipdev->data->nr);
	ipdev->heaps = devm_kzalloc(&pdev->dev,
				sizeof(struct ion_heap) * ipdev->data->nr,
				GFP_KERNEL);
	if (!ipdev->heaps) {
		ion_destroy_platform_data(ipdev->data);
		return -ENOMEM;
	}

	for (i = 0; i < ipdev->data->nr; i++) {

pr_err("ION heap from DT: %d/%d %x %x %s\n",
		ipdev->data->heaps[i].type,
		ipdev->data->heaps[i].id,
		(unsigned)ipdev->data->heaps[i].base,
		(unsigned)ipdev->data->heaps[i].size,
		ipdev->data->heaps[i].name);

		ipdev->heaps[i] = ion_heap_create(&ipdev->data->heaps[i]);
		if (!ipdev->heaps) {
			ion_destroy_platform_data(ipdev->data);
			return -ENOMEM;
		}
		ion_device_add_heap(ipdev->idev, ipdev->heaps[i]);
	}
	return 0;
}

static int ion_heaps_remove(struct platform_device *pdev)
{
	struct ion_heaps_dev *ipdev;
	int i;

	ipdev = platform_get_drvdata(pdev);

	for (i = 0; i < ipdev->data->nr; i++)
		ion_heap_destroy(ipdev->heaps[i]);

	ion_destroy_platform_data(ipdev->data);
	ion_device_destroy(ipdev->idev);

	return 0;
}

static const struct of_device_id ion_heaps_match[] = {
	{.compatible = "ion-heaps"},
	{},
};

static struct platform_driver ion_heaps_driver = {
	.probe = ion_heaps_probe,
	.remove = ion_heaps_remove,
	.driver = {
		.name = "ion-heaps",
		.of_match_table = ion_heaps_match,
	},
};

static int __init ion_heaps_init(void)
{
#if 1
	ion_device = ion_device_create(NULL);
	if (IS_ERR(ion_device))
		return PTR_ERR(ion_device);
#endif

	return platform_driver_register(&ion_heaps_driver);
}

subsys_initcall(ion_heaps_init);
