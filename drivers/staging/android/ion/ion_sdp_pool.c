/*
 * drivers/gpu/ion/ion_sdp_pool.c
 *
 * Copyright (C) 2013 Linaro, Inc
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/err.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/bootmem.h>
#include <linux/memblock.h>
#include <linux/sizes.h>
#include <linux/io.h>
#include "ion.h"
#include "ion_priv.h"

/*
 * this is a dump of the dummy drivers.
 * Currently provides "carveout" typed ion heaps,
 * for physical location hardcoded (TODO: get from device tree)
 */

/* aligned with reserved area from bootloader (qemu: 31MB, below TEE memory) */
#define CFG_SDP_POOL_BASE	0x7C000000
#define CFG_SDP_POOL_SIZE	0x01F00000

static struct ion_device *idev;
static struct ion_heap **heaps;

static struct ion_platform_heap sdp_heaps[] = {
		{
			.id	= ION_HEAP_TYPE_SYSTEM_CONTIG,
			.type	= ION_HEAP_TYPE_SYSTEM_CONTIG,
			.name	= "system contig",
		},
		{
			.id	= ION_HEAP_TYPE_CARVEOUT,
			.type	= ION_HEAP_TYPE_CARVEOUT,
			.name	= "carveout",
			.base	= CFG_SDP_POOL_BASE,
			.size	= CFG_SDP_POOL_SIZE / 2,
		},
		{
			.id	= ION_HEAP_TYPE_SECURE,
			.type	= ION_HEAP_TYPE_SECURE,
			.name	= "secure",
			.base	= CFG_SDP_POOL_BASE + (CFG_SDP_POOL_SIZE / 2),
			.size	= CFG_SDP_POOL_SIZE / 2,
		},
};

static struct ion_platform_data sdp_ion_pdata = {
	.nr = ARRAY_SIZE(sdp_heaps),
	.heaps = sdp_heaps,
};

static int __init ion_sdp_init(void)
{
	int i, err;

	idev = ion_device_create(NULL);
	heaps = kcalloc(sdp_ion_pdata.nr, sizeof(struct ion_heap *),
			GFP_KERNEL);
	if (!heaps)
		return -ENOMEM;

	for (i = 0; i < sdp_ion_pdata.nr; i++) {
		struct ion_platform_heap *heap_data = &sdp_ion_pdata.heaps[i];

		heaps[i] = ion_heap_create(heap_data);
		if (IS_ERR_OR_NULL(heaps[i])) {
			err = PTR_ERR(heaps[i]);
			goto err;
		}
		pr_err("sdp ion pool %s id/type %d/%d [%lx %lx]\n",
			heap_data->name, heap_data->id, heap_data->type,
			heap_data->base, heap_data->base + heap_data->size - 1);

		ion_device_add_heap(idev, heaps[i]);
	}
	return 0;
err:
	for (i = 0; i < sdp_ion_pdata.nr; ++i)
		ion_heap_destroy(heaps[i]);
	kfree(heaps);
	return err;
}
device_initcall(ion_sdp_init);

static void __exit ion_sdp_exit(void)
{
	int i;

	ion_device_destroy(idev);

	for (i = 0; i < sdp_ion_pdata.nr; i++)
		ion_heap_destroy(heaps[i]);
	kfree(heaps);
}
__exitcall(ion_sdp_exit);
