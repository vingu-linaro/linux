// SPDX-License-Identifier: GPL-2.0
/*
 * ION Memory Allocator unmapped heap helper
 *
 * Copyright (C) 2015-2016 Texas Instruments Incorporated - http://www.ti.com/
 *	Andrew F. Davis <afd@ti.com>
 *
 * ION "unmapped" heaps are physical memory heaps not by default mapped into
 * a virtual address space. The buffer owner can explicitly request kernel
 * space mappings but the underlying memory may still not be accessible for
 * various reasons, such as firewalls.
 */

#include <linux/err.h>
#include <linux/genalloc.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>

#include "ion.h"

#define ION_UNMAPPED_ALLOCATE_FAIL -1

struct ion_unmapped_heap {
	struct ion_heap heap;
	struct gen_pool *pool;
};

static phys_addr_t ion_unmapped_allocate(struct ion_heap *heap,
					 unsigned long size)
{
	struct ion_unmapped_heap *unmapped_heap =
		container_of(heap, struct ion_unmapped_heap, heap);
	unsigned long offset;

	offset = gen_pool_alloc(unmapped_heap->pool, size);
	if (!offset)
		return ION_UNMAPPED_ALLOCATE_FAIL;

	return offset;
}

static void ion_unmapped_free(struct ion_heap *heap, phys_addr_t addr,
			      unsigned long size)
{
	struct ion_unmapped_heap *unmapped_heap =
		container_of(heap, struct ion_unmapped_heap, heap);

	gen_pool_free(unmapped_heap->pool, addr, size);
}

static int ion_unmapped_heap_allocate(struct ion_heap *heap,
				      struct ion_buffer *buffer,
				      unsigned long size,
				      unsigned long flags)
{
	struct sg_table *table;
	phys_addr_t paddr;
	int ret;

	table = kmalloc(sizeof(*table), GFP_KERNEL);
	if (!table)
		return -ENOMEM;
	ret = sg_alloc_table(table, 1, GFP_KERNEL);
	if (ret)
		goto err_free;

	paddr = ion_unmapped_allocate(heap, size);
	if (paddr == ION_UNMAPPED_ALLOCATE_FAIL) {
		ret = -ENOMEM;
		goto err_free_table;
	}

	sg_set_page(table->sgl, pfn_to_page(PFN_DOWN(paddr)), size, 0);
	buffer->sg_table = table;

	return 0;

err_free_table:
	sg_free_table(table);
err_free:
	kfree(table);
	return ret;
}

static void ion_unmapped_heap_free(struct ion_buffer *buffer)
{
	struct ion_heap *heap = buffer->heap;
	struct sg_table *table = buffer->sg_table;
	struct page *page = sg_page(table->sgl);
	phys_addr_t paddr = PFN_PHYS(page_to_pfn(page));

	ion_unmapped_free(heap, paddr, buffer->size);
	sg_free_table(buffer->sg_table);
	kfree(buffer->sg_table);
}

static struct ion_heap_ops unmapped_heap_ops = {
	.allocate = ion_unmapped_heap_allocate,
	.free = ion_unmapped_heap_free,
	/* no .map_user, user mapping of unmapped heaps not allowed */
	.map_kernel = ion_heap_map_kernel,
	.unmap_kernel = ion_heap_unmap_kernel,
};

struct ion_heap *ion_unmapped_heap_create(phys_addr_t base, size_t size)
{
	struct ion_unmapped_heap *unmapped_heap;

	unmapped_heap = kzalloc(sizeof(*unmapped_heap), GFP_KERNEL);
	if (!unmapped_heap)
		return ERR_PTR(-ENOMEM);

	unmapped_heap->pool = gen_pool_create(PAGE_SHIFT, -1);
	if (!unmapped_heap->pool) {
		kfree(unmapped_heap);
		return ERR_PTR(-ENOMEM);
	}
	gen_pool_add(unmapped_heap->pool, base, size, -1);
	unmapped_heap->heap.ops = &unmapped_heap_ops;
	unmapped_heap->heap.type = ION_HEAP_TYPE_UNMAPPED;

	return &unmapped_heap->heap;
}

#if defined(CONFIG_ION_DUMMY_UNMAPPED_HEAP) && CONFIG_ION_DUMMY_UNMAPPED_SIZE
#define DUMMY_UNAMMPED_HEAP_NAME	"unmapped_contiguous"

static int ion_add_dummy_unmapped_heaps(void)
{
        struct ion_heap *heap;
	const char name[] = DUMMY_UNAMMPED_HEAP_NAME;
	struct ion_platform_heap pheap = {
		.type	= ION_HEAP_TYPE_UNMAPPED,
		.base   = CONFIG_ION_DUMMY_UNMAPPED_BASE,
		.size   = CONFIG_ION_DUMMY_UNMAPPED_SIZE,
	};

	heap = ion_unmapped_heap_create(CONFIG_ION_DUMMY_UNMAPPED_BASE,
					CONFIG_ION_DUMMY_UNMAPPED_SIZE);
	if (IS_ERR(heap))
		return PTR_ERR(heap);

	heap->name = kzalloc(sizeof(name), GFP_KERNEL);
	if (IS_ERR(heap->name)) {
		kfree(heap);
		return PTR_ERR(heap->name);
	}
	memcpy((char *)heap->name, name, sizeof(name));

	ion_device_add_heap(heap);
        return 0;
}
device_initcall(ion_add_dummy_unmapped_heaps);
#endif
