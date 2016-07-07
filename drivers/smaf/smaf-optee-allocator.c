/*
 * Copyright (c) 2016, Linaro Limited
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

#include <linux/dma-mapping.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/smaf-allocator.h>
#include <uapi/linux/tee.h>
#include <linux/tee_drv.h>

struct smaf_optee_allocator_buffer_info {
	void *dev;
	size_t size;
	void *vaddr;
	dma_addr_t paddr;
};

static struct {
	struct tee_context *ctx;
	__u32 session;
} optee_config;

/**
 * smaf_optee_allocator_match - return true if at least one device has been
 * found
 */
static bool smaf_optee_allocator_match(struct dma_buf *dmabuf)
{
	return !!1;
}

static void smaf_optee_allocator_release(struct dma_buf *dmabuf)
{
	struct smaf_optee_allocator_buffer_info *info = dmabuf->priv;
	struct tee_ioctl_invoke_arg arg;
	struct tee_param params[4];
	DEFINE_DMA_ATTRS(attrs);

	dma_set_attr(DMA_ATTR_WRITE_COMBINE, &attrs);

	memset(&arg, 0, sizeof(arg));
	arg.func = 1;	/* SMAF_OPTEE_ALLOCATOR_CMD_FREE */
	arg.session = optee_config.session;
	arg.num_params = 4;

	/*
	 * Set the parameters of the command
	 * - 1st parameter is the physical memory to free (input)
	 * - 2nd, 3rd and 4th parameters are none
	 */
	memset(params, 0, sizeof(params));
	params[0].attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT;
	params[0].u.value.a = info->paddr;
	params[1].attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;
	params[2].attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;
	params[3].attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;
	tee_client_invoke_func(optee_config.ctx, &arg, params);
	kfree(info);
}

static struct sg_table *smaf_optee_allocator_map(struct dma_buf_attachment *attachment,
				     enum dma_data_direction direction)
{
	struct smaf_optee_allocator_buffer_info *info = attachment->dmabuf->priv;
	struct sg_table *sgt;
	int ret;

	sgt = kzalloc(sizeof(*sgt), GFP_KERNEL);
	if (!sgt)
		return NULL;

	ret = dma_get_sgtable(info->dev, sgt, info->vaddr,
			      info->paddr, info->size);
	if (ret < 0)
		goto out;

	sg_dma_address(sgt->sgl) = info->paddr;
	return sgt;

out:
	kfree(sgt);
	return NULL;
}

static void smaf_optee_allocator_unmap(struct dma_buf_attachment *attachment,
				       struct sg_table *sgt,
				       enum dma_data_direction direction)
{
	/* do nothing */
}

static int smaf_optee_allocator_mmap(struct dma_buf *dmabuf, struct vm_area_struct *vma)
{
	struct smaf_optee_allocator_buffer_info *info = dmabuf->priv;
	size_t size = vma->vm_end - vma->vm_start;

	vma->vm_flags |= VM_IO | VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP;
	return remap_pfn_range(vma, vma->vm_start,
			       info->paddr >> PAGE_SHIFT,
			       size, vma->vm_page_prot);
}

static void *smaf_optee_allocator_vmap(struct dma_buf *dmabuf)
{
	struct smaf_optee_allocator_buffer_info *info = dmabuf->priv;

	return info->vaddr;
}

static void *smaf_kmap_atomic(struct dma_buf *dmabuf, unsigned long offset)
{
	struct smaf_optee_allocator_buffer_info *info = dmabuf->priv;

	return (void *)info->vaddr + offset;
}

static struct dma_buf_ops smaf_optee_allocator_ops = {
	.map_dma_buf = smaf_optee_allocator_map,
	.unmap_dma_buf = smaf_optee_allocator_unmap,
	.mmap = smaf_optee_allocator_mmap,
	.release = smaf_optee_allocator_release,
	.kmap_atomic = smaf_kmap_atomic,
	.kmap = smaf_kmap_atomic,
	.vmap = smaf_optee_allocator_vmap,
};

static int smaf_optee_match(struct tee_ioctl_version_data *data,
				const void *vers)
{
	return !!1;
}

static struct dma_buf *smaf_optee_allocator_allocate(struct dma_buf *dmabuf,
					 size_t length, unsigned int flags)
{
	struct dma_buf_attachment *attach_obj;
	struct smaf_optee_allocator_buffer_info *info;
	struct dma_buf *optee_allocator_dmabuf;
	struct tee_ioctl_invoke_arg arg;
	struct tee_param params[4];
	int ret;
	phys_addr_t paddr;
	size_t size;
	phys_addr_t begin;
	phys_addr_t end;

	DEFINE_DMA_BUF_EXPORT_INFO(export);
	DEFINE_DMA_ATTRS(attrs);
	dma_set_attr(DMA_ATTR_WRITE_COMBINE, &attrs);

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info)
		return NULL;

	memset(&arg, 0, sizeof(arg));
	arg.func = 0;	/* SMAF_OPTEE_ALLOCATOR_CMD_ALLOCATE */
	arg.session = optee_config.session;
	arg.num_params = 4;

	/*
	 * Set the parameters of the command
	 * - 1st parameter is the size to allocate (input)
	 * - 2nd parameter is the physical memory (output)
	 * - 3rd and 4th parameters are none
	 */
	memset(params, 0, sizeof(params));
	params[0].attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT;
	params[0].u.value.a = length;
	params[1].attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_OUTPUT;
	params[2].attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;
	params[3].attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;
	ret = tee_client_invoke_func(optee_config.ctx,
			&arg,
			params);

	if (ret)
		goto error;
	if (arg.ret) {
		ret = -EINVAL;
		goto error;
	}

	info->paddr = params[1].u.value.a;
	info->size = length;
	if (!info->paddr) {
		ret = -ENOMEM;
		goto error;
	}

	begin = roundup(info->paddr, PAGE_SIZE);
	end = rounddown(info->paddr + info->size, PAGE_SIZE);
	paddr = begin;
	size = end - begin;

	info->vaddr = ioremap_cache(paddr, size);
	info->dev = optee_config.ctx;

	export.ops = &smaf_optee_allocator_ops;
	export.size = info->size;
	export.flags = flags;
	export.priv = info;

	optee_allocator_dmabuf = dma_buf_export(&export);
	if (IS_ERR(optee_allocator_dmabuf))
		goto error;

	list_for_each_entry(attach_obj, &dmabuf->attachments, node) {
		dma_buf_attach(optee_allocator_dmabuf, attach_obj->dev);
	}

	return optee_allocator_dmabuf;

error:
	kfree(info);
	return NULL;
}

static struct smaf_allocator smaf_optee_allocator = {
	.match = smaf_optee_allocator_match,
	.allocate = smaf_optee_allocator_allocate,
	.name = "smaf-optee-allocator",
	.ranking = 1,
};

static int __init smaf_optee_allocator_init(void)
{
	int ret;
	struct tee_ioctl_version_data vers = {
		.impl_id = TEE_OPTEE_CAP_TZ,
		.impl_caps = TEE_IMPL_ID_OPTEE,
		.gen_caps = TEE_GEN_CAP_GP,
	};
	const __u8 uuid[TEE_IOCTL_UUID_LEN] = {
		0x47, 0x07, 0x2c, 0x63, 0x30, 0xcf, 0x3a, 0x44,
		0x8f, 0x16, 0x0f, 0xcb, 0x01, 0xf1, 0xf5, 0x9a};
	struct tee_ioctl_open_session_arg arg;

	optee_config.ctx = tee_client_open_context(NULL,
						   smaf_optee_match,
						   NULL, &vers);
	if (IS_ERR(optee_config.ctx))
		return PTR_ERR(optee_config.ctx);

	memset(&arg, 0, sizeof(arg));
	memcpy(arg.uuid, uuid, TEE_IOCTL_UUID_LEN);
	ret = tee_client_open_session(optee_config.ctx,
			&arg, NULL);
	if (ret)
		goto error;
	if (arg.ret) {
		ret = -EINVAL;
		goto error;
	}
	optee_config.session = arg.session;

	INIT_LIST_HEAD(&smaf_optee_allocator.list_node);
	return smaf_register_allocator(&smaf_optee_allocator);

error:
	if (optee_config.session) {
		tee_client_close_session(optee_config.ctx,
					 optee_config.session);
		optee_config.session = 0;
	}

	if (optee_config.ctx) {
		tee_client_close_context(optee_config.ctx);
		optee_config.ctx = 0;
	}
	return ret;
}
module_init(smaf_optee_allocator_init);

static void __exit smaf_optee_allocator_deinit(void)
{
	if (optee_config.session) {
		tee_client_close_session(optee_config.ctx,
					 optee_config.session);
		optee_config.session = 0;
	}

	if (optee_config.ctx) {
		tee_client_close_context(optee_config.ctx);
		optee_config.ctx = 0;
	}
	smaf_unregister_allocator(&smaf_optee_allocator);
}
module_exit(smaf_optee_allocator_deinit);

MODULE_DESCRIPTION("SMAF OPTEE Allocator module");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Pascal Brand <pascal.brand@linaro.org>");

