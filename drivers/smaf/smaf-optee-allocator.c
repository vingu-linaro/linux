/*
 * smaf-optee-allocator.c
 *
 * Copyright (C) Linaro SA 2016
 * License terms:  GNU General Public License (GPL), version 2
 */

#include <linux/dma-mapping.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/smaf-allocator.h>
#include <linux/tee_drv.h>
#include <uapi/linux/tee.h>

/* Those define are copied from ta_sdp.h (to get from dt?) */
#define TA_SDP_UUID { 0xb9aa5f00, 0xd229, 0x11e4, \
		{ 0x92, 0x5c, 0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b} }

#define TA_SDP_ALLOCATE_BUFFER		4
#define TA_SDP_FREE_BUFFER		5

struct teec_uuid {
	uint32_t timeLow;
	uint16_t timeMid;
	uint16_t timeHiAndVersion;
	uint8_t clockSeqAndNode[8];
};

struct tee_secbuf_info {
	struct mutex mutex;
	size_t size;
	void *vaddr;
	size_t kmaped;
	dma_addr_t paddr;
	struct sg_table sgt;
};

static struct {
	struct tee_context *ctx;
	uint32_t session;
} optee_config;

static struct sg_table *tee_map_dmabuf(struct dma_buf_attachment *attachment,
					enum dma_data_direction direction)
{
	struct tee_secbuf_info *info = attachment->dmabuf->priv;
	struct sg_table *sgt;
	int rc;


	sgt = kzalloc(sizeof(*sgt), GFP_KERNEL);
	if (!sgt)
		return NULL;

	rc = sg_alloc_table(sgt, 1, GFP_KERNEL);
	if (rc) {
		kfree(sgt);
		return NULL;
	}

	sg_set_page(sgt->sgl, 0, info->size, 0);
	sg_dma_address(sgt->sgl) = info->paddr;
	sg_dma_len(sgt->sgl) = info->size;

	return sgt;
}

static void tee_unmap_dmabuf(struct dma_buf_attachment *attachment,
				       struct sg_table *sgt,
				       enum dma_data_direction direction)
{
	/* do nothing */
}

static int tee_mmap(struct dma_buf *dmabuf, struct vm_area_struct *vma)
{
	struct tee_secbuf_info *info = dmabuf->priv;
	size_t size = vma->vm_end - vma->vm_start;

	vma->vm_flags |= VM_IO | VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP;
	return remap_pfn_range(vma, vma->vm_start,
			       info->paddr >> PAGE_SHIFT,
			       size, vma->vm_page_prot);
}

static void kmap_incr(struct tee_secbuf_info *info)
{
	mutex_lock(&info->mutex);
	if (!info->vaddr)
		info->vaddr = ioremap_cache(info->paddr, info->size);
	if (info->vaddr)
		info->kmaped++;
	mutex_unlock(&info->mutex);
}

static void kmap_decr(struct tee_secbuf_info *info)
{
	if (!info->vaddr)
		return;

	mutex_lock(&info->mutex);
	info->kmaped--;
	if (!info->kmaped) {
		iounmap(info->vaddr);
		info->vaddr = NULL;
	}
	mutex_unlock(&info->mutex);
}

static void *tee_vmap(struct dma_buf *dmabuf)
{
	struct tee_secbuf_info *info = dmabuf->priv;

	mutex_lock(&info->mutex);
	info->kmaped++;
	mutex_unlock(&info->mutex);

	return info->vaddr;
}

static void tee_vunmap(struct dma_buf *dmabuf, void *vaddr)
{
	kmap_decr((struct tee_secbuf_info *)dmabuf->priv);
}

static void *tee_kmap(struct dma_buf *dmabuf, unsigned long off)
{
	struct tee_secbuf_info *info = dmabuf->priv;

	kmap_incr(info);
	return (void *)info->vaddr + off;
}

static void *tee_kmap_atomic(struct dma_buf *dmabuf, unsigned long off)
{
	struct tee_secbuf_info *info = dmabuf->priv;

	if (!info->vaddr)
		return NULL;

	mutex_lock(&info->mutex);
	info->kmaped++;
	mutex_unlock(&info->mutex);

	return (void *)info->vaddr + off;
}

static void  tee_kunmap(struct dma_buf *dmabuf, unsigned long off, void *vaddr)
{
	kmap_decr((struct tee_secbuf_info *)dmabuf->priv);
}

static void tee_release(struct dma_buf *dmabuf)
{
	struct tee_secbuf_info *info = dmabuf->priv;
	struct tee_ioctl_invoke_arg arg;
	struct tee_param param;

	if(!optee_config.session)
		return;

	memset(&arg, 0, sizeof(arg));
	arg.func = TA_SDP_FREE_BUFFER;
	arg.session = optee_config.session;
	arg.num_params = 1;

	memset(&param, 0, sizeof(param));
	param.attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT;
	param.u.value.a = info->paddr;
	tee_client_invoke_func(optee_config.ctx, &arg, &param);

	WARN_ON(info->kmaped);
	mutex_destroy(&info->mutex);
	kfree(info);
}

static struct dma_buf_ops smaf_optee_allocator_ops = {
	.map_dma_buf = tee_map_dmabuf,
	.unmap_dma_buf = tee_unmap_dmabuf,
	.mmap = tee_mmap,
	.release = tee_release,
	.kmap = tee_kmap,
	.kmap_atomic = tee_kmap_atomic,
	.kunmap = tee_kunmap,
	.vmap = tee_vmap,
	.vunmap = tee_vunmap,
};

static int smaf_optee_match(struct tee_ioctl_version_data *data,
				const void *vers)
{
	return !!1;
}

static int tee_connect(void)
{
	int rc;
	struct tee_ioctl_version_data vers = {
		.impl_id = TEE_OPTEE_CAP_TZ,
		.impl_caps = TEE_IMPL_ID_OPTEE,
		.gen_caps = TEE_GEN_CAP_GP,
	};
	const struct teec_uuid uuid = TA_SDP_UUID;
	struct tee_ioctl_open_session_arg arg;

	optee_config.ctx = tee_client_open_context(NULL,
						   smaf_optee_match,
						   NULL, &vers);
	if (IS_ERR(optee_config.ctx))
		return PTR_ERR(optee_config.ctx);

	memset(&arg, 0, sizeof(arg));
	memcpy(arg.uuid, &uuid, TEE_IOCTL_UUID_LEN);
	rc = tee_client_open_session(optee_config.ctx,
			&arg, NULL);
	if (rc)
		goto error;
	if (arg.ret) {
		rc = -EINVAL;
		goto error;
	}

	optee_config.session = arg.session;
	return 0;

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
	return rc;
}

static struct dma_buf *tee_alloc(struct dma_buf *dmabuf, size_t length)
{
	struct dma_buf_attachment *attach_obj;
	struct tee_secbuf_info *info;
	struct dma_buf *tee_dmabuf;
	struct tee_ioctl_invoke_arg arg;
	struct tee_param params;
	int rc;
	DEFINE_DMA_BUF_EXPORT_INFO(export);

	if (!optee_config.session && tee_connect())
		return ERR_PTR(-EIO);

	memset(&arg, 0, sizeof(arg));
	arg.func = TA_SDP_ALLOCATE_BUFFER;
	arg.session = optee_config.session;
	arg.num_params = 1;

	memset(&params, 0, sizeof(params));
	params.attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INOUT;
	params.u.value.b = length;

	rc = tee_client_invoke_func(optee_config.ctx, &arg, &params);
	if (rc)
		return ERR_PTR(rc);
	if (arg.ret)
		return ERR_PTR(-EINVAL);

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info)
		return ERR_PTR(-ENOMEM);

	mutex_init(&info->mutex);
	info->paddr = params.u.value.a;
	info->size = params.u.value.b;

	if ((info->paddr & (PAGE_SIZE - 1)) ||
	   (info->size & (PAGE_SIZE - 1))) {
		rc = -EINVAL;
		goto error;
	}

	export.ops = &smaf_optee_allocator_ops;
	export.size = info->size;
	export.priv = info;

	tee_dmabuf = dma_buf_export(&export);
	if (IS_ERR(tee_dmabuf)) {
		rc = -EINVAL;
		goto error;
	}

	list_for_each_entry(attach_obj, &dmabuf->attachments, node)
		dma_buf_attach(tee_dmabuf, attach_obj->dev);

	return tee_dmabuf;

error:
	if (info)
		mutex_destroy(&info->mutex);
	kfree(info);
	return ERR_PTR(rc);
}

static bool tee_allocator_match(struct dma_buf *dmabuf)
{
	return !!1;
}

static struct smaf_allocator smaf_optee_allocator = {
	.match = tee_allocator_match,
	.allocate = tee_alloc,
	.name = "smaf-optee",
	.ranking = 1,
};

static int __init tee_allocator_init(void)
{
	INIT_LIST_HEAD(&smaf_optee_allocator.list_node);

	return smaf_register_allocator(&smaf_optee_allocator);
}
module_init(tee_allocator_init);

static void __exit tee_allocator_deinit(void)
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
module_exit(tee_allocator_deinit);

MODULE_DESCRIPTION("SMAF TEE Allocator module");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Pascal Brand <pascal.brand@linaro.org>");

