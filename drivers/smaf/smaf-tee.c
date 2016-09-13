/*
 * smaf-optee.c
 *
 * Copyright (C) Linaro SA 2015
 * Author: Benjamin Gaignard <benjamin.gaignard@linaro.org> for Linaro.
 * License terms:  GNU General Public License (GPL), version 2
 */
#include <linux/dma-mapping.h>
#include <linux/debugfs.h>
#include <linux/module.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/smaf-secure.h>

#include <linux/tee_drv.h>

/* Those define are copied from ta_sdp.h */
#define TA_SDP_UUID { 0xb9aa5f00, 0xd229, 0x11e4, \
		{ 0x92, 0x5c, 0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b} }

#define TA_SDP_CREATE_REGION    0
#define TA_SDP_DESTROY_REGION   1
#define TA_SDP_UPDATE_REGION    2
#define TA_SDP_DUMP_STATUS	3

struct teec_uuid {
	uint32_t timeLow;
	uint16_t timeMid;
	uint16_t timeHiAndVersion;
	uint8_t clockSeqAndNode[8];
};

struct smaf_optee_device {
	struct list_head clients_head;
	/* mutex to serialize list manipulation */
	struct mutex lock;
	struct dentry *debug_root;
	struct tee_context *ctx;
	uint32_t session;
	bool session_initialized;
};

struct sdp_client {
	struct list_head client_node;
	struct list_head regions_head;
	struct mutex lock;
	const char *name;
};

struct sdp_region {
	struct list_head region_node;
	dma_addr_t addr;
	size_t size;
	int id;
};

static struct smaf_optee_device so_dev;

/* trusted application call */

/**
 * sdp_ta_create_region -create a region with a given address and size
 *
 * in case of success return a region id (>=0) else -EINVAL
 */
static int sdp_ta_region_create(dma_addr_t addr, size_t size)
{
	struct tee_ioctl_invoke_arg arg;
	struct tee_param param[3];
	int rc;

	memset(&arg, 0, sizeof(arg));
	arg.func = TA_SDP_CREATE_REGION;
	arg.session = so_dev.session;
	arg.num_params = 3;

	memset(&param[0], 0, sizeof(param));
	param[0].attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT;
#ifdef CONFIG_ARCH_DMA_ADDR_T_64BIT
#error "not implemented"
#else
	param[0].u.value.b = addr;
#endif
	param[1].attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT;
	param[1].u.value.a = size;
	param[2].attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_OUTPUT;

	rc = tee_client_invoke_func(so_dev.ctx, &arg, &param[0]);
	if (rc || arg.ret)
		return rc ? rc : -EIO;		// FIXME: find better errno

	return (int)param[2].u.value.a;
}

static int sdp_ta_region_destroy(struct sdp_region *region)
{
	struct tee_ioctl_invoke_arg arg;
	struct tee_param param;
	int rc;

	memset(&arg, 0, sizeof(arg));
	arg.func = TA_SDP_DESTROY_REGION;
	arg.session = so_dev.session;
	arg.num_params = 1;

	memset(&param, 0, sizeof(param));
	param.attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT;
	param.u.value.a = region->id;

	rc = tee_client_invoke_func(so_dev.ctx, &arg, &param);
	if (rc || arg.ret)
		return rc ? rc : -EIO;		// FIXME: find better errno

	return 0;
}

#ifndef CONFIG_SMAF_RUNTIME_DEVICE
static int sdp_ta_region_update(struct sdp_region *region, struct device *dev,
				enum dma_data_direction dir, bool add)
{
	return -EINVAL;			// FIXME: errno
}
#else
static int sdp_ta_region_update(struct sdp_region *region, struct device *dev,
				enum dma_data_direction dir, bool add)
{
	struct tee_ioctl_invoke_arg arg;
	struct tee_param param[3];
	struct tee_shm *shm;
	void *shm_va;
	size_t len;
	char *id;
	const char id_cpu[] = "cpu";
	int rc;

	id = (char *)dev_name(dev);
	if (!id)
		id = (char *)id_cpu;

	len = strlen(id) + 1;
	shm = tee_shm_alloc(so_dev.ctx, len, TEE_SHM_MAPPED);
	if (!shm)
		return -ENOMEM;
	shm_va = tee_shm_get_va(shm, 0);
	if (IS_ERR(shm_va))
		return -ERESTART;
	memcpy(shm_va, id, len);

	memset(&arg, 0, sizeof(arg));
	arg.func = TA_SDP_UPDATE_REGION;
	arg.session = so_dev.session;
	arg.num_params = 3;

	memset(param, 0, sizeof(param));
	param[0].attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT;
	param[0].u.value.a = region->id;
	param[0].u.value.b = add ? 1 : 0;
	param[1].attr = TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT;
	param[1].u.memref.shm = shm;
	param[1].u.memref.size = len;
	param[2].attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT;
	param[2].u.value.a = dir;

	rc = tee_client_invoke_func(so_dev.ctx, &arg, &param[0]);
	if (rc || arg.ret)
		return rc ? rc : -EIO;		// FIXME: find better errno

	return 0;
}
#endif

static int smaf_optee_match(struct tee_ioctl_version_data *data,
				const void *vers)
{
	return !!1;
}

static int sdp_init_session(void)
{
	struct tee_ioctl_open_session_arg arg;
	struct teec_uuid uuid = TA_SDP_UUID;
	struct tee_ioctl_version_data vers = {
		.impl_id = TEE_OPTEE_CAP_TZ,
		.impl_caps = TEE_IMPL_ID_OPTEE,
		.gen_caps = TEE_GEN_CAP_GP,
	};
	int rc;

	if (so_dev.session_initialized)
		return 0;

	so_dev.ctx = tee_client_open_context(NULL, smaf_optee_match,
					     NULL, &vers);
	if (IS_ERR(so_dev.ctx))
		return -EINVAL;					// FIXME: errno

	memset(&arg, 0, sizeof(arg));
	memcpy(&arg.uuid, &uuid, sizeof(uuid));
	arg.clnt_login = TEE_IOCTL_LOGIN_PUBLIC;

	rc = tee_client_open_session(so_dev.ctx, &arg, NULL);
	if (!rc && arg.ret)
		rc = -EIO;					// FIXME: find better errno
	if (rc) {
		tee_client_close_context(so_dev.ctx);
		return rc;
	}

	so_dev.session = arg.session;
	so_dev.session_initialized = true;

	return 0;
}

static void sdp_destroy_session(void)
{
	if (!so_dev.session_initialized)
		return;

	tee_client_close_session(so_dev.ctx, so_dev.session);
	tee_client_close_context(so_dev.ctx);

	so_dev.session_initialized = false;
}

/* internal functions */
static int sdp_region_add(struct sdp_region *region, struct device *dev,
			  enum dma_data_direction dir)
{
	return sdp_ta_region_update(region, dev, dir, true);
}

static int sdp_region_remove(struct sdp_region *region, struct device *dev,
			     enum dma_data_direction dir)
{
	return sdp_ta_region_update(region, dev, dir, false);
}

static struct sdp_region *sdp_region_create(struct sdp_client *client,
					    dma_addr_t addr, size_t size)
{
	struct sdp_region *region;
	int region_id;

	/* here call TA to create the region */
	if (sdp_init_session())
		return NULL;

	region_id = sdp_ta_region_create(addr, size);
	if (region_id < 0)
		return NULL;

	region = kzalloc(sizeof(*region), GFP_KERNEL);
	if (!region)
		return NULL;

	INIT_LIST_HEAD(&region->region_node);
	region->addr = addr;
	region->size = size;
	region->id = region_id;

	mutex_lock(&client->lock);
	list_add(&region->region_node, &client->regions_head);
	mutex_unlock(&client->lock);

	return region;
}

static int sdp_region_destroy(struct sdp_client *client,
			      struct sdp_region *region)
{
	if (sdp_ta_region_destroy(region))
		return -EINVAL;

	mutex_lock(&client->lock);
	list_del(&region->region_node);
	mutex_unlock(&client->lock);

	kfree(region);
	return 0;
}

static struct sdp_region *sdp_region_find(struct sdp_client *client,
					  dma_addr_t addr, size_t size)
{
	struct sdp_region *region;

	mutex_lock(&client->lock);

	list_for_each_entry(region, &client->regions_head, region_node) {
		if (region->addr == addr && region->size == size) {
			mutex_unlock(&client->lock);
			return region;
		}
	}

	mutex_unlock(&client->lock);
	return NULL;
}

static int sdp_grant_access(struct sdp_client *client, struct device *dev,
		     dma_addr_t addr, size_t size, enum dma_data_direction dir)
{
	struct sdp_region *region;

	region = sdp_region_find(client, addr, size);

	if (!region)
		region = sdp_region_create(client, addr, size);

	if (!region)
		return -EINVAL;

	return sdp_region_add(region, dev, dir);

}

static int sdp_revoke_access(struct sdp_client *client, struct device *dev,
		     dma_addr_t addr, size_t size, enum dma_data_direction dir)
{
	struct sdp_region *region;

	region = sdp_region_find(client, addr, size);

	if (!region)
		return -EINVAL;

	return sdp_region_remove(region, dev, dir);

}

static void *smaf_optee_create_context(void)
{
	struct sdp_client *client;

	client = kzalloc(sizeof(*client), GFP_KERNEL);
	if (!client)
		return NULL;

	mutex_init(&client->lock);
	INIT_LIST_HEAD(&client->client_node);
	INIT_LIST_HEAD(&client->regions_head);

	client->name = kstrdup("smaf-optee", GFP_KERNEL);

	mutex_lock(&so_dev.lock);
	list_add(&client->client_node, &so_dev.clients_head);
	mutex_unlock(&so_dev.lock);

	return client;

}

static int smaf_optee_destroy_context(void *ctx)
{
	struct sdp_client *client = ctx;
	struct sdp_region *region, *tmp;

	if (!client)
		return -EINVAL;

	list_for_each_entry_safe(region, tmp, &client->regions_head, region_node) {
		sdp_region_destroy(client, region);
	}

	mutex_lock(&so_dev.lock);
	list_del(&client->client_node);
	mutex_unlock(&so_dev.lock);

	kfree(client->name);
	kfree(client);
	return 0;

}

static bool smaf_optee_grant_access(void *ctx,
				    struct device *dev,
				    size_t addr, size_t size,
				    enum dma_data_direction direction)
{
	struct sdp_client *client = ctx;

	return !sdp_grant_access(client, dev, addr, size, direction);
}

static void smaf_optee_revoke_access(void *ctx,
				     struct device *dev,
				     size_t addr, size_t size,
				     enum dma_data_direction direction)
{
	struct sdp_client *client = ctx;
	sdp_revoke_access(client, dev, addr, size, direction);
}

static struct smaf_secure smaf_optee_sec = {
	.create_ctx = smaf_optee_create_context,
	.destroy_ctx = smaf_optee_destroy_context,
	.grant_access = smaf_optee_grant_access,
	.revoke_access = smaf_optee_revoke_access,
};

/* debugfs helpers */
#define MAX_DUMP_SIZE 2048
static int smaf_optee_ta_dump_status(struct seq_file *s, void *unused)
{
	struct tee_ioctl_invoke_arg arg;
	struct tee_param param;
	struct tee_shm *shm;
	char *dump;
	int rc;

	if (sdp_init_session())
		return 0;

	shm = tee_shm_alloc(so_dev.ctx, MAX_DUMP_SIZE, TEE_SHM_MAPPED);
	if (!shm)
		return -ENOMEM;
	dump = tee_shm_get_va(shm, 0);
	if (IS_ERR(dump))
		return -ERESTART;
	memset(dump, 0, MAX_DUMP_SIZE);

	memset(&arg, 0, sizeof(arg));
	arg.func = TA_SDP_DUMP_STATUS;
	arg.session = so_dev.session;
	arg.num_params = 1;

	memset(&param, 0, sizeof(param));
	param.attr = TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT;
	param.u.memref.shm = shm;
	param.u.memref.size = MAX_DUMP_SIZE - 1;

	rc = tee_client_invoke_func(so_dev.ctx, &arg, &param);
	if (!rc && arg.ret)
		rc = -EIO;

	if (!rc)
		seq_printf(s, "%s", dump);

	tee_shm_free(shm);
	return rc;
}

static int smaf_optee_debug_open(struct inode *inode, struct file *file)
{
	return single_open(file, smaf_optee_ta_dump_status, inode->i_private);
}

static const struct file_operations so_debug_fops = {
	.open    = smaf_optee_debug_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
};

static int __init smaf_optee_init(void)
{
	mutex_init(&so_dev.lock);
	INIT_LIST_HEAD(&so_dev.clients_head);

	so_dev.debug_root = debugfs_create_dir("smaf-optee", NULL);
	debugfs_create_file("dump", S_IRUGO, so_dev.debug_root,
			    &so_dev, &so_debug_fops);

	so_dev.session_initialized = false;

	smaf_register_secure(&smaf_optee_sec);

	return 0;
}
module_init(smaf_optee_init);

static void __exit smaf_optee_exit(void)
{
	smaf_unregister_secure(&smaf_optee_sec);
	sdp_destroy_session();
}
module_exit(smaf_optee_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SMAF for OP-TEE");
MODULE_AUTHOR("Benjamin Gaignard <benjamin.gaignard@linaro.org>");

