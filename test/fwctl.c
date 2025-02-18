// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2024-2025 Intel Corporation. All rights reserved.
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <endian.h>
#include <stdint.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <cxl/libcxl.h>
#include <cxl/features.h>
#include <fwctl/fwctl.h>
#include <fwctl/cxl.h>
#include <linux/uuid.h>
#include <uuid/uuid.h>
#include <util/bitmap.h>

static const char provider[] = "cxl_test";

UUID_DEFINE(test_uuid,
	    0xff, 0xff, 0xff, 0xff,
	    0xff, 0xff,
	    0xff, 0xff,
	    0xff, 0xff,
	    0xff, 0xff, 0xff, 0xff, 0xff, 0xff
);

#define CXL_MBOX_OPCODE_GET_SUPPORTED_FEATURES	0x0500
#define CXL_MBOX_OPCODE_GET_FEATURE		0x0501
#define CXL_MBOX_OPCODE_SET_FEATURE		0x0502

#define GET_FEAT_SIZE	4
#define SET_FEAT_SIZE	4
#define EFFECTS_MASK	(BIT(0) | BIT(9))

#define MAX_TEST_FEATURES	1
#define DEFAULT_TEST_DATA	0xdeadbeef
#define DEFAULT_TEST_DATA2	0xabcdabcd

struct test_feature {
	uuid_t uuid;
	size_t get_size;
	size_t set_size;
};

static int send_command(int fd, struct fwctl_rpc *rpc, struct fwctl_rpc_cxl_out *out)
{
	if (ioctl(fd, FWCTL_RPC, rpc) == -1) {
		fprintf(stderr, "RPC ioctl error: %s\n", strerror(errno));
		return -errno;
	}

	if (out->retval) {
		fprintf(stderr, "operation returned failure: %d\n", out->retval);
		return -ENXIO;
	}

	return 0;
}

static int cxl_fwctl_rpc_get_test_feature(int fd, struct test_feature *feat_ctx,
					  const uint32_t expected_data)
{
	struct cxl_mbox_get_feat_in *feat_in;
	struct fwctl_rpc_cxl_out *out;
	struct fwctl_rpc rpc = {0};
	struct fwctl_rpc_cxl *in;
	size_t out_size, in_size;
	uint32_t val;
	void *data;
	int rc;

	in_size = sizeof(*in) + sizeof(*feat_in);
	rc = posix_memalign((void **)&in, 16, in_size);
	if (rc)
		return -ENOMEM;
	memset(in, 0, in_size);
	feat_in = &in->get_feat_in;

	uuid_copy(feat_in->uuid, feat_ctx->uuid);
	feat_in->count = feat_ctx->get_size;

	out_size = sizeof(*out) + feat_ctx->get_size;
	rc = posix_memalign((void **)&out, 16, out_size);
	if (rc)
		goto free_in;
	memset(out, 0, out_size);

	in->opcode = CXL_MBOX_OPCODE_GET_FEATURE;
	in->op_size = sizeof(*feat_in);

	rpc.size = sizeof(rpc);
	rpc.scope = FWCTL_RPC_CONFIGURATION;
	rpc.in_len = in_size;
	rpc.out_len = out_size;
	rpc.in = (uint64_t)(uint64_t *)in;
	rpc.out = (uint64_t)(uint64_t *)out;

	rc = send_command(fd, &rpc, out);
	if (rc)
		goto free_all;

	data = out->payload;
	val = le32toh(*(__le32 *)data);
	if (memcmp(&val, &expected_data, sizeof(val)) != 0) {
		rc = -ENXIO;
		goto free_all;
	}

free_all:
	free(out);
free_in:
	free(in);
	return rc;
}

static int cxl_fwctl_rpc_set_test_feature(int fd, struct test_feature *feat_ctx)
{
	struct cxl_mbox_set_feat_in *feat_in;
	struct fwctl_rpc_cxl_out *out;
	struct fwctl_rpc_cxl *in;
	struct fwctl_rpc rpc = {0};
	size_t in_size, out_size;
	uint32_t val;
	void *data;
	int rc;

	in_size = sizeof(*in) + sizeof(*feat_in) + sizeof(val);
	rc = posix_memalign((void **)&in, 16, in_size);
	if (rc)
		return -ENOMEM;
	memset(in, 0, in_size);
	feat_in = &in->set_feat_in;

	out_size = sizeof(*out) + sizeof(val);
	rc = posix_memalign((void **)&out, 16, out_size);
	if (rc)
		goto free_in;

	uuid_copy(feat_in->uuid, feat_ctx->uuid);
	data = feat_in->feat_data;
	val = DEFAULT_TEST_DATA2;
	*(uint32_t *)data = htole32(val);
	feat_in->flags = CXL_SET_FEAT_FLAG_FULL_DATA_TRANSFER;

	in->opcode = CXL_MBOX_OPCODE_SET_FEATURE;
	in->op_size = sizeof(*feat_in) + sizeof(val);

	rpc.size = sizeof(rpc);
	rpc.scope = FWCTL_RPC_DEBUG_WRITE_FULL;
	rpc.in_len = in_size;
	rpc.out_len = out_size;
	rpc.in = (uint64_t)(uint64_t *)in;
	rpc.out = (uint64_t)(uint64_t *)out;

	rc = send_command(fd, &rpc, out);
	if (rc)
		goto free_all;

	rc = cxl_fwctl_rpc_get_test_feature(fd, feat_ctx, DEFAULT_TEST_DATA2);
	if (rc) {
		fprintf(stderr, "Failed ioctl to get feature verify: %d\n", rc);
		goto free_all;
	}

free_all:
	free(out);
free_in:
	free(in);
	return rc;
}

static int cxl_fwctl_rpc_get_supported_features(int fd, struct test_feature *feat_ctx)
{
	struct cxl_mbox_get_sup_feats_out *feat_out;
	struct cxl_mbox_get_sup_feats_in *feat_in;
	struct fwctl_rpc_cxl_out *out;
	struct fwctl_rpc_cxl *in;
	struct cxl_feat_entry *entry;
	struct fwctl_rpc rpc = {0};
	size_t out_size, in_size;
	int feats, rc;

	in_size = sizeof(*in) + sizeof(*feat_in);
	rc = posix_memalign((void **)&in, 16, in_size);
	if (rc)
		return rc;
	memset(in, 0, in_size);
	/* First query, to get number of features w/o per feature data */
	in->opcode = CXL_MBOX_OPCODE_GET_SUPPORTED_FEATURES;
	in->op_size = sizeof(*feat_in);

	out_size = sizeof(*out) + sizeof(*feat_out);
	rc = posix_memalign((void **)&out, 16, out_size);
	if (rc)
		goto free_in;

	/* No need to fill in feat_in first go as we are passing in all 0's */

	rpc.size = sizeof(rpc);
	rpc.scope = FWCTL_RPC_CONFIGURATION;
	rpc.in_len = in_size;
	rpc.out_len = out_size;
	rpc.in = (uint64_t)(uint64_t *)in;
	rpc.out = (uint64_t)(uint64_t *)out;

	rc = send_command(fd, &rpc, out);
	if (rc)
		goto free_all;

	feat_out = &out->get_sup_feats_out;
	feats = le16toh(feat_out->supported_feats);
	if (feats != MAX_TEST_FEATURES) {
		fprintf(stderr, "Test device has greater than %d test features.\n",
			MAX_TEST_FEATURES);
		rc = -ENXIO;
		goto free_all;
	}

	free(in);
	free(out);

	/* Going second round to retrieve each feature details */
	in_size += feats * sizeof(*entry);
	rc = posix_memalign((void **)&in, 16, in_size);
	if (rc)
		return rc;
	memset(in, 0, in_size);
	in->opcode = CXL_MBOX_OPCODE_GET_SUPPORTED_FEATURES;
	in->op_size = sizeof(*feat_in);

	out_size += feats * sizeof(*entry);
	rpc.out_len = out_size;
	rc = posix_memalign((void **)&out, 16, out_size);
	if (rc)
		goto free_in;
	memset(out, 0, out_size);

	feat_in = &in->get_sup_feats_in;

	rpc.out = (uint64_t)(uint64_t *)out;
	rpc.out_len = out_size;
	rpc.in = (uint64_t)(uint64_t *)in;
	rpc.in_len = in_size;
	feat_in->count = htole32(feats * sizeof(*entry));

	rc = send_command(fd, &rpc, out);
	if (rc)
		goto free_all;

	feat_out = &out->get_sup_feats_out;
	feats = le16toh(feat_out->supported_feats);
	if (feats != MAX_TEST_FEATURES) {
		fprintf(stderr, "Test device has greater than %u test features.\n",
			MAX_TEST_FEATURES);
		rc = -ENXIO;
		goto free_all;
	}

	if (le16toh(feat_out->num_entries) != MAX_TEST_FEATURES) {
		fprintf(stderr, "Test device did not return expected entries. %u\n",
			le16toh(feat_out->num_entries));
		rc = -ENXIO;
		goto free_all;
	}

	entry = &feat_out->ents[0];
	if (uuid_compare(test_uuid, entry->uuid) != 0) {
		fprintf(stderr, "Test device did not export expected test feature.\n");
		rc = -ENXIO;
		goto free_all;
	}

	if (le16toh(entry->get_feat_size) != GET_FEAT_SIZE ||
	    le16toh(entry->set_feat_size) != SET_FEAT_SIZE) {
		fprintf(stderr, "Test device feature in/out size incorrect.\n");
		rc = -ENXIO;
		goto free_all;
	}

	if (le16toh(entry->effects) != EFFECTS_MASK) {
		fprintf(stderr, "Test device set effects incorrect\n");
		rc = -ENXIO;
		goto free_all;
	}

	uuid_copy(feat_ctx->uuid, entry->uuid);
	feat_ctx->get_size = le16toh(entry->get_feat_size);
	feat_ctx->set_size = le16toh(entry->set_feat_size);

free_all:
	free(out);
free_in:
	free(in);
	return rc;
}

static int test_fwctl_features(struct cxl_memdev *memdev)
{
	struct test_feature feat_ctx;
	unsigned int major, minor;
	int fd, rc;
	char path[256];

	major = cxl_memdev_get_fwctl_major(memdev);
	minor = cxl_memdev_get_fwctl_minor(memdev);

	if (!major && !minor)
		return -ENODEV;

	sprintf(path, "/dev/char/%d:%d", major, minor);

	fd = open(path, O_RDONLY, 0644);
	if (!fd) {
		fprintf(stderr, "Failed to open: %d\n", -errno);
		return -errno;
	}

	rc = cxl_fwctl_rpc_get_supported_features(fd, &feat_ctx);
	if (rc) {
		fprintf(stderr, "Failed ioctl to get supported features: %d\n", rc);
		goto out;
	}

	rc = cxl_fwctl_rpc_get_test_feature(fd, &feat_ctx, DEFAULT_TEST_DATA);
	if (rc) {
		fprintf(stderr, "Failed ioctl to get feature: %d\n", rc);
		goto out;
	}

	rc = cxl_fwctl_rpc_set_test_feature(fd, &feat_ctx);
	if (rc) {
		fprintf(stderr, "Failed ioctl to set feature: %d\n", rc);
		goto out;
	}

out:
	close(fd);
	return rc;
}

static int test_fwctl(struct cxl_ctx *ctx, struct cxl_bus *bus)
{
	struct cxl_memdev *memdev;

	cxl_memdev_foreach(ctx, memdev) {
		if (cxl_memdev_get_bus(memdev) != bus)
			continue;
		return test_fwctl_features(memdev);
	}

	return 0;
}

int main(int argc, char *argv[])
{
	struct cxl_ctx *ctx;
	struct cxl_bus *bus;
	int rc;

	rc = cxl_new(&ctx);
	if (rc < 0)
		return rc;

	cxl_set_log_priority(ctx, LOG_DEBUG);

	bus = cxl_bus_get_by_provider(ctx, provider);
	if (!bus) {
		fprintf(stderr, "%s: unable to find bus (%s)\n",
			argv[0], provider);
		rc = -EINVAL;
		goto out;
	}

	rc = test_fwctl(ctx, bus);

out:
	cxl_unref(ctx);
	return rc;
}
