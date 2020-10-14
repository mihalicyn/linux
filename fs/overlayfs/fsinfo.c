// SPDX-License-Identifier: GPL-2.0
/* Filesystem information for overlayfs
 *
 * Copyright (C) 2020 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/mount.h>
#include <linux/fsinfo.h>
#include "overlayfs.h"

static int __ovl_encode_mnt_opt_fh(struct fsinfo_ovl_source *p,
				   struct dentry *dentry)
{
	int fh_type, dwords;
	int buflen = MAX_HANDLE_SZ;
	int err;

	/* we ask for a non connected handle */
	dwords = buflen >> 2;
	fh_type = exportfs_encode_fh(dentry, (void *)p->fh.f_handle, &dwords, 0);
	buflen = (dwords << 2);

	err = -EIO;
	if (WARN_ON(fh_type < 0) ||
	    WARN_ON(buflen > MAX_HANDLE_SZ) ||
	    WARN_ON(fh_type == FILEID_INVALID))
		goto out_err;

	p->fh.handle_type = fh_type;
	p->fh.handle_bytes = buflen;

	/*
	 * Ideally, we want to have mnt_id+fhandle, but overlayfs not
	 * keep refcnts on layers mounts and we couldn't determine
	 * mnt_ids for layers. So, let's give s_dev to CRIU.
	 * It's better than nothing.
	 */
	p->s_dev = dentry->d_sb->s_dev;

	return 0;

out_err:
	return err;
}

static int ovl_fsinfo_store_source(struct fsinfo_ovl_source *p,
				   enum fsinfo_ovl_source_type type,
				   struct dentry *dentry)
{
	__ovl_encode_mnt_opt_fh(p, dentry);
	p->type = type;
	return 0;
}

static long ovl_ioctl_stor_lower_fhandle(struct fsinfo_ovl_source *p,
					 struct super_block *sb,
					 unsigned long arg)
{
	struct ovl_entry *oe = sb->s_root->d_fsdata;
	struct dentry *origin;

	if (arg >= oe->numlower)
		return -EINVAL;

	origin = oe->lowerstack[arg].dentry;

	return ovl_fsinfo_store_source(p, FSINFO_OVL_LWR, origin);
}

static long ovl_ioctl_stor_upper_fhandle(struct fsinfo_ovl_source *p,
					 struct super_block *sb)
{
	struct ovl_fs *ofs = sb->s_fs_info;
	struct dentry *origin;

	if (!ofs->config.upperdir)
		return -EINVAL;

	origin = OVL_I(d_inode(sb->s_root))->__upperdentry;

	return ovl_fsinfo_store_source(p, FSINFO_OVL_UPPR, origin);
}

static long ovl_ioctl_stor_work_fhandle(struct fsinfo_ovl_source *p,
					struct super_block *sb)
{
	struct ovl_fs *ofs = sb->s_fs_info;

	if (!ofs->config.upperdir)
		return -EINVAL;

	return ovl_fsinfo_store_source(p, FSINFO_OVL_WRK, ofs->workbasedir);
}

static int ovl_fsinfo_sources(struct path *path, struct fsinfo_context *ctx)
{
	struct fsinfo_ovl_source *p = ctx->buffer;
	struct super_block *sb = path->dentry->d_sb;
	struct ovl_fs *ofs = sb->s_fs_info;
	struct ovl_entry *oe = sb->s_root->d_fsdata;
	size_t nr_sources = (oe->numlower + 2 * !!ofs->config.upperdir);
	unsigned int i = 0, j;
	int ret = -ENODATA;

	ret = nr_sources * sizeof(*p);
	if (ret <= ctx->buf_size) {
		if (ofs->config.upperdir) {
			ovl_ioctl_stor_upper_fhandle(&p[i++], sb);
			ovl_ioctl_stor_work_fhandle(&p[i++], sb);
		}

		for (j = 0; j < oe->numlower; j++)
			ovl_ioctl_stor_lower_fhandle(&p[i++], sb, j);
	}

	return ret;
}

static const struct fsinfo_attribute ovl_fsinfo_attributes[] = {
	/* TODO: implement FSINFO_ATTR_SUPPORTS and FSINFO_ATTR_FEATURES */
	/*
	FSINFO_VSTRUCT	(FSINFO_ATTR_SUPPORTS,		ovl_fsinfo_supports),
	FSINFO_VSTRUCT	(FSINFO_ATTR_FEATURES,		ovl_fsinfo_features),
	*/
	FSINFO_LIST	(FSINFO_ATTR_OVL_SOURCES,	ovl_fsinfo_sources),
	{}
};

int ovl_fsinfo(struct path *path, struct fsinfo_context *ctx)
{
	return fsinfo_get_attribute(path, ctx, ovl_fsinfo_attributes);
}
