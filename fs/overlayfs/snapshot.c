/*
 * File: fs/overlayfs/snapshot.c
 *
 * Overlayfs snapshot core functions.
 *
 * Copyright (C) 2016-2018 CTERA Network by Amir Goldstein <amir73il@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 */

#include <uapi/linux/magic.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/parser.h>
#include <linux/seq_file.h>
#include "overlayfs.h"

static const struct dentry_operations ovl_snapshot_dentry_operations = {
	.d_release = ovl_dentry_release,
	.d_real = ovl_d_real,
};

static int ovl_snapshot_show_options(struct seq_file *m, struct dentry *dentry)
{
	struct ovl_fs *ofs = OVL_FS(dentry->d_sb);

	if (ofs->config.snapshot)
		seq_show_option(m, "snapshot", ofs->config.snapshot);
	else
		seq_puts(m, ",nosnapshot");

	return 0;
}

static int ovl_snapshot_remount(struct super_block *sb, int *flags, char *data)
{
	return 0;
}

static const struct super_operations ovl_snapshot_super_operations = {
	.alloc_inode	= ovl_alloc_inode,
	.free_inode	= ovl_free_inode,
	.destroy_inode	= ovl_destroy_inode,
	.drop_inode	= generic_delete_inode,
	.put_super	= ovl_put_super,
	.sync_fs	= ovl_sync_fs,
	.statfs		= ovl_statfs,
	.show_options	= ovl_snapshot_show_options,
	.remount_fs	= ovl_snapshot_remount,
};

enum {
	OPT_SNAPSHOT,
	OPT_NOSNAPSHOT,
	OPT_ERR,
};

static const match_table_t ovl_snapshot_tokens = {
	{OPT_SNAPSHOT,		"snapshot=%s"},
	{OPT_NOSNAPSHOT,	"nosnapshot"},
	{OPT_ERR,		NULL}
};

static int ovl_snapshot_parse_opt(char *opt, struct ovl_config *config)
{
	char *p;

	while ((p = ovl_next_opt(&opt)) != NULL) {
		int token;
		substring_t args[MAX_OPT_ARGS];

		if (!*p)
			continue;

		token = match_token(p, ovl_snapshot_tokens, args);
		switch (token) {
		case OPT_SNAPSHOT:
			kfree(config->snapshot);
			config->snapshot = match_strdup(&args[0]);
			if (!config->snapshot)
				return -ENOMEM;
			break;

		case OPT_NOSNAPSHOT:
			kfree(config->snapshot);
			config->snapshot = NULL;
			break;

		default:
			pr_err("unrecognized snapshot mount option \"%s\" or missing value\n", p);
			return -EINVAL;
		}
	}

	return 0;
}

static struct vfsmount *ovl_get_snapshot(struct ovl_fs *ofs)
{
	struct super_block *snapsb;
	struct path snappath = { };
	struct vfsmount *snapmnt;
	char *tmp = NULL;
	int err;

	err = -ENOMEM;
	tmp = kstrdup(ofs->config.snapshot, GFP_KERNEL);
	if (!tmp)
		goto out_err;

	ovl_unescape(tmp);
	err = ovl_mount_dir_noesc(ofs->config.snapshot, &snappath);
	if (err)
		goto out_err;

	/*
	 * The path passed in snapshot=<snappath> needs to be the root of a
	 * non-nested overlayfs with a single lower layer that matches the
	 * snapshot mount upper path.
	 */
	snapsb = snappath.mnt->mnt_sb;
	err = -EINVAL;
	if (!ovl_is_overlay_fs(snapsb) || snappath.dentry != snapsb->s_root) {
		pr_err("snapshot='%s' is not an overlayfs root\n",
		       tmp);
		goto out_err;
	}

	if (snapsb->s_stack_depth > 1) {
		pr_err("snapshot='%s' is a nested overlayfs\n", tmp);
		goto out_err;
	}

	if (OVL_FS(snapsb)->numlayer != 2 ||
	    ovl_upper_mnt(ofs)->mnt_root !=
	    OVL_FS(snapsb)->layers[1].mnt->mnt_root) {
		pr_err("upperdir and snapshot's lowerdir mismatch\n");
		goto out_err;
	}

	snapmnt = clone_private_mount(&snappath);
	err = PTR_ERR(snapmnt);
	if (IS_ERR(snapmnt)) {
		pr_err("failed to clone snapshot path\n");
		goto out_err;
	}

out:
	path_put(&snappath);
	kfree(tmp);
	return snapmnt;

out_err:
	snapmnt = ERR_PTR(err);
	goto out;
}

static int ovl_snapshot_fill_super(struct super_block *sb, const char *dev_name,
				   char *opt)
{
	struct path upperpath = { };
	struct dentry *root_dentry;
	struct vfsmount *snapmnt;
	struct ovl_entry *oe = NULL;
	struct ovl_layer *upper_layer;
	struct ovl_fs *ofs;
	struct cred *cred;
	int err;

	err = -ENOMEM;
	ofs = kzalloc(sizeof(struct ovl_fs), GFP_KERNEL);
	if (!ofs)
		goto out;

	ofs->creator_cred = cred = prepare_creds();
	if (!cred)
		goto out_err;

	err = ovl_snapshot_parse_opt(opt, &ofs->config);
	if (err)
		goto out_err;

	err = -ENOMEM;
	ofs->config.upperdir = kstrdup(dev_name, GFP_KERNEL);
	if (!ofs->config.upperdir)
		goto out_err;

	/* alloc/destroy_inode needed for setting up traps in inode cache */
	sb->s_op = &ovl_snapshot_super_operations;

	upper_layer = kzalloc(sizeof(struct ovl_layer), GFP_KERNEL);
	if (!upper_layer)
		goto out_err;

	ofs->layers = upper_layer;
	ofs->numlayer = 1;
	err = ovl_get_upper(sb, ofs, upper_layer, &upperpath);
	if (err)
		goto out_err;

	sb->s_maxbytes = upper_layer->mnt->mnt_sb->s_maxbytes;
	sb->s_time_gran = upper_layer->mnt->mnt_sb->s_time_gran;
	sb->s_stack_depth = upper_layer->mnt->mnt_sb->s_stack_depth;

	/*
	 * Snapshot mount may be remounted later with underlying
	 * snapshot overlay. We must leave room in stack below us
	 * for that overlay, even if snapshot= mount option is not
	 * provided on the initial mount.
	 */
	if (!sb->s_stack_depth)
		sb->s_stack_depth++;

	err = -EINVAL;
	sb->s_stack_depth++;
	if (sb->s_stack_depth > FILESYSTEM_MAX_STACK_DEPTH) {
		pr_err("snapshot fs maximum stacking depth exceeded\n");
		goto out_err;
	}

	if (ofs->config.snapshot) {
		snapmnt = ovl_get_snapshot(ofs);
		err = PTR_ERR(snapmnt);
		if (IS_ERR(snapmnt))
			goto out_err;

		ofs->snap_mnt = snapmnt;
	}

	/* No need to set/get any overlay xattr for snaphsot fs */
	ofs->noxattr = true;

	err = -ENOMEM;
	oe = ovl_alloc_entry(0);
	if (!oe)
		goto out_err;

	sb->s_d_op = &ovl_snapshot_dentry_operations;

	/* Never override disk quota limits or use reserved space */
	cap_lower(cred->cap_effective, CAP_SYS_RESOURCE);

	sb->s_magic = OVERLAYFS_SUPER_MAGIC;
	sb->s_xattr = ovl_xattr_handlers;
	sb->s_fs_info = ofs;
	sb->s_flags |= SB_POSIXACL;
	sb->s_iflags |= SB_I_SKIP_SYNC;

	err = -ENOMEM;
	root_dentry = ovl_get_root(sb, upperpath.dentry, oe);
	if (!root_dentry)
		goto out_err;

	mntput(upperpath.mnt);

	sb->s_root = root_dentry;

	return 0;

out_err:
	kfree(oe);
	path_put(&upperpath);
	ovl_free_fs(ofs);
out:
	return err;
}

static struct dentry *ovl_snapshot_mount(struct file_system_type *fs_type,
					 int flags, const char *dev_name,
					 void *raw_data)
{
	struct super_block *sb;
	int err;

	sb = sget(fs_type, NULL, set_anon_super, flags, NULL);

	if (IS_ERR(sb))
		return ERR_CAST(sb);

	err = ovl_snapshot_fill_super(sb, dev_name, raw_data);
	if (err) {
		deactivate_locked_super(sb);
		return ERR_PTR(err);
	}
	sb->s_flags |= SB_ACTIVE;

	return dget(sb->s_root);
}

struct file_system_type ovl_snapshot_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "snapshot",
	.mount		= ovl_snapshot_mount,
	.kill_sb	= kill_anon_super,
};
MODULE_ALIAS_FS("snapshot");
MODULE_ALIAS("snapshot");

static bool registered;

int ovl_snapshot_fs_register(void)
{
	int err = register_filesystem(&ovl_snapshot_fs_type);

	if (!err)
		registered = true;

	return err;
}

void ovl_snapshot_fs_unregister(void)
{
	if (registered)
		unregister_filesystem(&ovl_snapshot_fs_type);
}
