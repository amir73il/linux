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
#include <linux/cred.h>
#include <linux/exportfs.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/parser.h>
#include <linux/ratelimit.h>
#include <linux/seq_file.h>
#include "overlayfs.h"


enum ovl_snapshot_flag {
	/* No need to copy object to snapshot */
	OVL_SNAP_NOCOW,
	/* No need to copy children to snapshot */
	OVL_SNAP_CHILDREN_NOCOW,
};

static bool ovl_snapshot_test_flag(int nr, struct dentry *dentry)
{
	return test_bit(nr, &OVL_E(dentry)->snapflags);
}

static void ovl_snapshot_set_flag(int nr, struct dentry *dentry)
{
	set_bit(nr, &OVL_E(dentry)->snapflags);
}

static struct vfsmount *ovl_snapshot_mntget(struct dentry *dentry)
{
	return mntget(OVL_FS(dentry->d_sb)->snap_mnt);
}

static bool ovl_snapshot_need_cow(struct dentry *dentry)
{
	return !ovl_snapshot_test_flag(OVL_SNAP_NOCOW, dentry);
}

static bool ovl_snapshot_children_need_cow(struct dentry *dentry)
{
	return !ovl_snapshot_test_flag(OVL_SNAP_CHILDREN_NOCOW, dentry);
}

static void ovl_snapshot_set_nocow(struct dentry *dentry)
{
	ovl_snapshot_set_flag(OVL_SNAP_NOCOW, dentry);
}

static void ovl_snapshot_set_children_nocow(struct dentry *dentry)
{
	ovl_snapshot_set_flag(OVL_SNAP_CHILDREN_NOCOW, dentry);
}

/* Lookup snapshot overlay directory from a snapshot fs directory */
static struct dentry *ovl_snapshot_lookup_dir(struct super_block *snapsb,
					      struct dentry *dentry)
{
	struct dentry *upper = ovl_dentry_upper(dentry);

	if (WARN_ON(!upper))
		return ERR_PTR(-ENOENT);

	/* Find a snapshot overlay dentry whose lower is our upper */
	return ovl_lookup_real(snapsb, upper, &OVL_FS(snapsb)->layers[1]);
}

/*
 * Check if dentry or its children need to be copied to snapshot and cache
 * the result in dentry flags.
 *
 * We lookup directory in snapshot by index and non-directory and negative
 * dentries by name relative to snapshot's parent directory.
 *
 * Returns the found snapshot overlay dentry.
 * Returns error is failed to lookup snapshot overlay dentry.
 * Returns NULL if dentry doesn't need to be copied to snapshot.
 */
static struct dentry *ovl_snapshot_check_cow(struct dentry *parent,
					     struct dentry *dentry)
{
	struct vfsmount *snapmnt = ovl_snapshot_mntget(dentry);
	bool is_dir = d_is_dir(dentry);
	struct dentry *dir = is_dir ? dentry : parent;
	const struct qstr *name = &dentry->d_name;
	struct dentry *snapdir = NULL;
	struct dentry *snap = NULL;
	const struct cred *old_cred = NULL;
	int err;

	if (!snapmnt || !ovl_snapshot_need_cow(dentry))
		goto out;

	err = ovl_inode_lock_interruptible(d_inode(dir));
	if (err) {
		snap = ERR_PTR(err);
		goto out;
	}

	if (!ovl_snapshot_need_cow(dentry))
		goto out_unlock;

	if (!is_dir && !ovl_snapshot_children_need_cow(parent)) {
		ovl_snapshot_set_nocow(dentry);
		goto out_unlock;
	}

	if (OVL_FS(dentry->d_sb)->config.metacopy && !is_dir &&
	    !d_is_negative(dentry) && !ovl_snapshot_need_cow(parent)) {
		/* Only copy directory skeleton to snapshot */
		ovl_snapshot_set_nocow(dentry);
		goto out_unlock;
	}

	old_cred = ovl_override_creds(dentry->d_sb);
	/* Find dir or non-dir parent by index in snapshot */
	snapdir = ovl_snapshot_lookup_dir(snapmnt->mnt_sb, dir);
	if (IS_ERR(snapdir)) {
		err = PTR_ERR(snapdir);
		snap = snapdir;
		snapdir = NULL;
		/*
		 * ENOENT - maybe dir is new and whiteout in snapshot.
		 * ESTALE - maybe dir is new and an old object in snapshot.
		 * In either case, no need to copy children to snapshot.
		 */
		if (err == -ENOENT || err == -ESTALE) {
			ovl_snapshot_set_nocow(dentry);
			ovl_snapshot_set_children_nocow(dir);
			snap = NULL;
		}
		goto out_unlock;
	}

	/*
	 * Negative dentries are not indexed and non-directory dentries can
	 * have several aliases (i.e. copied up hardlinks), so we need to look
	 * them up by name after looking up parent by index.
	 */
	if (is_dir) {
		snap = dget(snapdir);
	} else {
		snap = lookup_one_len_unlocked(name->name, snapdir, name->len);
		if (IS_ERR(snap))
			goto out_unlock;
	}

	/*
	 * Set NOCOW if no need to copy object to snapshot because object is
	 * whiteout in snapshot or already copied up to snapshot.
	 */
	if (ovl_dentry_is_whiteout(snap) ||
	    (d_inode(snap) && ovl_already_copied_up(snap, O_WRONLY))) {
		ovl_snapshot_set_nocow(dentry);
		dput(snap);
		snap = NULL;
	}

out_unlock:
	dput(snapdir);
	if (old_cred)
		revert_creds(old_cred);
	ovl_inode_unlock(d_inode(dir));
out:
	mntput(snapmnt);
	return snap;
}

/*
 * Lookup the underlying dentry in the same path as the looked up snapshot fs
 * dentry and find an overlay snapshot dentry which refers back to the
 * underlying dentry. Check if dentry has already been copied up or doesn't
 * need to be copied to snapshot and cache the result in dentry flags.
 */
static struct dentry *ovl_snapshot_lookup(struct inode *dir,
					  struct dentry *dentry,
					  unsigned int flags)
{
	struct dentry *parent = dentry->d_parent;
	struct dentry *ret;
	struct dentry *snap;

	if (WARN_ON(!ovl_dentry_upper(parent)))
		return ERR_PTR(-ENOENT);

	ret = ovl_lookup(dir, dentry, flags);
	if (IS_ERR(ret))
		return ret;
	else if (ret)
		dentry = ret;

	/* Best effort - will check again before actual write */
	snap = ovl_snapshot_check_cow(parent, dentry);
	if (!IS_ERR(snap))
		dput(snap);

	return ret;
}

const struct inode_operations ovl_snapshot_inode_operations = {
	.lookup		= ovl_snapshot_lookup,
	.mkdir		= ovl_mkdir,
	.symlink	= ovl_symlink,
	.unlink		= ovl_unlink,
	.rmdir		= ovl_rmdir,
	.rename		= ovl_rename,
	.link		= ovl_link,
	.setattr	= ovl_setattr,
	.create		= ovl_create,
	.mknod		= ovl_mknod,
	.permission	= ovl_permission,
	.getattr	= ovl_getattr,
	.listxattr	= ovl_listxattr,
	.get_acl	= ovl_get_acl,
	.update_time	= ovl_update_time,
};

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
	if (ofs->config.metacopy)
		seq_puts(m, ",metacopy=on");

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

static int ovl_snapshot_encode_fh(struct inode *inode, u32 *fid, int *max_len,
				  struct inode *parent)
{
	/* Encode the real fs inode */
	return exportfs_encode_inode_fh(ovl_inode_upper(inode),
					(struct fid *)fid, max_len,
					parent ? ovl_inode_upper(parent) :
					NULL);
}

static int ovl_snapshot_acceptable(void *context, struct dentry *dentry)
{
	return 1;
}

static struct dentry *ovl_snapshot_fh_to_dentry(struct super_block *sb,
						struct fid *fid,
						int fh_len, int fh_type)
{
	struct ovl_fs *ofs = sb->s_fs_info;
	struct dentry *real;
	struct dentry *this;

	/* Decode the real fs inode */
	real = exportfs_decode_fh(ovl_upper_mnt(ofs), fid, fh_len, fh_type,
				  ovl_snapshot_acceptable, NULL);
	if (IS_ERR_OR_NULL(real))
		return real;

	this = ovl_get_dentry(sb, real, NULL, NULL);
	dput(real);

	return this;
}

const struct export_operations ovl_snapshot_export_operations = {
	.encode_fh      = ovl_snapshot_encode_fh,
	.fh_to_dentry   = ovl_snapshot_fh_to_dentry,
};


enum {
	OPT_SNAPSHOT,
	OPT_NOSNAPSHOT,
	OPT_METACOPY_ON,
	OPT_METACOPY_OFF,
	OPT_ERR,
};

static const match_table_t ovl_snapshot_tokens = {
	{OPT_SNAPSHOT,		"snapshot=%s"},
	{OPT_NOSNAPSHOT,	"nosnapshot"},
	{OPT_METACOPY_ON,	"metacopy=on"},
	{OPT_METACOPY_OFF,	"metacopy=off"},
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

		case OPT_METACOPY_ON:
			config->metacopy = true;
			break;

		case OPT_METACOPY_OFF:
			config->metacopy = false;
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

	if (ovl_can_decode_fh(upperpath.dentry->d_sb))
		sb->s_export_op = &ovl_snapshot_export_operations;

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

	ovl_snapshot_set_nocow(root_dentry);
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

/*
 * Helpers for overlayfs snapshot that may be called from code that is
 * shared between snapshot fs mount and overlay fs mount.
 */
static struct dentry *ovl_snapshot_dentry(struct dentry *dentry)
{
	struct dentry *parent = dget_parent(dentry);
	struct dentry *snap;

	snap = ovl_snapshot_check_cow(parent, dentry);

	dput(parent);
	return snap;
}

/*
 * Copy to snapshot if needed before file is modified.
 */
static int ovl_snapshot_copy_up(struct dentry *dentry)
{
	struct inode *inode = d_inode(dentry);
	struct dentry *snap = NULL;
	bool disconnected = dentry->d_flags & DCACHE_DISCONNECTED;
	int err = -ENOENT;

	if (WARN_ON(!inode))
		goto bug;

	err = -ESTALE;
	if (disconnected)
		goto bug;

	/*
	 * Snapshot overlay dentry may be positive or negative or NULL.
	 * If positive, it may need to be copied up.
	 * If negative, it should be a whiteout, because our dentry is positive.
	 * If snapshot overlay dentry is already copied up or whiteout or if it
	 * is an ancestor of an already whited out directory, we need to do
	 * nothing about it.
	 */
	snap = ovl_snapshot_dentry(dentry);
	if (!snap)
		return 0;

	if (IS_ERR(snap)) {
		err = PTR_ERR(snap);
		snap = NULL;
		goto bug;
	}

	if (WARN_ON(d_is_negative(snap)))
		goto bug;

	/* Trigger copy up in snapshot overlay */
	err = ovl_want_write(snap);
	if (err)
		goto bug;
	err = ovl_copy_up_with_data(snap);
	ovl_drop_write(snap);
	if (err)
		goto bug;

	/* No need to copy to snapshot next time */
	ovl_snapshot_set_nocow(dentry);
	dput(snap);
	return 0;
bug:
	pr_warn_ratelimited("failed copy to snapshot (%pd2, ino=%lu, err=%i)\n",
			    dentry, inode ? inode->i_ino : 0, err);
	dput(snap);
	/* Allowing write would corrupt snapshot so deny */
	return -EROFS;
}

/* Explicitly whiteout a negative snapshot fs dentry before create */
static int ovl_snapshot_whiteout(struct dentry *dentry)
{
	struct dentry *snap = ovl_snapshot_dentry(dentry);
	struct dentry *parent = NULL;
	struct dentry *upperdir;
	struct dentry *whiteout = NULL;
	struct inode *sdir = NULL;
	struct inode *udir = NULL;
	const struct cred *old_cred = NULL;
	int err = 0;

	if (IS_ERR(snap))
		return PTR_ERR(snap);

	/* No need to whiteout a positive or whiteout snapshot dentry */
	if (!snap || !d_is_negative(snap) || ovl_dentry_is_opaque(snap))
		goto out;

	parent = dget_parent(snap);
	sdir = parent->d_inode;

	inode_lock_nested(sdir, I_MUTEX_PARENT);

	err = ovl_want_write(snap);
	if (err)
		goto out;

	err = ovl_copy_up(parent);
	if (err)
		goto out_drop_write;

	upperdir = ovl_dentry_upper(parent);
	udir = upperdir->d_inode;
	old_cred = ovl_override_creds(snap->d_sb);
	inode_lock_nested(udir, I_MUTEX_PARENT);

	whiteout = lookup_one_len(snap->d_name.name, upperdir,
				  snap->d_name.len);
	if (IS_ERR(whiteout)) {
		err = PTR_ERR(whiteout);
		whiteout = NULL;
		goto out_drop_write;
	}

	/*
	 * We could have raced with another task that tested false
	 * ovl_dentry_is_opaque() before udir lock, so if we find a
	 * whiteout all is good.
	 */
	if (!ovl_is_whiteout(whiteout)) {
		err = ovl_do_whiteout(udir, whiteout);
		if (err)
			goto out_drop_write;
	}

	/*
	 * Setting a negative snapshot dentry opaque to signify that
	 * lower is going to be positive and set dedntry flags to suppress
	 * copy to snapshot of future object and possibly its children.
	 */
	ovl_dentry_set_opaque(snap);
	ovl_dir_modified(parent, true);
	ovl_snapshot_set_nocow(dentry);
	ovl_snapshot_set_children_nocow(dentry);

out_drop_write:
	if (udir)
		inode_unlock(udir);
	if (old_cred)
		revert_creds(old_cred);
	ovl_drop_write(snap);
out:
	if (sdir)
		inode_unlock(sdir);
	dput(whiteout);
	dput(parent);
	dput(snap);
	return err;
}

static int ovl_snapshot_copy_up_meta(struct dentry *dentry)
{
	struct dentry *parent;
	int err;

	if (d_is_dir(dentry) || !OVL_FS(dentry->d_sb)->config.metacopy)
		return ovl_snapshot_copy_up(dentry);

	/* Only copy directory skeleton to snapshot */
	parent = dget_parent(dentry);
	err = ovl_snapshot_copy_up(parent);
	dput(parent);

	return err;
}

int ovl_snapshot_open(struct dentry *dentry, unsigned int flags)
{
	struct vfsmount *snapmnt = ovl_snapshot_mntget(dentry);
	int err = 0;

	if (snapmnt && ovl_open_flags_need_copy_up(flags) &&
	    !special_file(d_inode(dentry)->i_mode) &&
	    ovl_snapshot_need_cow(dentry))
		err = ovl_snapshot_copy_up_meta(dentry);

	mntput(snapmnt);
	return err;
}

int ovl_snapshot_modify(struct dentry *dentry)
{
	struct vfsmount *snapmnt = ovl_snapshot_mntget(dentry);
	int err = 0;

	if (snapmnt && ovl_snapshot_need_cow(dentry)) {
		/* Negative dentry may need to be explicitly whited out */
		if (d_is_negative(dentry))
			err = ovl_snapshot_whiteout(dentry);
		else
			err = ovl_snapshot_copy_up_meta(dentry);
	}

	mntput(snapmnt);
	return err;
}
