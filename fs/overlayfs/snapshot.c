/*
 * File: fs/overlayfs/snapshot.c
 *
 * Overlayfs snapshot core functions.
 *
 * Copyright (C) 2016-2017 CTERA Network by Amir Goldstein <amir73il@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 */

#include <uapi/linux/magic.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/cred.h>
#include <linux/namei.h>
#include <linux/parser.h>
#include <linux/seq_file.h>
#include <linux/ratelimit.h>
#include <linux/exportfs.h>
#include "overlayfs.h"

static void ovl_snapshot_dentry_release(struct dentry *dentry)
{
	struct ovl_entry *oe = dentry->d_fsdata;

	if (oe) {
		dput(oe->__snapdentry);
		kfree_rcu(oe, rcu);
	}
}

static int ovl_snapshot_copy_up_meta(struct dentry *dentry);

static struct dentry *ovl_snapshot_d_real(struct dentry *dentry,
					  const struct inode *inode,
					  unsigned int open_flags,
					  unsigned int flags)
{
	struct dentry *real = ovl_dentry_upper(dentry);
	int err;

	if (flags & D_REAL_UPPER)
		return real;

	if (!d_is_reg(dentry)) {
		if (!inode || inode == d_inode(dentry))
			return dentry;
		goto bug;
	}

	if (!real)
		goto bug;

	if (open_flags & (O_ACCMODE|O_TRUNC)) {
		err = ovl_snapshot_copy_up_meta(dentry);
		if (err)
			return ERR_PTR(err);
	}

	if (inode && inode != d_inode(real))
		goto bug;

	if (!inode) {
		err = ovl_check_append_only(d_inode(real), open_flags);
		if (err)
			return ERR_PTR(err);
	}

	return real;

bug:
	WARN(1, "%s(%pd4, %s:%lu): real dentry not found\n", __func__, dentry,
	     inode ? inode->i_sb->s_id : "NULL", inode ? inode->i_ino : 0);
	return dentry;
}

static int ovl_snapshot_dentry_is_valid(struct dentry *snapdentry,
					struct vfsmount *snapmnt)
{
	/* No snaphsot overlay (pre snapshot take) */
	if (!snapmnt && !snapdentry)
		return 0;

	/* An uninitialized snapdentry after snapshot take */
	if (!snapdentry)
		return -ENOENT;

	/*
	 * snapmnt is NULL and snapdentry is non-NULL
	 * or snapdentry->d_sb != snapmnt->mnt_sb. This implies
	 * a stale snapdentry from an older snapshot overlay
	 */
	if (unlikely(!snapmnt ||
		     snapmnt->mnt_sb != snapdentry->d_sb))
		return -ESTALE;

	return 0;
}

/*
 * Return snapshot overlay path associated with a snapshot mount dentry
 * with elevated refcount if it is valid or error if snapshot mount dentry
 * should be revalidated.
 */
static int ovl_snapshot_path(struct dentry *dentry, struct path *path)
{
	struct ovl_fs *ofs = dentry->d_sb->s_fs_info;
	struct ovl_entry *oe = dentry->d_fsdata;
	struct path snappath;
	int err;

	rcu_read_lock();
	snappath.mnt = mntget(rcu_dereference(ofs->__snapmnt));
	snappath.dentry = dget(rcu_dereference(oe->__snapdentry));
	rcu_read_unlock();

	err = ovl_snapshot_dentry_is_valid(snappath.dentry, snappath.mnt);
	if (err)
		goto out_err;

	*path = snappath;
	return 0;

out_err:
	path_put(&snappath);
	return err;
}

/*
 * Make the new snapshot requested in remount effective.
 *
 * We only update __snapdentry for the snapshot mount root dentry.
 * All other dentries may still reference the old snapshot overlay.
 * Those will be invalidated either by shrink_dcache_parent() below
 * or during RCU lookup by ovl_snapshot_revalidate().
 *
 * TODO: handle stale dentries of open files.
 */
void ovl_snapshot_barrier(struct super_block *sb)
{
	struct ovl_fs *ofs = sb->s_fs_info;
	struct ovl_entry *roe = sb->s_root->d_fsdata;
	struct path oldsnappath;

	if (ofs->__snapmnt == ofs->snap_mnt)
		return;

	pr_debug("%s: old snap_sid='%s'\n", __func__,
		 ofs->__snapmnt ? ofs->__snapmnt->mnt_sb->s_id : "");
	oldsnappath.mnt = ofs->__snapmnt;
	oldsnappath.dentry = roe->__snapdentry;
	rcu_assign_pointer(ofs->__snapmnt, mntget(ofs->snap_mnt));
	rcu_assign_pointer(roe->__snapdentry, ofs->snap_mnt ?
			   dget(ofs->snap_mnt->mnt_root) : NULL);
	pr_debug("%s: new snap_sid='%s'\n", __func__,
		 ofs->__snapmnt ? ofs->__snapmnt->mnt_sb->s_id : "");

	/* wait grace period before dropping old snapshot overlay */
	synchronize_rcu();
	/* prune invalid dcache entries - this doesn't deal with open files */
	shrink_dcache_parent(sb->s_root);
	/* drop old snapmnt - this may warn about dentries still in use */
	path_put(&oldsnappath);
}

/*
 * Returns 1 if both snapdentry and snapmnt are NULL or
 * if snapdentry and snapmnt point to the same super block.
 *
 * Returns 0 if snapdentry is NULL and snapmnt is not NULL or
 * if snapdentry and snapmnt point to different super blocks.
 * This will cause vfs lookup to invalidate this dentry and call ovl_lookup()
 * again to re-lookup snapdentry from the current snapmnt.
 */
static int ovl_snapshot_revalidate(struct dentry *dentry, unsigned int flags)
{
	struct path snappath = { };
	int err;

	if (flags & LOOKUP_RCU) {
		struct ovl_fs *ofs = dentry->d_sb->s_fs_info;
		struct ovl_entry *oe = dentry->d_fsdata;

		err = ovl_snapshot_dentry_is_valid(
				rcu_dereference(oe->__snapdentry),
				rcu_dereference(ofs->__snapmnt));
	} else {
		err = ovl_snapshot_path(dentry, &snappath);
		path_put(&snappath);
	}

	if (likely(!err))
		return 1;

	if (err == -ESTALE || err == -ENOENT)
	       return 0;

	return err;
}

static const struct dentry_operations ovl_snapshot_dentry_operations = {
	.d_release = ovl_snapshot_dentry_release,
	.d_real = ovl_snapshot_d_real,
	.d_revalidate = ovl_snapshot_revalidate,
};

static int ovl_snapshot_freeze(struct super_block *sb)
{
	struct ovl_fs *ofs = sb->s_fs_info;

	return freeze_super(ofs->upper_mnt->mnt_sb);
}

static int ovl_snapshot_unfreeze(struct super_block *sb)
{
	struct ovl_fs *ofs = sb->s_fs_info;

	/* Make requested snapshot effective before thawing fs */
	ovl_snapshot_barrier(sb);

	return thaw_super(ofs->upper_mnt->mnt_sb);
}

static int ovl_snapshot_show_options(struct seq_file *m, struct dentry *dentry)
{
	struct super_block *sb = dentry->d_sb;
	struct ovl_fs *ofs = sb->s_fs_info;

	seq_show_option(m, "upperdir", ofs->config.upperdir);
	if (!ofs->config.redirect_dir)
		seq_puts(m, ",redirect_dir=off");
	if (ofs->config.metacopy)
		seq_puts(m, ",metacopy=on");
	if (ofs->config.snapshot)
		seq_show_option(m, "snapshot", ofs->config.snapshot);
	else
		seq_puts(m, ",nosnapshot");

	return 0;
}

static int ovl_snapshot_remount(struct super_block *sb, int *flags, char *data);

static const struct super_operations ovl_snapshot_super_operations = {
	.alloc_inode	= ovl_alloc_inode,
	.destroy_inode	= ovl_destroy_inode,
	.drop_inode	= generic_delete_inode,
	.put_super	= ovl_put_super,
	.sync_fs	= ovl_sync_fs,
	.freeze_fs	= ovl_snapshot_freeze,
	.unfreeze_fs	= ovl_snapshot_unfreeze,
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
	struct dentry *this = NULL;
	struct dentry *real;
	struct inode *inode;

	/* Decode the real fs inode */
	real = exportfs_decode_fh(ofs->upper_mnt, fid, fh_len, fh_type,
				  ovl_snapshot_acceptable, NULL);
	if (IS_ERR_OR_NULL(real))
		return real;

	/* Lookup snapshot fs dentry from real fs inode */
	inode = ovl_lookup_inode(sb, real, true);
	if (IS_ERR(inode))
		return ERR_CAST(inode);
	if (inode) {
		this = d_find_any_alias(inode);
		iput(inode);
	}

	/*
	 * Decode of non cached dentry is not implemented yet -
	 * should be similar to overlay upper handle decode.
	 */
	return this ?: ERR_PTR(-EACCES);
}

const struct export_operations ovl_snapshot_export_operations = {
	.encode_fh	= ovl_snapshot_encode_fh,
	.fh_to_dentry	= ovl_snapshot_fh_to_dentry,
};

enum {
	OPT_UPPERDIR,
	OPT_REDIRECT_DIR_ON,
	OPT_REDIRECT_DIR_OFF,
	OPT_METACOPY_ON,
	OPT_METACOPY_OFF,
	/* mount options that can be changed on remount: */
	OPT_REMOUNT_FIRST,
	OPT_SNAPSHOT = OPT_REMOUNT_FIRST,
	OPT_NOSNAPSHOT,
	OPT_ERR,
};

static const match_table_t ovl_snapshot_tokens = {
	{OPT_UPPERDIR,			"upperdir=%s"},
	{OPT_REDIRECT_DIR_ON,		"redirect_dir=on"},
	{OPT_REDIRECT_DIR_OFF,		"redirect_dir=off"},
	{OPT_METACOPY_ON,		"metacopy=on"},
	{OPT_METACOPY_OFF,		"metacopy=off"},
	{OPT_SNAPSHOT,			"snapshot=%s"},
	{OPT_NOSNAPSHOT,		"nosnapshot"},
	{OPT_ERR,			NULL}
};

static int ovl_snapshot_parse_opt(char *opt, struct ovl_config *config,
				  bool remount)
{
	char *p;

	while ((p = ovl_next_opt(&opt)) != NULL) {
		int token;
		substring_t args[MAX_OPT_ARGS];

		if (!*p)
			continue;

		token = match_token(p, ovl_snapshot_tokens, args);
		/* Ignore options that cannot be changed on remount */
		if (remount && token < OPT_REMOUNT_FIRST)
			continue;

		switch (token) {
		case OPT_UPPERDIR:
			kfree(config->upperdir);
			config->upperdir = match_strdup(&args[0]);
			if (!config->upperdir)
				return -ENOMEM;
			break;

		case OPT_REDIRECT_DIR_ON:
			config->redirect_dir = true;
			config->redirect_follow = true;
			break;

		case OPT_REDIRECT_DIR_OFF:
			config->redirect_dir = false;
			config->redirect_follow = false;
			break;

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
			pr_err("overlayfs: unrecognized snapshot mount option \"%s\" or missing value\n", p);
			return -EINVAL;
		}
	}

	return 0;
}

static int ovl_snapshot_dir(struct super_block *sb, struct ovl_fs *ofs,
			    const char *name, struct path *snappath)
{
	struct vfsmount *snapmnt;
	char *tmp;
	int err;

	err = -ENOMEM;
	tmp = kstrdup(name, GFP_KERNEL);
	if (!tmp)
		goto out;

	ovl_unescape(tmp);
	err = ovl_mount_dir_noesc(name, snappath);
	if (err)
		goto out;

	snapmnt = snappath->mnt;
	/* snappath has to be the root of a non-nested overlayfs mount */
	err = -EINVAL;
	if (snappath->dentry != snapmnt->mnt_root ||
	    snapmnt->mnt_sb->s_magic != OVERLAYFS_SUPER_MAGIC) {
		pr_err("overlayfs: snapshot='%s' is not an overlayfs mount\n",
		       tmp);
		goto out_put;
	}

	if (snapmnt->mnt_sb->s_stack_depth > 1) {
		pr_err("overlayfs: snapshot='%s' is a nested overlayfs mount\n",
		       tmp);
		goto out_put;
	}

	err = 0;
out:
	kfree(tmp);
	return err;

out_put:
	path_put_init(snappath);
	goto out;
}

static struct vfsmount *ovl_snapshot_clone_mount(struct ovl_fs *ofs,
						 struct path *snappath)
{
	struct ovl_fs *snapfs;
	struct vfsmount *snapmnt;

	snapmnt = clone_private_mount(snappath);
	if (IS_ERR(snapmnt)) {
		pr_err("overlayfs: failed to clone snapshot path\n");
		return snapmnt;
	}

	snapfs = snapmnt->mnt_sb->s_fs_info;
	if (snapfs->numlower > 1 ||
	    ofs->upper_mnt->mnt_root != snapfs->lower_layers[0].mnt->mnt_root) {
		pr_err("overlayfs: upperdir and snapshot's lowerdir mismatch\n");
		mntput(snapmnt);
		return ERR_PTR(-EINVAL);
	}

	return snapmnt;
}
static int ovl_snapshot_fill_super(struct super_block *sb, void *data,
				   int silent)
{
	struct path upperpath = { };
	struct path snappath = { };
	struct vfsmount *snapmnt;
	struct dentry *root_dentry;
	struct ovl_entry *oe = NULL;
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

	ofs->config.redirect_dir = true;
	err = ovl_snapshot_parse_opt((char *) data, &ofs->config, false);
	if (err)
		goto out_err;

	err = -EINVAL;
	if (!ofs->config.upperdir) {
		if (!silent)
			pr_err("overlayfs: snapshot mount missing 'upperdir'\n");
		goto out_err;
	}

	err = ovl_get_upper(ofs, &upperpath);
	if (err)
		goto out_err;

	sb->s_maxbytes = ofs->upper_mnt->mnt_sb->s_maxbytes;
	sb->s_time_gran = ofs->upper_mnt->mnt_sb->s_time_gran;
	ofs->same_sb = ofs->upper_mnt->mnt_sb;

	/*
	 * snapshot mount may be remounted later with underlying
	 * snapshot overlay. we must leave room in stack below us
	 * for that overlay, even if snapshot= mount option is not
	 * provided on the initial mount.
	 */
	sb->s_stack_depth = max(1, ofs->upper_mnt->mnt_sb->s_stack_depth);

	err = -EINVAL;
	sb->s_stack_depth++;
	if (sb->s_stack_depth > FILESYSTEM_MAX_STACK_DEPTH) {
		pr_err("overlayfs: snapshot fs maximum stacking depth exceeded\n");
		goto out_err;
	}

	if (ofs->config.snapshot) {
		err = ovl_snapshot_dir(sb, ofs, ofs->config.snapshot,
				       &snappath);
		if (err)
			goto out_err;

		snapmnt = ovl_snapshot_clone_mount(ofs, &snappath);
		err = PTR_ERR(snapmnt);
		if (IS_ERR(snapmnt))
			goto out_err;

		/* Set both requested and effective snapshot overlay */
		ofs->snap_mnt = snapmnt;
		ofs->__snapmnt = mntget(snapmnt);
	}

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
	sb->s_op = &ovl_snapshot_super_operations;
	sb->s_xattr = ovl_xattr_handlers;
	sb->s_fs_info = ofs;
	sb->s_flags |= MS_POSIXACL | MS_NOREMOTELOCK;

	err = -ENOMEM;
	root_dentry = d_make_root(ovl_new_inode(sb, S_IFDIR, 0));
	if (!root_dentry)
		goto out_err;

	mntput(upperpath.mnt);
	mntput(snappath.mnt);
	oe->__snapdentry = snappath.dentry;

	root_dentry->d_fsdata = oe;
	ovl_dentry_set_upper_alias(root_dentry);

	/* Hash root directory inode for NFS export */
	ovl_inode_update(d_inode(root_dentry), upperpath.dentry);
	ovl_inode_init(d_inode(root_dentry), upperpath.dentry, NULL);

	sb->s_root = root_dentry;

	return 0;

out_err:
	kfree(oe);
	path_put(&upperpath);
	path_put(&snappath);
	ovl_free_fs(ofs);
out:
	return err;
}

static struct dentry *ovl_snapshot_mount(struct file_system_type *fs_type,
					 int flags, const char *dev_name,
					 void *raw_data)
{
	return mount_nodev(fs_type, flags, raw_data, ovl_snapshot_fill_super);
}

static int ovl_snapshot_remount(struct super_block *sb, int *flags, char *data)
{
	struct ovl_fs *ofs = sb->s_fs_info;
	struct path snappath = { };
	struct vfsmount *snapmnt = NULL;
	struct ovl_config config = {
		.snapshot = NULL,
		.lowerdir = NULL,
		.upperdir = NULL,
		.workdir = NULL,
	};
	char *nosnapshot = NULL;
	int err;

	if (!data)
		return 0;

	pr_info("%s: -o'%s'\n", __func__, (char *)data);

	/*
	 * Set config.snapshot to an empty string and parse remount options.
	 * If no new snapshot= option nor nosnapshot option was found,
	 * config.snapshot will remain an empty string and nothing will change.
	 * If snapshot= option will set a new config.snapshot value or
	 * nosnapshot option will free the empty string, then we will
	 * change the requested snapshot overlay to the new one or to NULL.
	 */
	if (ofs->config.snapshot) {
		err = -ENOMEM;
		nosnapshot = kstrdup("", GFP_KERNEL);
		if (!nosnapshot)
			return err;
		config.snapshot = nosnapshot;
	}

	err = ovl_snapshot_parse_opt((char *)data, &config, true);
	if (err)
		goto out_free_config;

	/* If no old snapshot nor new snapshot - do nothing */
	if (!config.snapshot && !ofs->config.snapshot)
		goto out_free_config;

	/* If options did not have snapshot= - do not change snapshot */
	if (config.snapshot && !*config.snapshot)
		goto same_snapshot;

	pr_debug("%s: old snapshot='%s' sid='%s'\n", __func__,
		 ofs->config.snapshot,
		 ofs->snap_mnt ? ofs->snap_mnt->mnt_sb->s_id : "");

	if (config.snapshot) {
		err = ovl_snapshot_dir(sb, ofs, config.snapshot, &snappath);
		if (err)
			goto out_free_config;

		/* The same snapshot path may be a new overlay mount */
		if (ofs->snap_mnt &&
		    ofs->snap_mnt->mnt_sb == snappath.mnt->mnt_sb)
			goto same_snapshot;

		snapmnt = ovl_snapshot_clone_mount(ofs, &snappath);
		if (IS_ERR(snapmnt)) {
			err = PTR_ERR(snapmnt);
			goto out_put_snappath;
		}
	}

	pr_debug("%s: new snapshot='%s' sid='%s'\n", __func__,
		 config.snapshot,
		 snapmnt ? snapmnt->mnt_sb->s_id : "");

	kfree(ofs->config.snapshot);
	ofs->config.snapshot = config.snapshot;
	config.snapshot = NULL;

	/* Set new requested snapshot overlay */
	path_put(&snappath);
	snappath.mnt = ofs->snap_mnt;
	snappath.dentry = NULL;
	ofs->snap_mnt = snapmnt;

same_snapshot:
	/*
	 * remount ro=>* and *=>ro can set effective snapshot now.
	 * remount rw=>rw will set effective snapshot on next remount ro.
	 */
	if ((sb->s_flags & MS_RDONLY) || (*flags & MS_RDONLY))
		ovl_snapshot_barrier(sb);

out_put_snappath:
	path_put(&snappath);
out_free_config:
	kfree(config.snapshot);
	kfree(config.lowerdir);
	kfree(config.upperdir);
	kfree(config.workdir);
	return err;
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
 * shared between snapshot mount and overlayfs mount.
 */

/*
 * Return snapshot overlay dentry associated with a snapshot mount dentry
 * with elevated refcount if it is valid or error if snapshot mount dentry
 * should be revalidated.
 * If a snapshot mount dentry is used after snapshot take without being
 * revalidated this function may return ESTALE/ENOENT.
 */
struct dentry *ovl_snapshot_dentry(struct dentry *dentry)
{
	struct path snappath = { };
	int err;

	/* Not a snapshot mount */
	if (!ovl_is_snapshot_fs_type(dentry->d_sb))
		return NULL;

	err = ovl_snapshot_path(dentry, &snappath);
	if (err)
		return ERR_PTR(err);

	/*
	 * If snapentry is root, but dentry is not, that indicates that
	 * snapentry is nested inside an already whited out directory,
	 * so need to do nothing about it.
	 */
	if (snappath.dentry && IS_ROOT(snappath.dentry) && !IS_ROOT(dentry)) {
		path_put(&snappath);
		return NULL;
	}

	mntput(snappath.mnt);
	return snappath.dentry;
}

/*
 * Verify that found overlay snapshot dentry in sane -
 * If the snapshot overlay dentry is a merge/lower dir, then its lower dentry
 * should be pointing back to the snapshot mount upper dentry.
 * If the snapshot overlay dentry is non-opaque negative (i.e. not a whiteout),
 * then the snapshot mount should be also negative (i.e. no upper).
 * Otherwise, this may be a stray redirect that is pointing the snapshot mount
 * at the wrong path in overlay snapshot.
 *
 * Return 0 for sane, < 0 for inconsitency
 */
int ovl_snapshot_verify(struct ovl_fs *ofs, struct dentry *snapdentry,
			struct dentry *upperdentry, char *redirect)
{
	enum ovl_path_type snaptype;
	int err = 0;

	/* Redirect should not be pointing at disconnected snapshot path */
	if (!snapdentry || IS_ROOT(snapdentry))
		goto no_redirect;

	/* Redirect should not be pointing at negative */
	if (!snapdentry->d_inode) {
		if (!ovl_dentry_is_opaque(snapdentry)) {
			if (!upperdentry)
				return 0;
			/* Either a stale redirect or inconsitency */
			err = -ENOENT;
		}
		goto no_redirect;
	}

	/* Redirect should not be pointing at non-dir */
	if (!upperdentry || !d_is_dir(upperdentry) || !d_is_dir(snapdentry))
		goto no_redirect;

	/* Redirect should not be pointing at non-merge upper */
	snaptype = ovl_path_type(snapdentry);
	if (OVL_TYPE_UPPER(snaptype) && !OVL_TYPE_MERGE(snaptype))
		goto no_redirect;

	/* Lower/merge dir should point back at the redirecting upper */
	if (ovl_dentry_lower(snapdentry) != upperdentry)
		goto no_redirect;

	return 0;

no_redirect:
	/* Clear stale redirect if exists and return ESTALE to retry lookup */
	if (redirect && upperdentry) {
		err = mnt_want_write(ofs->upper_mnt);
		if (!err) {
			err = ovl_do_removexattr(upperdentry,
						 OVL_XATTR_REDIRECT);
			mnt_drop_write(ofs->upper_mnt);
		}
		if (!err)
			err = -ESTALE;
	} else if (err && snapdentry) {
		/* We cannot recover from this lookup error */
		pr_warn_ratelimited("%s(%pd2): is_dir=%d, negative=%d, snap_is_dir=%d, snap_negative=%d, err=%i\n",
				    __func__, snapdentry,
				    upperdentry && d_is_dir(upperdentry),
				    !upperdentry, d_is_dir(snapdentry),
				    d_is_negative(snapdentry), err);
	}
	return err;
}

/*
 * Lookup the overlay snapshot dentry in the same path as the looked up
 * snapshot mount dentry. We need to hold a reference to a negative snapshot
 * dentry for explicit whiteout before create in snapshot mount and we need
 * to hold a reference to positive non-dir snapshot dentry even if snapshot
 * mount dentry is a directory, so we know that we don't need to copy up the
 * snapshot mount directory children.
 */
int ovl_snapshot_lookup(struct dentry *parent, struct ovl_lookup_data *d,
			struct dentry **ret)
{
	struct path snappath;
	struct dentry *snapdentry = NULL;
	int err;

	err = ovl_snapshot_path(parent, &snappath);
	if (unlikely(err))
		return err;

	/* No parent snapshot dentry means no active snapshot overlay */
	if (!snappath.dentry)
		goto out;

	/*
	 * When parent's snapshot dentry is negative or non-dir or when its
	 * lower dir is not the snapshot mount parent's upper, point the
	 * snapdentry to the snapshot overlay root. This is needed to
	 * indicate this special case and to access snapshot overlay sb.
	 */
	if (!d_can_lookup(snappath.dentry) ||
	    ovl_dentry_lower(snappath.dentry) != ovl_dentry_upper(parent)) {
		snapdentry = dget(snappath.mnt->mnt_root);
		goto out;
	}

	err = ovl_lookup_layer(snappath.dentry, d, &snapdentry);

out:
	path_put(&snappath);
	*ret = snapdentry;
	return err;
}

/*
 * Copy on write to snapshot if needed before file is modified.
 */
static int ovl_snapshot_copy_up(struct dentry *dentry)
{
	struct inode *inode = d_inode(dentry);
	struct dentry *snap = ovl_snapshot_dentry(dentry);
	int err = 0;

	/*
	 * Snapshot dentry may be positive or negative or NULL.
	 * If positive, it may need to be copied down.
	 * If negative, it should be a whiteout.
	 * If NULL, it may be an uninitialized snapdentry after snapshot take,
	 * or it can also be that the snapshot dentry is nested inside an
	 * already whited out directory. Either way, we do nothing about it.
	 */
	if (!snap)
		return 0;

	if (unlikely(IS_ERR(snap))) {
		err = PTR_ERR(snap);
		snap = NULL;
		goto bug;
	}

	if (d_is_negative(snap)) {
		if (WARN_ON(!ovl_dentry_is_opaque(snap)))
			goto bug;
		goto out;
	}

	if (ovl_dentry_upper(snap) && ovl_dentry_has_upper_alias(snap))
		goto out;

	/* Trigger 'copy down' to snapshot */
	err = ovl_want_write(snap);
	if (err)
		goto bug;
	err = ovl_copy_up(snap);
	ovl_drop_write(snap);
	if (err)
		goto bug;

out:
	dput(snap);
	return 0;

bug:
	pr_warn_ratelimited("overlayfs: failed copy to snapshot (%pd2, ino=%lu, err=%i)\n",
			    dentry, inode ? inode->i_ino : 0, err);
	dput(snap);
	/* Allowing write would corrupt snapshot so deny */
	return -EROFS;
}

static int ovl_snapshot_copy_up_meta(struct dentry *dentry)
{
	struct ovl_fs *ofs = dentry->d_sb->s_fs_info;
	struct dentry *parent;
	int err;

	if (!ofs->config.metacopy || d_is_dir(dentry))
		return ovl_snapshot_copy_up(dentry);

	/* Only copy directory skeleton to snapshot */
	parent = dget_parent(dentry);
	err = ovl_snapshot_copy_up(parent);
	dput(parent);

	return err;
}

/* Explicitly whiteout a negative snapshot mount dentry before create */
static int ovl_snapshot_whiteout(struct dentry *dentry)
{
	struct dentry *parent;
	struct dentry *upperdir;
	struct inode *sdir, *udir;
	struct dentry *whiteout;
	const struct cred *old_cred;
	struct dentry *snap = ovl_snapshot_dentry(dentry);
	int err = 0;

	if (!snap)
		return 0;

	if (unlikely(IS_ERR(snap))) {
		err = PTR_ERR(snap);
		pr_warn_ratelimited("%s(%pd2): err=%i\n", __func__,
				    dentry, err);
		d_drop(dentry);
		return err;
	}

	/* No need to whiteout a positive or whiteout snapshot dentry */
	if (!d_is_negative(snap) || ovl_dentry_is_opaque(snap))
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
		goto out_unlock;
	}

	/*
	 * We could have raced with another task that tested false
	 * ovl_dentry_is_opaque() before udir lock, so if we find a
	 * whiteout all is good.
	 */
	if (!ovl_is_whiteout(whiteout)) {
		err = ovl_do_whiteout(udir, whiteout);
		if (err)
			goto out_dput_whiteout;
	}

	/*
	 * Setting a negative snapshot dentry opaque to signify that
	 * there is no need for explicit whiteout next time.
	 */
	ovl_dentry_set_opaque(snap);
	ovl_dentry_version_inc(parent, true);
out_dput_whiteout:
	dput(whiteout);
out_unlock:
	inode_unlock(udir);
	revert_creds(old_cred);
out_drop_write:
	ovl_drop_write(snap);
	inode_unlock(sdir);
	dput(parent);
out:
	dput(snap);
	return err;
}

int ovl_snapshot_want_write(struct dentry *dentry)
{
	if (!ovl_is_snapshot_fs_type(dentry->d_sb))
		return 0;

	/* Negative dentry may need to be explicitly whited out */
	if (d_is_negative(dentry))
		return ovl_snapshot_whiteout(dentry);

	return ovl_snapshot_copy_up_meta(dentry);
}

void ovl_snapshot_drop_write(struct dentry *dentry)
{
	struct dentry *snap = ovl_snapshot_dentry(dentry);
	struct inode *inode = d_inode(dentry);

	if (unlikely(IS_ERR(snap))) {
		pr_warn_ratelimited("%s(%pd2): err=%i\n", __func__,
				    dentry, (int)PTR_ERR(snap));
		d_drop(dentry);
		return;
	}

	/*
	 * We may have just dropped this dentry, because it was deleted or
	 * renamed over - then snapshot still thinks it has a lower dentry.
	 * Unhash the snapshot dentry as well in this case.
	 */
	if (snap && d_unhashed(dentry)) {
		pr_debug("ovl_snapshot_d_drop(%pd4, %lu): is_dir=%d, negative=%d, unhashed=%d\n",
			dentry, inode ? inode->i_ino : 0, d_is_dir(dentry),
			d_is_negative(dentry), d_unhashed(dentry));
		d_drop(snap);
	}
	dput(snap);
}
