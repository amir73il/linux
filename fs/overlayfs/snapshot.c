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
#include <linux/file.h>
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
	/* Keep last */
	OVL_SNAP_ID_SHIFT
};

static unsigned long ovl_snapshot_get_id(struct dentry *dentry)
{
	return READ_ONCE(OVL_E(dentry)->snapflags) >> OVL_SNAP_ID_SHIFT;
}

static void ovl_snapshot_reset_id(struct dentry *dentry, unsigned long id)
{
	/* Set new snapshot id and reset flags */
	WRITE_ONCE(OVL_E(dentry)->snapflags, id << OVL_SNAP_ID_SHIFT);
}

/*
 * Test dcache snapflag which is relevant for snapshot @id.
 * If cached snapid differs from @id we have no flags info.
 */
static bool ovl_snapshot_test_flag(int nr, struct dentry *dentry,
				   unsigned long id)
{
	unsigned long oldid = ovl_snapshot_get_id(dentry);

	if (WARN_ON(nr >= OVL_SNAP_ID_SHIFT) || oldid != id)
	    return false;

	/*
	 * To avoid spin_lock and smp_mb, check that the cached flags refer to
	 * snapshot @id before and after test_bit.
	 */
	return test_bit(nr, &OVL_E(dentry)->snapflags) &&
		ovl_snapshot_get_id(dentry) == id;
}

/*
 * Set dcache snapflag which is relevant for snapshot @id.
 * Invalidate existing cache of older snapid.
 * snapshot id 0 means set the flag without checking nor
 * invalidating cached snapid.
 */
static void ovl_snapshot_set_flag(int nr, struct dentry *dentry,
				  unsigned long id)
{
	unsigned long oldid;

	spin_lock(&dentry->d_lock);

	oldid = ovl_snapshot_get_id(dentry);
	/* Reset existing cached flags if cached snapid is older */
	if (id && oldid < id)
		ovl_snapshot_reset_id(dentry, id);

	/* Discard set flag request if cached snapid is newer */
	if (!id || oldid <= id) {
		smp_mb__before_atomic();
		set_bit(nr, &OVL_E(dentry)->snapflags);
	}

	spin_unlock(&dentry->d_lock);
}

static struct vfsmount *ovl_snapshot_mntget(struct dentry *dentry,
					    unsigned long *snapid)
{
	struct ovl_snap *snap;
	struct vfsmount *snapmnt = NULL;

	rcu_read_lock();
	snap = rcu_dereference(OVL_FS(dentry->d_sb)->snap);
	if (!WARN_ON(!snap)) {
		snapmnt = mntget(snap->mnt);
		*snapid = snap->id;
	}
	rcu_read_unlock();

	return snapmnt;
}

static bool ovl_snapshot_need_cow(struct dentry *dentry, unsigned long id)
{
	return !ovl_snapshot_test_flag(OVL_SNAP_NOCOW, dentry, id);
}

static bool ovl_snapshot_children_need_cow(struct dentry *dentry,
					   unsigned long id)
{
	return !ovl_snapshot_test_flag(OVL_SNAP_CHILDREN_NOCOW, dentry, id);
}

static void ovl_snapshot_set_nocow(struct dentry *dentry, unsigned long id)
{
	ovl_snapshot_set_flag(OVL_SNAP_NOCOW, dentry, id);
}

static void ovl_snapshot_set_children_nocow(struct dentry *dentry,
					    unsigned long id)
{
	ovl_snapshot_set_flag(OVL_SNAP_CHILDREN_NOCOW, dentry, id);
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
	unsigned long snapid;
	struct vfsmount *snapmnt = ovl_snapshot_mntget(dentry, &snapid);
	bool is_dir = d_is_dir(dentry);
	struct dentry *dir = is_dir ? dentry : parent;
	const struct qstr *name = &dentry->d_name;
	struct dentry *snapdir = NULL;
	struct dentry *snap = NULL;
	const struct cred *old_cred = NULL;
	int err;

	if (!snapmnt || !ovl_snapshot_need_cow(dentry, snapid))
		goto out;

	err = ovl_inode_lock_interruptible(d_inode(dir));
	if (err) {
		snap = ERR_PTR(err);
		goto out;
	}

	if (!ovl_snapshot_need_cow(dentry, snapid))
		goto out_unlock;

	if (!is_dir && !ovl_snapshot_children_need_cow(parent, snapid)) {
		ovl_snapshot_set_nocow(dentry, snapid);
		goto out_unlock;
	}

	/*
	 * dentry may be nagative in pre create hook and may be unhashed
	 * in post delete hook. In both cases, find the snapshot dentry and
	 * return it to the caller without setting NOCOW flags.
	 */
	if (OVL_FS(dentry->d_sb)->config.metacopy && !is_dir &&
	    !d_is_negative(dentry) && !d_unhashed(dentry) &&
	    !ovl_snapshot_need_cow(parent, snapid)) {
		/* Only copy directory skeleton to snapshot */
		ovl_snapshot_set_nocow(dentry, snapid);
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
			ovl_snapshot_set_nocow(dentry, snapid);
			ovl_snapshot_set_children_nocow(dir, snapid);
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
		ovl_snapshot_set_nocow(dentry, snapid);
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

/*
 * Make the new snapshot requested in remount effective.
 */
static void ovl_snapshot_barrier(struct super_block *sb)
{
	struct ovl_fs *ofs = sb->s_fs_info;
	struct ovl_snap *oldsnap;

	if (!ofs->new_snap)
		return;

	pr_info("%s: old snap id=%lu, new snap id=%lu\n",
		__func__, ofs->snap ? ofs->snap->id : 0,
		ofs->new_snap ? ofs->new_snap->id : 0);

	oldsnap = ofs->snap;
	rcu_assign_pointer(ofs->snap, ofs->new_snap);
	ofs->new_snap = NULL;
	/* wait grace period before dropping oldsnap->mnt refcount */
	synchronize_rcu();
	ovl_snap_free(oldsnap);
}

static int ovl_snapshot_remount(struct super_block *sb, int *flags, char *data);

static int ovl_snapshot_freeze(struct super_block *sb)
{
	return freeze_super(ovl_upper_mnt(OVL_FS(sb))->mnt_sb);
}

static int ovl_snapshot_unfreeze(struct super_block *sb)
{
	/* Make requested snapshot effective before thawing fs */
	ovl_snapshot_barrier(sb);

	return thaw_super(ovl_upper_mnt(OVL_FS(sb))->mnt_sb);
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
	.freeze_fs	= ovl_snapshot_freeze,
	.unfreeze_fs	= ovl_snapshot_unfreeze,
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
	/* End of mount options that can be changed on remount */
	OPT_REMOUNT_LAST,
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
		if (remount && token >= OPT_REMOUNT_LAST)
			continue;

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

static struct ovl_snap *ovl_get_snapshot(struct ovl_fs *ofs,
					 const char *snapshot, unsigned long id)
{
	struct super_block *snapsb;
	struct path snappath = { };
	struct ovl_snap *snap = NULL;
	char *tmp = NULL;
	int err;

	err = -ENOMEM;
	snap = kzalloc(sizeof(struct ovl_snap), GFP_KERNEL);
	if (!snap)
		goto out_err;

	snap->id = id;

	if (!snapshot)
		return snap;

	tmp = kstrdup(snapshot, GFP_KERNEL);
	if (!tmp)
		goto out_err;

	ovl_unescape(tmp);
	err = ovl_mount_dir_noesc(snapshot, &snappath);
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

	snap->mnt = clone_private_mount(&snappath);
	err = PTR_ERR(snap->mnt);
	if (IS_ERR(snap->mnt)) {
		pr_err("failed to clone snapshot path\n");
		goto out_err;
	}

out:
	path_put(&snappath);
	kfree(tmp);
	return snap;

out_err:
	kfree(snap);
	snap = ERR_PTR(err);
	goto out;
}

static int ovl_snapshot_fill_super(struct super_block *sb, const char *dev_name,
				   char *opt)
{
	struct path upperpath = { };
	struct dentry *root_dentry;
	struct ovl_snap *snap;
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

	err = ovl_snapshot_parse_opt(opt, &ofs->config, false);
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

	snap = ovl_get_snapshot(ofs, ofs->config.snapshot, 0);
	err = PTR_ERR(snap);
	if (IS_ERR(snap))
		goto out_err;

	ofs->snap = snap;

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

	ovl_snapshot_set_nocow(root_dentry, 0);
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

static int ovl_snapshot_remount(struct super_block *sb, int *flags, char *data)
{
	struct ovl_fs *ofs = sb->s_fs_info;
	struct ovl_snap *oldsnap, *snap;
	struct ovl_config config = { };
	int err;

	if (!data)
		return 0;

	pr_debug("%s: '%s'\n", __func__, (char *)data);

	/*
	 * Set config.snapshot to an empty string and parse remount options.
	 * If no new snapshot= option nor nosnapshot option was found,
	 * config.snapshot will remain an empty string and nothing will change.
	 * If snapshot= option will set a new config.snapshot value or
	 * nosnapshot option will free the empty string, then we will change
	 * the requested snapshot overlay to the new one or to no snapshot.
	 */
	if (ofs->config.snapshot) {
		config.snapshot = kstrdup("", GFP_KERNEL);
		if (!config.snapshot)
			return -ENOMEM;
	}

	err = ovl_snapshot_parse_opt((char *)data, &config, true);
	if (err)
		goto out;

	/*
	 * If parser did not change empty string or if parser found
	 * 'nosnapshot' and there is no snapshot - do nothing
	 */
	if ((config.snapshot && !*config.snapshot) ||
	    (!config.snapshot && !ofs->config.snapshot))
		goto nochange;

	snap = ovl_get_snapshot(ofs, config.snapshot, ofs->snap->id + 1);
	err = PTR_ERR(snap);
	if (IS_ERR(snap))
		goto out;

	err = 0;
	/* Did anything change since last requested snapshot? */
	oldsnap = ofs->new_snap ?: ofs->snap;
	if ((!snap->mnt && !oldsnap->mnt) ||
	    (snap->mnt && oldsnap->mnt &&
	     snap->mnt->mnt_sb == oldsnap->mnt->mnt_sb)) {
		/* Nope! */
		ovl_snap_free(snap);
		goto nochange;
	} else {
		pr_info("%s: old snapshot='%s' (%lu), new snapshot='%s' (%lu)\n",
			__func__, ofs->config.snapshot, oldsnap->id,
			config.snapshot, snap->id);
		kfree(ofs->config.snapshot);
		ofs->config.snapshot = config.snapshot;
		config.snapshot = NULL;
		/* Discard old ineffective requested snapshot */
		ovl_snap_free(ofs->new_snap);
		ofs->new_snap = snap;
	}

nochange:
	/*
	 * remount ro=>* and *=>ro can set effective snapshot now.
	 * remount rw=>rw will set effective snapshot on next remount ro.
	 */
	if ((sb->s_flags & SB_RDONLY) || (*flags & SB_RDONLY))
		ovl_snapshot_barrier(sb);

out:
	ovl_free_config(&config);
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
 * With regular snapshot, fsync is done in ovl_copy_up_data() on copy of file
 * to snapshot before writing new file data to disk, so there is no risk of
 * exposing new file data to snapshot.
 *
 * With metacopy snapshot, file is not copied up, only its parent dir, so we
 * need to make sure that copied up parent is persistent on-disk before writing
 * new file data to disk to make sure that after a crash the modification is
 * recorded.
 */
static int ovl_snapshot_fsync_meta(struct dentry *snap)
{
	struct path path;
	struct file *file;
	int err;

	ovl_path_upper(snap, &path);
	file = dentry_open(&path, O_RDONLY, current_cred());
	if (IS_ERR(file))
		return PTR_ERR(file);

	err = vfs_fsync(file, 0);
	fput(file);

	return err;
}

/*
 * Copy to snapshot if needed before file is modified.
 */
static int ovl_snapshot_copy_up(struct dentry *dentry)
{
	struct ovl_fs *ofs = OVL_FS(dentry->d_sb);
	struct inode *inode = d_inode(dentry);
	struct dentry *snap = NULL;
	bool disconnected = dentry->d_flags & DCACHE_DISCONNECTED;
	const struct cred *old_cred;
	int flags = O_WRONLY;
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

	/*
	 * Before a directory is renamed, we usually cover the target with a
	 * whiteout. When directory is exchanged with a file in a metacopy
	 * snapshot, we cover the target with an empty file instead.
	 */
	if (ofs->config.metacopy)
		flags |= O_TRUNC;

	err = ovl_copy_up_flags(snap, flags);
	if (!err && ofs->config.metacopy) {
		old_cred = ovl_override_creds(snap->d_sb);
		err = ovl_snapshot_fsync_meta(snap);
		revert_creds(old_cred);
	}
	ovl_drop_write(snap);
	if (err)
		goto bug;

	/* No need to copy to snapshot next time */
	ovl_snapshot_set_nocow(dentry, 0);
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
static int ovl_snapshot_whiteout(struct dentry *dentry, bool new_is_dir)
{
	struct ovl_fs *ofs = OVL_FS(dentry->d_sb);
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

	/* Only whiteout directories in snapshot */
	if (!new_is_dir && ofs->config.metacopy)
		goto done;

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
	 * lower is going to be positive.
	 */
	ovl_dentry_set_opaque(snap);
	ovl_dir_modified(parent, true);

done:
	if (ofs->config.metacopy) {
		err = ovl_snapshot_fsync_meta(parent);
		if (err)
			goto out_drop_write;
	}

	/*
	 * set dentry flags to suppress copy to snapshot of future object
	 * and possibly its children.
	 */
	ovl_snapshot_set_nocow(dentry, 0);
	ovl_snapshot_set_children_nocow(dentry, 0);

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

static int ovl_snapshot_copy_up_meta(struct dentry *dentry, bool new_is_dir)
{
	struct dentry *parent;
	int err;

	if (d_is_dir(dentry) || new_is_dir ||
	    !OVL_FS(dentry->d_sb)->config.metacopy)
		return ovl_snapshot_copy_up(dentry);

	/* Only copy directory skeleton to snapshot */
	parent = dget_parent(dentry);
	err = ovl_snapshot_copy_up(parent);
	dput(parent);

	return err;
}

int ovl_snapshot_open(struct dentry *dentry, unsigned int flags)
{
	unsigned long snapid;
	struct vfsmount *snapmnt;
	int err = 0;

	/* Prevent copy to snapshot if fs is frozen */
	sb_start_intwrite(dentry->d_sb);

	snapmnt = ovl_snapshot_mntget(dentry, &snapid);
	if (snapmnt && ovl_open_flags_need_copy_up(flags) &&
	    !special_file(d_inode(dentry)->i_mode) &&
	    ovl_snapshot_need_cow(dentry, snapid))
		err = ovl_snapshot_copy_up_meta(dentry, false);

	sb_end_intwrite(dentry->d_sb);

	mntput(snapmnt);
	return err;
}

int ovl_snapshot_pre_modify(struct dentry *dentry, bool new_is_dir)
{
	unsigned long snapid;
	struct vfsmount *snapmnt;
	int err = 0;

	/* Prevent copy to snapshot if fs is frozen */
	sb_start_intwrite(dentry->d_sb);

	snapmnt = ovl_snapshot_mntget(dentry, &snapid);
	if (snapmnt && ovl_snapshot_need_cow(dentry, snapid)) {
		/* Negative dentry may need to be explicitly whited out */
		if (d_is_negative(dentry))
			err = ovl_snapshot_whiteout(dentry, new_is_dir);
		else
			err = ovl_snapshot_copy_up_meta(dentry, new_is_dir);
	}

	sb_end_intwrite(dentry->d_sb);

	mntput(snapmnt);
	return err;
}

void ovl_snapshot_post_modify(struct dentry *dentry)
{
	struct dentry *snap;

	/*
	 * We may have just dropped this dentry, because it was deleted or
	 * renamed over, but snapshot may still think it has a lower dentry.
	 * With metacopy snapshot, the file wasn't copied to snapshot before it
	 * was deleted, so we need to make sure that snapshot lookup of the same
	 * path as this one won't end up finding the stale snapshot dentry.
	 * Find and drop that snapshot dentry.
	 */
	if (d_unhashed(dentry) && !d_is_dir(dentry)) {
		ovl_snapshot_reset_id(dentry, 0);
		snap = ovl_snapshot_dentry(dentry);
		pr_debug("ovl_snapshot: d_unhashed(%pd4), negative=%d\n",
			 dentry, d_is_negative(dentry));
		if (!IS_ERR_OR_NULL(snap)) {
			pr_debug("ovl_snapshot: d_drop(%pd4), is_dir=%d, negative=%d, unhashed=%d\n",
				 snap, d_is_dir(snap), d_is_negative(snap),
				 d_unhashed(snap));
			d_drop(snap);
			dput(snap);
		}
	}
}
