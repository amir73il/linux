// SPDX-License-Identifier: GPL-2.0-only
/*
 * Overlayfs change tracking snapshot.
 *
 * Amir Goldstein <amir73il@gmail.com>
 *
 * Copyright (C) 2020 CTERA Networks. All Rights Reserved.
 */

#include <linux/fs.h>
#include <linux/fsnotify.h>
#include <linux/namei.h>
#include <linux/ratelimit.h>
#include "overlayfs.h"

/* Check if lowerdir was deleted/renamed since copied up to snapshot */
static bool ovl_snapshot_verify_origin(struct dentry *snap)
{
	struct ovl_entry *oe = snap->d_fsdata;
	struct ovl_path *lower = oe->lowerstack;

	/* Pure upper dir in snapshot means that lower was deleted/renamed */
	if (!oe->numlower)
		return false;

	if (lower->hash != lower->dentry->d_name.hash_len)
		return false;

	return true;
}

/*
 * Check if lower dir or its child need to be copied to snapshot.
 *
 * We lookup directory in overlay snapshot whose lower is @lowerdir and
 * we lookup non-directory and negative dentries by @name relative to
 * snapshot's parent directory.
 *
 * Returns error if failed to lookup overlay snapshot dentry.
 * Returns NULL if found an opaque snapshot dentry.
 * Returns NULL if found a verified merged dir snapshot dentry.
 * Returns the found overlay snapshot dentry otherwise.
 */
static struct dentry *ovl_snapshot_lookup(struct super_block *sb,
					  struct dentry *lowerdir,
					  const struct qstr *name)
{
	const struct cred *old_cred = ovl_override_creds(sb);
	struct dentry *snapdir, *snap = NULL;
	int err;

	/* Find directory whose lower is @lowerdir in overlay snapshot mount */
	snapdir = ovl_lookup_real(sb, lowerdir, &OVL_FS(sb)->layers[1]);
	if (IS_ERR(snapdir)) {
		err = PTR_ERR(snapdir);
		snap = snapdir;
		snapdir = NULL;
		goto out;
	}

	/*
	 * Negative dentries and non-directory dentries cannot be found by lower
	 * inode, so we need to look them up by name after looking up parent by
	 * @lowerdir.
	 */
	if (name) {
		snap = lookup_one_len_unlocked(name->name, snapdir, name->len);
		/* TODO: make sure this does not return the "benign" errors */
		if (IS_ERR(snap))
			goto out;
	} else {
		snap = dget(snapdir);
	}

	/* Whiteout/opaque in snapshot returns NULL for noop */
	if (ovl_dentry_is_opaque(snap))
		goto noop;

	/*
	 * Return negative snapshot dentry to be whited out in snapshot
	 * and non-upper snapshot dentry to be copied up.
	 */
	if (d_is_negative(snap) || !ovl_dentry_has_upper_alias(snap))
		goto out;

	/* Copied up non-dir and verified merged dir return NULL for noop */
	if (!d_is_dir(snap) || ovl_snapshot_verify_origin(snap))
		goto noop;

out:
	dput(snapdir);
	revert_creds(old_cred);

	return snap;

noop:
	dput(snap);
	snap = NULL;
	goto out;
}

/*
 * Explicitly whiteout a negative overlay snapshot dentry before creating
 * a lower object.
 */
static int ovl_snapshot_whiteout(struct dentry *snap)
{
	struct dentry *parent = dget_parent(snap);
	struct path upperpath;
	struct dentry *whiteout = NULL;
	struct inode *udir, *sdir = parent->d_inode;
	const struct cred *old_cred = NULL;
	int err = 0;

	inode_lock_nested(sdir, I_MUTEX_PARENT);

	err = ovl_want_write(snap);
	if (err)
		goto out;

	err = ovl_copy_up(parent);
	if (err)
		goto out_drop_write;

	ovl_path_upper(parent, &upperpath);
	udir = upperpath.dentry->d_inode;
	old_cred = ovl_override_creds(snap->d_sb);
	inode_lock_nested(udir, I_MUTEX_PARENT);

	whiteout = lookup_one_len(snap->d_name.name, upperpath.dentry,
				  snap->d_name.len);
	if (IS_ERR(whiteout)) {
		err = PTR_ERR(whiteout);
		whiteout = NULL;
		goto out_unlock_udir;
	}

	/*
	 * We could have raced with another task that tested false
	 * ovl_dentry_is_opaque() before udir lock, so if we find a whiteout
	 * all is good.
	 *
	 * If snapshot upper dir and lower dir are on the same filesystem and
	 * that filesystem metadata is journaled and strictly ordered, there
	 * is no need to fsync the snapshot upper dir before proceeding with
	 * create of lower object.  For other setups, the 'dirsync' mount option
	 * for the overlay snapshot mount can be used to request explicit fsync
	 * of the whiteout marker before lower object create.
	 */
	if (!ovl_is_whiteout(whiteout)) {
		err = ovl_do_whiteout(udir, whiteout);
		if (!err && IS_DIRSYNC(sdir))
			err = ovl_fsync_upperdir(&upperpath);
		if (err)
			goto out_unlock_udir;
	}

	/*
	 * Setting a negative overlay snapshot dentry opaque to signify that
	 * lower is going to be positive and invalidate parent's readdir cache.
	 */
	ovl_dentry_set_opaque(snap);
	ovl_dir_modified(parent, true);

out_unlock_udir:
	inode_unlock(udir);
	revert_creds(old_cred);
out_drop_write:
	ovl_drop_write(snap);
out:
	inode_unlock(sdir);
	dput(whiteout);
	dput(parent);
	return err;
}

/*
 * Explicitly set a merged overlay snapshot directory opaque before creating
 * a lower object.
 */
static int ovl_snapshot_set_opaque(struct dentry *snap)
{
	struct path upperpath;
	struct inode *sdir = snap->d_inode;
	const struct cred *old_cred = NULL;
	int err = 0;

	inode_lock(sdir);

	/* Raced with another set opaque? */
	if (ovl_dentry_is_opaque(snap))
		goto out;

	err = ovl_want_write(snap);
	if (err)
		goto out;

	ovl_path_upper(snap, &upperpath);
	old_cred = ovl_override_creds(snap->d_sb);
	err = ovl_check_setxattr(snap, upperpath.dentry, OVL_XATTR_OPAQUE,
				 "y", 1, -EIO);
	if (!err)
		err = ovl_fsync_upperdir(&upperpath);
	/*
	 * Setting dentry OPAQUE flag only *after* fsync, because a parallel
	 * ovl_handle_pre_modify() MUST NOT find this dentry opaque and skip
	 * ovl_snapshot_set_opaque() unless the opaque xattr is safe on disk.
	 *
	 * For example: directory A is renamed to X, file X/B/C/F is modified
	 * and not marked in snapshot (because a is under a whiteout). Then X
	 * is renamed back to A by thread 1, which gets here and waits on fsync.
	 * Thread 2 tries to write to file A/B/C/F.  If it finds the snapshot
	 * dentry is opaque, it will be able to modify file before fsync of
	 * thread 1 has completed and file F data may hit the disk before the
	 * OPAQUE xattr does. That will make directory A look like it has no
	 * changes in its tree after a crash, while actually the file A/B/C/F
	 * data was in fact modified.
	 */
	if (!err)
		ovl_dentry_set_opaque(snap);
	ovl_dir_modified(snap, true);

	revert_creds(old_cred);
	ovl_drop_write(snap);
out:
	inode_unlock(sdir);

	return err;
}

/*
 * Mark change in snapshot if needed before file is modified.
 *
 * Returns 0 if change is marked snapshot
 * Returns >0 if dir or ancestor are opaque in snapshot
 * Returns <0 on failure to mark the change in snapshot
 */
static int ovl_handle_pre_modify(struct super_block *sb, struct dentry *lowerdir,
				 const struct qstr *name)
{
	const char *fname = name ? name->name : (void *)"";
	struct inode *inode = d_inode(lowerdir);
	struct dentry *snap = NULL;
	int err = -ENOENT;
	int ret = 0;

	/* Pre-modify event on disconnected parent is unexpected */
	if (WARN_ON(lowerdir->d_flags & DCACHE_DISCONNECTED))
		goto bug;

	snap = ovl_snapshot_lookup(sb, lowerdir, name);
	/*
	 * Overlay snapshot dentry may be positive or negative or NULL.
	 * If positive, it may need to be copied up.
	 * If negative, it may need to be whited out.
	 * If overlay snapshot dentry is already copied up or whiteout or if it
	 * is an ancestor of an already whited out directory, we need to do
	 * nothing about it.
	 */
	if (IS_ERR_OR_NULL(snap)) {
		err = PTR_ERR(snap);
		snap = NULL;
		/*
		 * ENOENT - parent is whiteout in snapshot?
		 * ESTALE - origin mismatch in snapshot?
		 * EXDEV  - lowerdir is not under overlay lower layer root?
		 */
		ret = -err;
		if (!err || err == -ENOENT || err == -ESTALE || err == -EXDEV)
			goto out;

		goto bug;
	}

	if (d_is_negative(snap)) {
		/*
		 * That is an unexpected result for lookup of directory, because
		 * if we raced with rename of directory, the pre modify events
		 * generated by that rename should have made the snapshot dentry
		 * either positive or whiteout.
		 */
		err = -ENOENT;
		if (WARN_ON_ONCE(!name))
			goto bug;

		/* Whiteout in snapshot before creating lower */
		err = ovl_snapshot_whiteout(snap);
		if (err)
			goto bug;

		goto out;
	}

	if (ovl_dentry_has_upper_alias(snap)) {
		err = 0;
		/*
		 * The snapshot dentry is expected to be a merged directory,
		 * because a "copied up" non-dir is supposed to be pure upper
		 * and return NULL (noop) from ovl_snapshot_lookup(), but we
		 * could have raced with another pre modify event that has
		 * beat us to copy up of non-dir.  In any case, there is
		 * nothing left to do for a "copied up" non-dir.
		 */
		if (!d_is_dir(snap))
			goto out;

		/*
		 * On pre modify event, we need to make a pure upper directory
		 * opaque before creating lower.
		 */
		err = ovl_snapshot_set_opaque(snap);
		if (err)
			goto bug;

		err = -EEXIST;
		goto out;
	}

	err = ovl_want_write(snap);
	if (err)
		goto bug;

	/*
	 * Create directory or empty file in overlay snapshot.
	 * With overlay snapshot, file is not copied up, only an empty file or
	 * its parent dir, so there is no fsync in copy up.  We need to make
	 * sure that the change markers are persistent on-disk before making
	 * the modification to make sure that we will find them after a crash.
	 * Use the OVL_SYNC_DIRECTORY flag combination to request fsync of
	 * parent before a parallel thread can find that the overlay dentry is
	 * ovl_already_copied_up().
	 */
	err = ovl_copy_up_flags(snap, O_TRUNC | OVL_SYNC_DIRECTORY);
	ovl_drop_write(snap);
	if (err)
		goto bug;

out:
	pr_debug("%s: %pd2/%s %s in snapshot (ret=%i)\n", __func__, lowerdir, fname,
		 !snap ? (!err ? "is already" : "noop") :
		 d_is_negative(snap) ? "whiteout created" :
		 err ? "set opaque" : "created", ret);
	dput(snap);

	return ret;

bug:
	pr_warn_ratelimited("failed copy to snapshot (%pd2/%s ino=%lu, err=%i)\n",
			    lowerdir, fname, inode ? inode->i_ino : 0, err);
	dput(snap);

	/* Allowing write would corrupt snapshot so deny */
	return -EPERM;
}

#define OVL_FSNOTIFY_MASK (FS_PRE_MODIFY | FS_PRE_MODIFY_NAME)

static struct kmem_cache *ovl_mark_cachep;

struct ovl_mark {
	struct fsnotify_mark fsn_mark;
	/* TBD */
};


static void ovl_add_ignored_mark(struct fsnotify_group *group,
				 struct dentry *lowerdir, u32 mask)
{
	struct inode *inode = d_inode(lowerdir);
	struct ovl_mark *ovm;
	int err = -ENOMEM;

	ovm = kmem_cache_alloc(ovl_mark_cachep, GFP_KERNEL);
	if (!ovm)
		goto out;

	pr_debug("%s: %pd2 group=%p mark=%p mask=%x\n", __func__,
		 lowerdir, group, ovm, mask);

	fsnotify_init_mark(&ovm->fsn_mark, group);
	/* Set the mark mask, so fsnotify_parent() will find this mark */
	ovm->fsn_mark.mask = mask | FS_EVENT_ON_CHILD;
	ovm->fsn_mark.ignored_mask = mask;
	ovm->fsn_mark.flags = FSNOTIFY_MARK_FLAG_IGNORED_SURV_MODIFY;
	err = fsnotify_add_mark(&ovm->fsn_mark, &inode->i_fsnotify_marks,
				FSNOTIFY_OBJ_TYPE_INODE,
				FSNOTIFY_ADD_MARK_NO_IREF, NULL);
	fsnotify_put_mark(&ovm->fsn_mark);

out:
	if (!err)
		return;

	/* Adding ignored mask is an optimization so just warn */
	pr_warn_ratelimited("failed add ignored mask (%pd2 ino=%lu, err=%i)\n",
			    lowerdir, inode ? inode->i_ino : 0, err);
}

static int ovl_handle_event(struct fsnotify_group *group, u32 mask,
			    const void *data, int data_type, struct inode *dir,
			    const struct qstr *name, u32 cookie,
			    struct fsnotify_iter_info *iter_info)
{
	struct super_block *sb = group->private;
	const struct path *lowerpath = fsnotify_data_path(data, data_type);
	struct dentry *lowerdir = NULL;
	int err = 0;

	/* Should be no events from mount marks */
	if (WARN_ON_ONCE(fsnotify_iter_vfsmount_mark(iter_info)))
		return 0;

	if (WARN_ON(!(mask & OVL_FSNOTIFY_MASK)) || !lowerpath)
		return 0;

	/* Don't handle events before overlay mount is done */
	if (!(sb->s_flags & SB_BORN))
		return 0;
	smp_rmb();

	if (mask & FS_PRE_MODIFY_NAME) {
		/*
		 * We get here from a call to either mnt_want_write_name() or
		 * mnt_want_write_rename() (i.e. link or unlink an entry) -
		 * record change in dir/name.
		 */
		lowerdir = dget(lowerpath->dentry);
		WARN_ON_ONCE(d_inode(lowerdir) != dir);
		WARN_ON_ONCE(!name);

		pr_debug("%s: %pd2/%s mask=%x\n", __func__, lowerdir, name->name, mask);
	} else if (mask & FS_PRE_MODIFY) {
		/*
		 * Event is on dir itself or on a non-dir child -
		 * record change in dir (without name).
		 *
		 * We get here from a call to either file_start_write() or
		 * mnt_want_write_path().
		 *
		 * If event in on a non-dir child, we need to get the unstable
		 * parent because event data is the path to the non-dir child,
		 * not to the parent.
		 *
		 * If a rename came in between the pre-modify event and now and
		 * moved child away from its parent, the rename itself should
		 * have generated pre-modify events that would have already
		 * recorded the change in the old and new parents, so it does
		 * not matter if we get the old or new parent.
		 */
		lowerdir = (mask & FS_ISDIR) ? dget(lowerpath->dentry) :
					       dget_parent(lowerpath->dentry);
		name = NULL;
		/* Not interested in events from non-dir with no parent */
		if (unlikely(!d_is_dir(lowerdir)))
			goto out;

		pr_debug("%s: %pd2 mask=%x\n", __func__, lowerdir, mask);
	}

	if (lowerdir) {
		u32 ignored = FS_PRE_MODIFY;

		err = ovl_handle_pre_modify(sb, lowerdir, name);
		if (err < 0)
			goto out;

		/*
		 * Add inode mark on lowerdir with ignored mask.
		 * If lowerdir is copied to snapshot ignore only FS_PRE_MODIFY.
		 * If lowerdir or an ancestor is opaque in snapshot, ignore also
		 * FS_PRE_MODIFY_NAME, because children do not need to and
		 * cannot be marked in snapshot.
		 */
		if (err > 0)
			ignored |= FS_PRE_MODIFY_NAME;

		/*
		 * Do not add ignored mask without FS_PRE_MODIFY_NAME from an
		 * FS_PRE_MODIFY_NAME event, because we will keep getting those
		 * events after adding the mark and will keep getting -EEXIST on
		 * attempt to re-add the mark.
		 */
		if (!(mask & ~ignored & OVL_FSNOTIFY_MASK))
			ovl_add_ignored_mark(group, lowerdir, ignored);
		err = 0;
	}

out:
	dput(lowerdir);

	return err;
}

static int ovl_add_sb_mark(struct fsnotify_group *group,
			   struct super_block *lowersb)
{
	struct ovl_mark *ovm;
	int err;

	ovm = kmem_cache_alloc(ovl_mark_cachep, GFP_KERNEL);
	if (!ovm)
		return -ENOMEM;

	fsnotify_init_mark(&ovm->fsn_mark, group);
	ovm->fsn_mark.mask = OVL_FSNOTIFY_MASK;
	err = fsnotify_add_mark(&ovm->fsn_mark, &lowersb->s_fsnotify_marks,
				FSNOTIFY_OBJ_TYPE_SB, 0, NULL);
	fsnotify_put_mark(&ovm->fsn_mark);

	return err;
}

static void ovl_free_mark(struct fsnotify_mark *mark)
{
	struct ovl_mark *ovm = container_of(mark, struct ovl_mark, fsn_mark);

	pr_debug("%s: group=%p mark=%p\n", __func__, mark->group, ovm);

	kmem_cache_free(ovl_mark_cachep, ovm);
}

static const struct fsnotify_ops ovl_fsnotify_ops = {
	.handle_event = ovl_handle_event,
	.free_mark = ovl_free_mark,
};

int ovl_get_watch(struct super_block *sb, struct ovl_fs *ofs)
{
	struct fsnotify_group *group;
	int err;

	group = fsnotify_alloc_group(&ovl_fsnotify_ops);
	if (IS_ERR(group)) {
		pr_err("failed to allocate fsnotify group\n");
		return PTR_ERR(group);
	}

	ofs->watch = group;
	group->private = sb;

	/* Create a mark on lower fs */
	err = ovl_add_sb_mark(group, ofs->layers[1].fs->sb);

	if (err)
		pr_err("failed to add fsnotify sb mark (err=%i)\n", err);

	return err;
}

void ovl_free_watch(struct ovl_fs *ofs)
{
	if (!ofs->watch)
		return;

	/* Wait for in-flight events, then free all marks and group */
	fsnotify_destroy_group(ofs->watch);
	ofs->watch = NULL;
}

int __init ovl_fsnotify_init(void)
{
	ovl_mark_cachep = KMEM_CACHE(ovl_mark, 0);
	if (!ovl_mark_cachep)
		return -ENOMEM;

	return 0;
}

void ovl_fsnotify_destroy(void)
{
	kmem_cache_destroy(ovl_mark_cachep);
}
