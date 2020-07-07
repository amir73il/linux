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

/*
 * Check if lower dir or its child need to be copied to snapshot.
 *
 * We lookup directory in overlay snapshot whose lower is @lowerdir and
 * we lookup non-directory and negative dentries by @name relative to
 * snapshot's parent directory.
 *
 * Returns error if failed to lookup overlay snapshot dentry.
 * Returns NULL if found an opaque or pure upper snapshot dentry.
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

	/* Pure upper in snapshot returns NULL for noop */
	if (!d_is_dir(snap) || !ovl_dentry_lower(snap))
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
 * Mark change in snapshot if needed before file is modified.
 */
static int ovl_handle_pre_modify(struct super_block *sb, struct dentry *lowerdir,
				 const struct qstr *name)
{
	const char *fname = name ? name->name : (void *)"";
	struct inode *inode = d_inode(lowerdir);
	struct dentry *snap = NULL;
	int err = -ENOENT;

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
		if (!err || err == -ENOENT || err == -ESTALE || err == -EXDEV)
			goto out;

		goto bug;
	}

	if (d_is_negative(snap)) {
		/* TODO: whiteout in snapshot before creating lower */
		err = -ENOENT;
		goto bug;
	}

	if (ovl_dentry_has_upper_alias(snap)) {
		/* TODO: set upper dir opaque before creating lower */
		err = 0;
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
	pr_debug("%s: %pd2/%s %s in snapshot (err=%i)\n", __func__, lowerdir, fname,
		 !snap ? (!err ? "is already" : "noop") :
		 d_is_negative(snap) ? "whiteout created" : "created", err);
	dput(snap);

	return 0;

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


static int ovl_handle_event(struct fsnotify_group *group, u32 mask,
			    const void *data, int data_type, struct inode *dir,
			    const struct qstr *name, u32 cookie,
			    struct fsnotify_iter_info *iter_info)
{
	struct super_block *sb = group->private;
	const struct path *lowerpath = fsnotify_data_path(data, data_type);
	struct dentry *lowerdir = NULL;
	int err = 0;

	/* Should be no events from inode/mount marks */
	if (WARN_ON_ONCE(fsnotify_iter_inode_mark(iter_info)) ||
	    WARN_ON_ONCE(fsnotify_iter_vfsmount_mark(iter_info)))
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
		err = ovl_handle_pre_modify(sb, lowerdir, name);
		/* TODO: add inode mark on lowerdir with ignore mask */
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
