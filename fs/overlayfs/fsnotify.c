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
#include "../mount.h"
#include "overlayfs.h"

#define OVL_FSNOTIFY_MASK (FS_MODIFY_PERM | FS_MODIFY_DIR_PERM)

static struct kmem_cache *ovl_mark_cachep;

struct ovl_mark {
	struct fsnotify_mark fsn_mark;
	/* TBD */
};

static struct dentry *ovl_lookup_lower_unlocked(struct super_block *sb,
						struct dentry *lowerdir,
						const struct qstr *name)
{
	const struct cred *old_cred = ovl_override_creds(sb);
	struct dentry *dentry;

	dentry = lookup_one_len_unlocked(name->name, lowerdir, name->len);
	revert_creds(old_cred);

	return dentry;
}

/*
 * Check if lower dir needs to be indexed.
 *
 * We lookup the @lowerdir index entry.
 * If found negative, we may want to make it positive.
 * If found postive, we may want to make it a whiteout.
 * If found whiteout, we have nothing more to do.
 *
 * Returns error if failed to lookup index entry.
 * Returns NULL if found a whiteout index dentry.
 * Returns the found index entry otherwise.
 */
static struct dentry *ovl_lookup_lowerdir_index(struct super_block *sb,
						struct dentry *lowerdir)
{
	struct ovl_fs *ofs = sb->s_fs_info;
	struct dentry *index;
	struct qstr name;
	int err;

	err = ovl_get_index_name(ofs, lowerdir, &name);
	if (err)
		return ERR_PTR(err);

	index = ovl_lookup_lower_unlocked(sb, ofs->indexdir, &name);
	if (IS_ERR(index)) {
		err = PTR_ERR(index);
		goto fail;
	}

	if (d_is_dir(index) || d_is_negative(index)) {
		/* Return found positive/negative index entry for hit/miss */
	} else if (ovl_is_whiteout(index)) {
		/* Whiteout index returns NULL for noop */
		dput(index);
		index = NULL;
	} else {
		dput(index);
		err = -ENOTDIR;
		goto fail;
	}

	pr_debug("%s: %pd2 is %s\n", __func__, lowerdir,
		 !index ? "covered" : d_is_dir(index) ? "indexed" : "unchanged");
out:
	kfree(name.name);

	return index;

fail:
	pr_warn_ratelimited("failed lowerdir index lookup (ino=%lu, key=%.*s, err=%i)\n",
			    d_inode(lowerdir)->i_ino, name.len, name.name, err);
	index = ERR_PTR(err);
	goto out;
}

/*
 * Record change in index if needed before lower modification.
 *
 * Returns 0 if change is recorded in index
 * Returns >0 if dir or ancestor are whiteout in index
 * Returns <0 on failure to record the change in index
 *
 * Called without any filesystem locks held.
 */
static int ovl_handle_want_write(struct super_block *sb, u32 mask,
				 struct dentry *lowerdir)
{
	struct dentry *index;
	int err = 0;

	/*
	 * Event is on dir itself or on a non-dir child -
	 * record change in dir.
	 *
	 * We get here from a call to either file_start_write() or
	 * mnt_want_write_path().
	 *
	 * If event is on a non-dir child, we need to get the unstable
	 * parent because event data is the dentry of the non-dir child,
	 * not of the parent.
	 *
	 * If a rename came in between the pre-modify event and now and
	 * moved child away from its parent, the rename itself should
	 * have generated pre-modify events that would have already
	 * recorded the change in the old and new parents, so it does
	 * not matter if we get the old or new parent.
	 */
	index = ovl_lookup_lowerdir_index(sb, lowerdir);
	if (!index) {
		/* Allow modification of covered lower */
		err = 1;
	} else if (IS_ERR(index)) {
		err = PTR_ERR(index);
		index = NULL;
	} else if (d_is_negative(index)) {
		/* Deny modification unless change is recorded in index */
		err = -ENOENT;
	}

	dput(index);

	return err;
}

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
	if (!err || err == -EEXIST)
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
	struct ovl_fs *ofs = sb->s_fs_info;
	struct dentry *dentry = fsnotify_data_dentry(data, data_type);
	struct dentry *lowerdir = NULL;
	int ret = 0;

	if (WARN_ON_ONCE(!(mask & OVL_FSNOTIFY_MASK)))
		return 0;

	if (WARN_ON_ONCE(!dentry))
		return 0;

	pr_debug("%s: %pd2 mask=%x\n", __func__, dentry, mask);

	/* Don't handle events before overlay mount is done */
	if (!(sb->s_flags & SB_BORN))
		return 0;
	smp_rmb();

	lowerdir = d_is_dir(dentry) ? dget(dentry) : dget_parent(dentry);
	/* Not interested in events from non-dir with no parent */
	if (unlikely(!d_is_dir(lowerdir)))
		goto out;

	if (!is_subdir(lowerdir, ofs->layers[1].mnt->mnt_root)) {
		/* Not interested in events on objects outside lower rootdir */
		ret = 1;
	} else if (!ovl_indexdir(sb)) {
		/* Deny all modification to lower when indexing is disabled */
		ret = -EROFS;
	} else {
		ret = ovl_handle_want_write(sb, mask, lowerdir);
		if (ret < 0)
			goto out;

		if (cookie) {
			/* TODO: handle move */
		}
	}

	if (ret > 0) {
		/*
		 * Add ignored mark for lowerdir outside lower rootdir.
		 * TODO: Add ignored mark for indexed lowerdir.
		 */
		ovl_add_ignored_mark(group, lowerdir, OVL_FSNOTIFY_MASK);
		ret = 0;
	}
out:
	dput(lowerdir);

	return ret ? -EPERM : 0;
}

static int ovl_add_sb_mark(struct fsnotify_group *group,
			   struct vfsmount *lowermnt, bool watch_mnt)
{
	struct ovl_mark *ovm;
	int err;

	ovm = kmem_cache_alloc(ovl_mark_cachep, GFP_KERNEL);
	if (!ovm)
		return -ENOMEM;

	fsnotify_init_mark(&ovm->fsn_mark, group);
	ovm->fsn_mark.mask = OVL_FSNOTIFY_MASK;
	if (watch_mnt) {
		err = fsnotify_add_mark(&ovm->fsn_mark,
					&real_mount(lowermnt)->mnt_fsnotify_marks,
					FSNOTIFY_OBJ_TYPE_VFSMOUNT, 0, NULL);
	} else {
		err = fsnotify_add_mark(&ovm->fsn_mark,
					&lowermnt->mnt_sb->s_fsnotify_marks,
					FSNOTIFY_OBJ_TYPE_SB, 0, NULL);
	}
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

int ovl_get_watch(struct super_block *sb, struct ovl_fs *ofs, struct path *lowerpath)
{
	struct fsnotify_group *group;
	int err;

	if (ofs->numlayer > 2) {
		pr_err("option \"watch\" is not supported with multi lower layers.\n");
		return -EINVAL;
	}

	if (ofs->numfs > 1 && ofs->config.watch == OVL_WATCH_SB) {
		pr_warn("option \"watch\" requires lowerdir and upperdir on the same fs.\n");
		return -EINVAL;
	}

	group = fsnotify_alloc_group(&ovl_fsnotify_ops);
	if (IS_ERR(group)) {
		pr_err("failed to allocate fsnotify group\n");
		return PTR_ERR(group);
	}

	ofs->watch = group;
	group->private = sb;

	/* Create a mark on lower sb/mnt */
	err = ovl_add_sb_mark(group, lowerpath->mnt,
			      ofs->config.watch == OVL_WATCH_MNT);

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
