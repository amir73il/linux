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

#define OVL_FSNOTIFY_MASK (FS_MODIFY_INTENT | FS_NAME_INTENT | FS_MOVE_INTENT)

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
 * Returns the positive or negative index entry.
 * Returns NULL if no need to index index lowerdir.
 * Returns error if failed to lookup index entry.
 */
static struct dentry *ovl_lookup_lowerdir_index(struct super_block *sb,
						struct dentry *lowerdir)
{
	struct ovl_fs *ofs = sb->s_fs_info;
	struct dentry *index;
	struct qstr name = {};
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
		 !index ? "moved" : d_is_dir(index) ? "indexed" : "unchanged");
	kfree(name.name);

	return index;

fail:
	pr_warn_ratelimited("failed lowerdir index lookup (ino=%lu, key=%.*s, err=%i)\n",
			    d_inode(lowerdir)->i_ino, name.len, name.name, err);
	kfree(name.name);

	return ERR_PTR(err);
}

/*
 * Record change in index if needed before lower modification.
 *
 * Called without any filesystem locks held.
 */
static int ovl_handle_want_write(struct super_block *sb, u32 mask,
				 struct dentry *lowerdir)
{
	struct dentry *index;
	int err = 0;

	index = ovl_lookup_lowerdir_index(sb, lowerdir);
	if (IS_ERR_OR_NULL(index)) {
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
	int add_flags = FSNOTIFY_ADD_MARK_NO_IREF;
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
				FSNOTIFY_OBJ_TYPE_INODE, add_flags, NULL);
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

	/* Modifications on disconnected dir is unexpected */
	if (WARN_ON_ONCE(lowerdir->d_flags & DCACHE_DISCONNECTED)) {
		ret = -EIO;
		goto out;
	}

	/* Not interested in events on objects outside lower rootdir */
	if (!is_subdir(lowerdir, ofs->layers[1].mnt->mnt_root)) {
		ovl_add_ignored_mark(group, lowerdir, OVL_FSNOTIFY_MASK);
		goto out;
	}

	/* Deny all modification to lower when indexing is disabled */
	if (!ovl_indexdir(sb)) {
		ret = -EROFS;
		goto out;
	}

	ret = ovl_handle_want_write(sb, mask, lowerdir);
	if (ret < 0)
		goto out;

	if (mask & FS_MOVE_INTENT) {
		/* TODO: whiteout index before move of lower */
	}

out:
	dput(lowerdir);

	return ret < 0 ? -EPERM : 0;
}

static int ovl_add_sb_mark(struct fsnotify_group *group,
			   struct vfsmount *lowermnt, bool watch_mnt)
{
	struct ovl_mark *ovm;
	u32 mask = OVL_FSNOTIFY_MASK;
	fsnotify_connp_t *connp;
	int type, err;

	/* TODO: relax for watch_mnt and idmapped mount */
	if (!ns_capable(lowermnt->mnt_sb->s_user_ns, CAP_SYS_ADMIN))
		return -EPERM;

	ovm = kmem_cache_alloc(ovl_mark_cachep, GFP_KERNEL);
	if (!ovm)
		return -ENOMEM;

	fsnotify_init_mark(&ovm->fsn_mark, group);
	ovm->fsn_mark.mask = mask;
	if (watch_mnt) {
		connp = &real_mount(lowermnt)->mnt_fsnotify_marks;
		type = FSNOTIFY_OBJ_TYPE_VFSMOUNT;
	} else {
		connp = &lowermnt->mnt_sb->s_fsnotify_marks;
		type = FSNOTIFY_OBJ_TYPE_SB;
	}
	err = fsnotify_add_mark(&ovm->fsn_mark, connp, type, 0, NULL);
	fsnotify_put_mark(&ovm->fsn_mark);

	pr_debug("%s: %pd2 group=%p mark=%p type=%d mask=%x\n", __func__,
		 lowermnt->mnt_root, group, ovm, type, mask);

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
		pr_warn("option \"watch\" requires lowerdir and upperdir on the same fs; Try \"watch=mnt\".\n");
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
