// SPDX-License-Identifier: GPL-2.0-only
/*
 * The inodes that syncfs() and unmount have to write with fsync=relaxed.
 *
 * An overlay inode has no pages and no metadata of its own.  What is dirty,
 * under writeback or deferred by lazytime is the state of the upper inode, and
 * nothing tells overlayfs when it changes.  So overlayfs does not mirror that
 * state.  It only remembers which overlay inodes were modified, and a sync
 * asks the upper inode of each of them.
 *
 * The set is an xarray with the marks of the page cache:
 *
 *   OVL_X_DIRTY      the upper inode was modified
 *   OVL_X_TOWRITE    a sync that has begun is going to write it
 *   OVL_X_WRITEBACK  a sync has started to write it
 *
 * The set holds one reference to an inode that has any of them.  They change
 * under the i_lock of the inode, except that OVL_X_TOWRITE is added to
 * OVL_X_DIRTY under the lock of the xarray alone.
 *
 * There is one difference to the page cache.  No completion clears
 * OVL_X_WRITEBACK, whoever has waited does.  Another sync may have started the
 * inode again meanwhile, so the mark only goes when the upper inode is seen
 * clean.  That way whoever walks the set needs no lock against anybody else who
 * does.
 */

#include <linux/fs.h>
#include <linux/log2.h>
#include <linux/mount.h>
#include <linux/pagemap.h>
#include <linux/writeback.h>
#include <linux/xarray.h>
#include <linux/xattr.h>
#include "overlayfs.h"

#define OVL_X_DIRTY	XA_MARK_0
#define OVL_X_TOWRITE	XA_MARK_1
#define OVL_X_WRITEBACK	XA_MARK_2

/*
 * Index by address.  Inodes are at least their size apart and the shift rounds
 * down, so it stays unique, and neighbours in a slab share an xarray node.
 */
static unsigned long ovl_slot(struct inode *inode)
{
	return (unsigned long)OVL_I(inode) >> ilog2(sizeof(struct ovl_inode));
}

/*
 * Give a new inode its slot in the set, so that tracking it later cannot fail.
 * An entry without a mark is never looked at.
 */
int ovl_track_alloc(struct super_block *sb, struct inode *inode)
{
	struct ovl_fs *ofs = OVL_FS(sb);

	if (!ovl_tracks_dirty(ofs))
		return 0;

	return xa_insert(&ofs->tracked, ovl_slot(inode), inode, GFP_KERNEL);
}

/*
 * @inode is about to be freed.  It is not tracked, or it had a reference.
 *
 * Mount settles on the fsync mode after it has allocated the first trap inodes,
 * so the mode does not tell if @inode has a slot.
 */
void ovl_forget_inode(struct inode *inode)
{
	struct ovl_fs *ofs = OVL_FS(inode->i_sb);

	WARN_ON_ONCE(ovl_test_flag(OVL_TRACKED, inode));
	if (!xa_empty(&ofs->tracked))
		xa_erase(&ofs->tracked, ovl_slot(inode));
}

static bool ovl_marked(struct ovl_fs *ofs, unsigned long id)
{
	return xa_get_mark(&ofs->tracked, id, OVL_X_DIRTY) ||
	       xa_get_mark(&ofs->tracked, id, OVL_X_TOWRITE) ||
	       xa_get_mark(&ofs->tracked, id, OVL_X_WRITEBACK);
}

/* OVL_TRACKED is OVL_X_DIRTY without a walk down the tree */
static void ovl_set_dirty(struct ovl_fs *ofs, struct inode *inode)
{
	unsigned long id = ovl_slot(inode);

	lockdep_assert_held(&inode->i_lock);

	if (ovl_test_flag(OVL_TRACKED, inode))
		return;
	if (!ovl_marked(ofs, id)) {
		struct inode *upper = ovl_inode_upper(inode);

		__iget(inode);
		atomic_long_inc(&ofs->nr_tracked);
		/* A sync reports what fails now, or what nobody has seen */
		OVL_I(inode)->wb_err = filemap_sample_wb_err(upper->i_mapping);
	}
	ovl_set_flag(OVL_TRACKED, inode);
	xa_set_mark(&ofs->tracked, id, OVL_X_DIRTY);
}

/* OVL_X_DIRTY goes first, nobody adds OVL_X_TOWRITE after that */
static void ovl_clear_dirty(struct ovl_fs *ofs, struct inode *inode)
{
	unsigned long id = ovl_slot(inode);

	lockdep_assert_held(&inode->i_lock);

	ovl_clear_flag(OVL_TRACKED, inode);
	xa_clear_mark(&ofs->tracked, id, OVL_X_DIRTY);
	xa_clear_mark(&ofs->tracked, id, OVL_X_TOWRITE);
}

/*
 * The upper inode was modified through this overlay, remember the overlay
 * inode for syncfs() and unmount.  The caller holds a reference to @inode.
 *
 * Do not look at the upper inode here.  Its dirty flags are cleared when its
 * writeback starts, not when it completes.
 *
 * Nobody needs an unlinked file to be durable, and the reference would keep its
 * space.  An O_TMPFILE that can still get a name is not such a file.
 *
 * This takes i_lock even if @inode is tracked already, see ovl_untrack().
 */
void ovl_track_inode(struct inode *inode)
{
	if (!ovl_tracks_dirty(OVL_FS(inode->i_sb)) || !ovl_inode_upper(inode))
		return;

	spin_lock(&inode->i_lock);
	if (inode->i_nlink || (inode_state_read(inode) & I_LINKABLE))
		ovl_set_dirty(OVL_FS(inode->i_sb), inode);
	spin_unlock(&inode->i_lock);
}

/*
 * Is there nothing that a sync would have to do for the upper inode?  The
 * caller holds i_lock.
 *
 * Stores through a shared mapping dirty the pages without a call into
 * overlayfs, so the inode has to stay tracked while there may be one.  The
 * mapping holds the real file open for writing.  Read i_writecount first: the
 * page cache tag is set before the last fput().
 *
 * That does not cover pages that are pinned through such a mapping.  A direct
 * read into it that completes after the last munmap() and close() dirties them
 * with nobody looking.
 *
 * An error that was not reported yet is something to do as well.
 */
static bool ovl_upper_clean(struct inode *inode)
{
	struct inode *upper = ovl_inode_upper(inode);
	struct address_space *mapping = upper->i_mapping;

	if (atomic_read_acquire(&upper->i_writecount) > 0)
		return false;

	return !mapping_tagged(mapping, PAGECACHE_TAG_DIRTY) &&
	       !mapping_tagged(mapping, PAGECACHE_TAG_WRITEBACK) &&
	       !(inode_state_read_once(upper) & (I_DIRTY_ALL | I_SYNC)) &&
	       !filemap_check_wb_err(mapping, OVL_I(inode)->wb_err);
}

enum ovl_untrack {
	OVL_UNTRACK_ALWAYS,
	OVL_UNTRACK_CLEAN,	/* if the upper inode is clean */
	OVL_UNTRACK_UNLINKED,	/* if it has no link and cannot get one */
};

/*
 * Take @inode out of the set.  The caller holds a reference to @inode of its
 * own.
 *
 * The condition is looked at under i_lock as well.  A task that has called
 * ovl_track_inode() before is ordered by i_lock, so what it did to the upper
 * inode, or to the link count, is visible.  One that calls it later tracks
 * @inode again.
 */
static bool ovl_untrack(struct inode *inode, enum ovl_untrack when)
{
	struct ovl_fs *ofs = OVL_FS(inode->i_sb);
	unsigned long id = ovl_slot(inode);
	bool done;

	spin_lock(&inode->i_lock);
	done = ovl_marked(ofs, id);
	if (done && when == OVL_UNTRACK_CLEAN)
		done = ovl_upper_clean(inode);
	else if (done && when == OVL_UNTRACK_UNLINKED)
		done = !inode->i_nlink &&
		       (!(inode_state_read(inode) & I_LINKABLE) ||
			hlist_empty(&inode->i_dentry));
	if (done) {
		ovl_clear_dirty(ofs, inode);
		xa_clear_mark(&ofs->tracked, id, OVL_X_WRITEBACK);
		atomic_long_dec(&ofs->nr_tracked);
	}
	spin_unlock(&inode->i_lock);

	if (done)
		iput(inode);
	return done;
}

/*
 * A link to @inode was removed, or a dentry of it has gone and it may be an
 * O_TMPFILE that never got a name.  The caller holds a reference to @inode.
 */
void ovl_untrack_inode(struct inode *inode)
{
	if (ovl_tracks_dirty(OVL_FS(inode->i_sb)) && !inode->i_nlink)
		ovl_untrack(inode, OVL_UNTRACK_UNLINKED);
}

/*
 * Get a reference to the first inode with @mark from *@id on.  A mark is
 * cleared before the reference of the set is dropped, so under the lock of the
 * xarray an inode that has one is alive.
 */
static struct inode *ovl_next_marked(struct ovl_fs *ofs, unsigned long *id,
				     xa_mark_t mark)
{
	struct inode *inode;

	xa_lock(&ofs->tracked);
	inode = xa_find(&ofs->tracked, id, ULONG_MAX, mark);
	if (inode)
		ihold(inode);
	xa_unlock(&ofs->tracked);

	return inode;
}

/* Does only lazytime keep @upper from being clean? */
static bool ovl_only_lazytime(struct inode *upper)
{
	return (inode_state_read_once(upper) & I_DIRTY_ALL) == I_DIRTY_TIME &&
	       atomic_read(&upper->i_writecount) <= 0;
}

/*
 * Drop @inode if its upper inode is clean.
 *
 * lazytime holds timestamps back for up to a day.  The last iput() would write
 * them, but that cannot come while the overlay inode is tracked.  So hand them
 * to the upper filesystem.  Nobody has asked for them to be on disk, so there
 * is nothing to wait for.
 */
static void ovl_release_inode(struct vfsmount *mnt, struct inode *inode)
{
	struct inode *upper = ovl_inode_upper(inode);
	int err;

	if (ovl_untrack(inode, OVL_UNTRACK_CLEAN) ||
	    !ovl_only_lazytime(upper) || mnt_get_write_access(mnt))
		return;

	err = write_inode_for_sync(upper);
	mnt_put_write_access(mnt);
	if (err)
		errseq_set(&inode->i_sb->s_wb_err, err);

	ovl_untrack(inode, OVL_UNTRACK_CLEAN);
}

/*
 * Look at up to *@nr inodes with @mark.  Dropping one writes nothing, so that
 * also works on an upper filesystem that has become read-only.  It keeps a
 * freeze out, because on a frozen filesystem dropping the last reference to an
 * inode that was unlinked sleeps until the thaw.
 */
static void ovl_scan_marked(struct ovl_fs *ofs, xa_mark_t mark,
			    unsigned long *id, unsigned long *nr)
{
	struct vfsmount *mnt = ovl_upper_mnt(ofs);
	struct inode *inode;

	while (*nr && sb_start_write_trylock(mnt->mnt_sb)) {
		--*nr;
		inode = ovl_next_marked(ofs, id, mark);
		if (inode) {
			ovl_release_inode(mnt, inode);
			iput(inode);
		}
		sb_end_write(mnt->mnt_sb);

		if (!inode) {
			*id = 0;
			break;
		}
		++*id;
		cond_resched();
	}
}

/*
 * An inode may be left with OVL_X_WRITEBACK alone, if a sync did not get to
 * wait for it.
 */
static void ovl_release_work(struct work_struct *work)
{
	struct ovl_fs *ofs = container_of(work, struct ovl_fs, release_work);
	unsigned long nr = atomic_long_xchg(&ofs->release_nr, 0);

	ovl_scan_marked(ofs, OVL_X_DIRTY, &ofs->release_id[0], &nr);
	ovl_scan_marked(ofs, OVL_X_WRITEBACK, &ofs->release_id[1], &nr);
}

void ovl_track_init(struct ovl_fs *ofs)
{
	xa_init_flags(&ofs->tracked, XA_FLAGS_ACCOUNT);
	INIT_WORK(&ofs->release_work, ovl_release_work);
}

void ovl_track_exit(struct ovl_fs *ofs)
{
	unsigned long id = 0;

	/* Not xa_empty(), an insert that has failed can leave nodes behind */
	WARN_ON(xa_find(&ofs->tracked, &id, ULONG_MAX, XA_PRESENT));
	xa_destroy(&ofs->tracked);
}

/*
 * Unmount.  The sync of generic_shutdown_super() has written what it could, if
 * the overlay is not read-only.  evict_inodes() has left alone what is still
 * in the set.  Trap inodes can be in the xarray as well, without a mark.
 */
void ovl_drop_tracked(struct ovl_fs *ofs)
{
	struct inode *inode;
	unsigned long id;

	cancel_work_sync(&ofs->release_work);

	xa_for_each(&ofs->tracked, id, inode) {
		ihold(inode);
		ovl_untrack(inode, OVL_UNTRACK_ALWAYS);
		iput(inode);
		cond_resched();
	}
}

long ovl_nr_cached_objects(struct super_block *sb, struct shrink_control *sc)
{
	return atomic_long_read(&OVL_FS(sb)->nr_tracked);
}

/*
 * A tracked inode, its upper inode and the dentry of that cannot be reclaimed.
 * While the upper inode is dirty that is as with any filesystem.  Afterwards
 * nothing tells overlayfs, so look when memory is needed.
 *
 * Not from reclaim itself.  The reference that is dropped may be the last one
 * to an upper inode that was unlinked, and handing over timestamps takes locks
 * of an upper inode that is in use.  Filesystems allocate memory under the
 * locks that both need.
 */
long ovl_free_cached_objects(struct super_block *sb, struct shrink_control *sc)
{
	struct ovl_fs *ofs = OVL_FS(sb);

	atomic_long_add(sc->nr_to_scan, &ofs->release_nr);
	queue_work(system_dfl_wq, &ofs->release_work);

	return 0;
}

/*
 * Keep a freeze and a read-only remount of the upper filesystem out.  Do not
 * wait for either.
 */
static bool ovl_upper_start_write(struct ovl_fs *ofs)
{
	struct vfsmount *mnt = ovl_upper_mnt(ofs);

	if (!sb_start_write_trylock(mnt->mnt_sb))
		return false;
	if (mnt_get_write_access(mnt)) {
		sb_end_write(mnt->mnt_sb);
		return false;
	}
	return true;
}

/*
 * Like tag_pages_for_writeback(): what is dirty now is what this sync has to
 * write.
 */
static void ovl_tag_for_writeback(struct ovl_fs *ofs)
{
	XA_STATE(xas, &ofs->tracked, 0);
	unsigned int tagged = 0;
	struct inode *inode;

	xas_lock(&xas);
	xas_for_each_marked(&xas, inode, ULONG_MAX, OVL_X_DIRTY) {
		xas_set_mark(&xas, OVL_X_TOWRITE);
		if (++tagged % XA_CHECK_SCHED)
			continue;

		xas_pause(&xas);
		xas_unlock(&xas);
		cond_resched();
		xas_lock(&xas);
	}
	xas_unlock(&xas);
}

/*
 * Start to write the data of the upper inode.  OVL_X_WRITEBACK is set before
 * OVL_X_DIRTY is cleared, so that a sync always finds one of them, and
 * OVL_X_DIRTY is cleared before the write, so that a modification that comes
 * later sets it again.
 */
static void ovl_start_inode(struct super_block *sb, struct inode *inode)
{
	struct ovl_fs *ofs = OVL_FS(sb);
	unsigned long id = ovl_slot(inode);
	bool start;
	int err;

	spin_lock(&inode->i_lock);
	/* It may have been unlinked, or another sync was here first */
	start = xa_get_mark(&ofs->tracked, id, OVL_X_TOWRITE);
	if (start) {
		xa_set_mark(&ofs->tracked, id, OVL_X_WRITEBACK);
		ovl_clear_dirty(ofs, inode);
	}
	spin_unlock(&inode->i_lock);

	if (!start)
		return;

	/* Tags the pages first, so it does not follow an appender */
	err = filemap_fdatawrite(ovl_inode_upper(inode)->i_mapping);
	/* If ->sync_fs() returned it the VFS would not call again to wait */
	if (err)
		errseq_set(&sb->s_wb_err, err);
}

/*
 * Write the upper inode and wait for its data, whoever has started to write it.
 *
 * After that OVL_X_WRITEBACK goes if the upper inode is clean.  If it is not,
 * another sync may have started it again and relies on the mark, or it is open
 * for writing and the next sync has to write it again.
 *
 * Writeback of the upper inode that has failed since @inode has entered the
 * set, whoever has done it, shows in the wb_err of the mapping.  Nobody takes
 * that away, unlike the error flags.  It is recorded in the superblock of the
 * overlay under the lock that protects the cursor.  So another syncfs() that is
 * here at the same time finds the one or the other.
 *
 * btrfs records an error after it has ended writeback.  If that is too late for
 * the look here, the error is reported once the inode is modified again.
 */
static int ovl_wait_inode(struct super_block *sb, struct inode *inode)
{
	struct ovl_fs *ofs = OVL_FS(sb);
	struct inode *upper = ovl_inode_upper(inode);
	struct address_space *mapping = upper->i_mapping;
	unsigned long id = ovl_slot(inode);
	bool drop = false;
	int err, err2 = 0;

	err = write_inode_for_sync(upper);
	if (err)
		errseq_set(&sb->s_wb_err, err);
	filemap_fdatawait_keep_errors(mapping);

	spin_lock(&inode->i_lock);
	if (xa_get_mark(&ofs->tracked, id, OVL_X_WRITEBACK)) {
		err2 = errseq_check_and_advance(&mapping->wb_err,
						&OVL_I(inode)->wb_err);
		if (err2)
			errseq_set(&sb->s_wb_err, err2);

		if (ovl_upper_clean(inode)) {
			xa_clear_mark(&ofs->tracked, id, OVL_X_WRITEBACK);
			drop = !ovl_marked(ofs, id);
			if (drop)
				atomic_long_dec(&ofs->nr_tracked);
		} else {
			ovl_set_dirty(ofs, inode);
		}
	}
	spin_unlock(&inode->i_lock);

	if (drop)
		iput(inode);
	return err ? err : err2;
}

/*
 * Start every inode that has OVL_X_TOWRITE, or finish every inode that has
 * OVL_X_WRITEBACK.
 *
 * Do not write to an upper filesystem that is frozen or read-only, or on its
 * way there.  Keep a freeze and a read-only remount out meanwhile, inode by
 * inode, because writers wait behind a freeze that waits for us.
 *
 * Returns false if one of the two has begun.
 */
static bool ovl_walk_marked(struct super_block *sb, xa_mark_t mark, int *error)
{
	struct ovl_fs *ofs = OVL_FS(sb);
	struct inode *inode;
	unsigned long id = 0;
	int err;

	for (;;) {
		if (!ovl_upper_start_write(ofs))
			return false;

		inode = ovl_next_marked(ofs, &id, mark);
		if (inode && mark == OVL_X_TOWRITE) {
			ovl_start_inode(sb, inode);
		} else if (inode) {
			err = ovl_wait_inode(sb, inode);
			if (err && !*error)
				*error = err;
		}
		iput(inode);
		mnt_drop_write(ovl_upper_mnt(ofs));

		if (!inode)
			return true;
		id++;
		cond_resched();
	}
}

/*
 * This tags once, so tasks that modify files do not keep it going.  The marks
 * are shared with every other sync that is running, and what those tag ahead of
 * a walk is written and waited for as well.  But a walk only goes up, so it
 * comes to an end.
 */
static bool ovl_sync_inodes(struct super_block *sb, int wait, int *error)
{
	if (!wait)
		ovl_tag_for_writeback(OVL_FS(sb));

	/*
	 * With @wait this is for what the call before could not start, because
	 * of a freeze or a remount that has gone away again.
	 */
	if (!ovl_walk_marked(sb, OVL_X_TOWRITE, error))
		return false;

	return !wait || ovl_walk_marked(sb, OVL_X_WRITEBACK, error);
}

/*
 * syncfs(), unmount or a read-only remount of an overlay with fsync=relaxed.
 * sync_filesystem() calls this without @wait first and then with.  The steps
 * are those that it takes itself for the upper filesystem, except that only the
 * tracked inodes are written.
 */
int ovl_sync_tracked(struct super_block *sb, int wait)
{
	struct super_block *upper_sb = ovl_upper_mnt(OVL_FS(sb))->mnt_sb;
	int ret, err = 0;
	bool done;

	done = ovl_sync_inodes(sb, wait, &err);

	down_read(&upper_sb->s_umount);
	/*
	 * If the upper filesystem is frozen or read-only, or on its way there,
	 * sync all of it when asked to wait, like without fsync=relaxed.
	 *
	 * Otherwise this has to take care of the upper inodes that have no
	 * overlay inode, like whiteouts and the work directories.
	 */
	if (wait && !done)
		ret = sync_filesystem(upper_sb);
	else
		ret = sync_fs_and_bdev(upper_sb, wait);
	up_read(&upper_sb->s_umount);

	return err ? err : ret;
}
