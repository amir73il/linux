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
