/*
 * linux/fs/next3/snapshot.c
 *
 * Written by Amir Goldstein <amir73il@users.sf.net>, 2008
 *
 * Copyright (C) 2008-2010 CTERA Networks
 *
 * This file is part of the Linux kernel and is made available under
 * the terms of the GNU General Public License, version 2, or at your
 * option, any later version, incorporated herein by reference.
 *
 * Next3 snapshots core functions.
 */

#ifdef CONFIG_NEXT3_FS_SNAPSHOT_BLOCK_MOVE
#include <linux/quotaops.h>
#endif
#include "snapshot.h"

#ifdef CONFIG_NEXT3_FS_SNAPSHOT_BLOCK
#define snapshot_debug_hl(n, f, a...)	snapshot_debug_l(n, handle ? 	\
						 IS_COWING(handle) : 0, f, ## a)

/*
 * next3_snapshot_map_blocks() - helper function for
 * next3_snapshot_test_and_cow().  Test if blocks are mapped in snapshot file.
 * If @block is not mapped and if @cmd is non zero, try to allocate @maxblocks.
 * Also used by next3_snapshot_create() to pre-allocate snapshot blocks.
 *
 * Return values:
 * > 0 - no. of mapped blocks in snapshot file
 * = 0 - @block is not mapped in snapshot file
 * < 0 - error
 */
int next3_snapshot_map_blocks(handle_t *handle, struct inode *inode,
			      next3_snapblk_t block, unsigned long maxblocks,
			      next3_fsblk_t *mapped, int cmd)
{
	struct buffer_head dummy;
	int err;

	dummy.b_state = 0;
	dummy.b_blocknr = 0;
	err = next3_get_blocks_handle(handle, inode, SNAPSHOT_IBLOCK(block),
				      maxblocks, &dummy, cmd);
	/*
	 * next3_get_blocks_handle() returns number of blocks
	 * mapped. 0 in case of a HOLE.
	 */
	if (mapped && err > 0)
		*mapped = dummy.b_blocknr;

	snapshot_debug_hl(4, "snapshot (%u) map_blocks "
			"[%lu/%lu] = [%lu/%lu] "
			"cmd=%d, maxblocks=%lu, mapped=%d\n",
			inode->i_generation,
			SNAPSHOT_BLOCK_TUPLE(block),
			SNAPSHOT_BLOCK_TUPLE(dummy.b_blocknr),
			cmd, maxblocks, err);
	return err;
}
#endif

#ifdef CONFIG_NEXT3_FS_SNAPSHOT_FILE_READ
/*
 * next3_snapshot_get_inode_access() - called from next3_get_blocks_handle()
 * on snapshot file access.
 * return value <0 indicates access not granted
 * return value 0 indicates normal inode access
 * return value 1 indicates snapshot inode read through access
 * in which case 'prev_snapshot' is pointed to the previous snapshot
 * on the list or set to NULL to indicate read through to block device.
 */
#ifdef CONFIG_NEXT3_FS_SNAPSHOT_LIST_READ
/*
 * In-memory snapshot list manipulation is protected by snapshot_mutex.
 * In this function we read the in-memory snapshot list without holding
 * snapshot_mutex, because we don't want to slow down snapshot read performance.
 * Following is a proof, that even though we don't hold snapshot_mutex here,
 * reading the list is safe from races with snapshot list delete and add (take).
 *
 * Proof of no race with snapshot delete:
 * --------------------------------------
 * We get here only when reading from an enabled snapshot or when reading
 * through from an enabled snapshot to a newer snapshot.  Snapshot delete
 * operation is only allowed for a disabled snapshot, when no older enabled
 * snapshot exists (i.e., the deleted snapshot in not 'in-use').  Hence,
 * read through is safe from races with snapshot list delete operations.
 *
 * Proof of no race with snapshot take:
 * ------------------------------------
 * Snapshot B take is composed of the following steps:
 * - Add snapshot B to head of list (active_snapshot is A).
 * - Allocate and copy snapshot B initial blocks.
 * - Clear snapshot A 'active' flag.
 * - Set snapshot B 'list' and 'active' flags.
 * - Set snapshot B as active snapshot (active_snapshot=B).
 *
 * When reading from snapshot A during snapshot B take, we have 2 cases:
 * 1. is_active(A) is tested before setting active_snapshot=B -
 *    read through from A to block device.
 * 2. is_active(A) is tested after setting active_snapshot=B -
 *    read through from A to B.
 *
 * When reading from snapshot B during snapshot B take, we have 3 cases:
 * 1. B->flags and B->prev are read before adding B to list -
 *    access to B denied.
 * 2. B->flags is read before setting the 'list' and 'active' flags -
 *    normal file access to B.
 * 3. B->flags is read after setting the 'list' and 'active' flags -
 *    read through from B to block device.
 */
#endif
int next3_snapshot_get_inode_access(handle_t *handle, struct inode *inode,
		next3_fsblk_t iblock, int count, int cmd,
		struct inode **prev_snapshot)
{
	struct next3_inode_info *ei = NEXT3_I(inode);
	unsigned int flags = ei->i_flags;
#ifdef CONFIG_NEXT3_FS_SNAPSHOT_LIST_READ
	struct list_head *prev = ei->i_snaplist.prev;
#endif
#ifdef CONFIG_NEXT3_FS_SNAPSHOT_BLOCK
#ifdef CONFIG_NEXT3_FS_DEBUG
	next3_fsblk_t block = SNAPSHOT_BLOCK(iblock);
	unsigned long block_group = (iblock < SNAPSHOT_BLOCK_OFFSET ? -1 :
			SNAPSHOT_BLOCK_GROUP(block));
	next3_grpblk_t blk = (iblock < SNAPSHOT_BLOCK_OFFSET ? iblock :
			SNAPSHOT_BLOCK_GROUP_OFFSET(block));
	snapshot_debug_hl(4, "snapshot (%u) get_blocks [%d/%lu] count=%d "
			  "cmd=%d\n", inode->i_generation, blk, block_group,
			  count, cmd);
#endif

	if (SNAPMAP_ISSPECIAL(cmd)) {
		/*
		 * COWing or moving blocks to active snapshot
		 */
		BUG_ON(!handle || !IS_COWING(handle));
		BUG_ON(!(flags & NEXT3_SNAPFILE_ACTIVE_FL));
		BUG_ON(iblock < SNAPSHOT_BLOCK_OFFSET);
		return 0;
	} else if (cmd)
		BUG_ON(handle && IS_COWING(handle));
#endif

	if (!(flags & NEXT3_SNAPFILE_LIST_FL)) {
#ifdef CONFIG_NEXT3_FS_SNAPSHOT_LIST_READ
		if (prev && prev == &NEXT3_SB(inode->i_sb)->s_snapshot_list)
			/* normal access to snapshot being taken */
			return 0;
		/* snapshot not on the list - read/write access denied */
		return -EPERM;
#else
		return 0;
#endif
	}

	if (cmd) {
		/* snapshot inode write access */
		snapshot_debug(1, "snapshot (%u) is read-only"
				" - write access denied!\n",
				inode->i_generation);
		return -EPERM;
	} else {
		/* snapshot inode read access */
		if (iblock < SNAPSHOT_BLOCK_OFFSET)
			/* snapshot reserved blocks */
			return 0;
		/*
		 * non NULL handle indicates this is test_and_cow()
		 * checking if snapshot block is mapped
		 */
		if (handle)
			return 0;
	}

	/*
	 * Snapshot image read through access: (!cmd && !handle)
	 * indicates this is next3_snapshot_readpage()
	 * calling next3_snapshot_get_block()
	 */
	*prev_snapshot = NULL;
#ifdef CONFIG_NEXT3_FS_SNAPSHOT_LIST_READ
	if (next3_snapshot_is_active(inode) ||
			(flags & NEXT3_SNAPFILE_ACTIVE_FL))
		/* read through from active snapshot to block device */
		return 1;

	if (list_empty(prev))
		/* not on snapshots list? */
		return -EIO;

	if (prev == &NEXT3_SB(inode->i_sb)->s_snapshot_list)
		/* active snapshot not found on list? */
		return -EIO;

	/* read through to prev snapshot on the list */
	ei = list_entry(prev, struct next3_inode_info, i_snaplist);
	*prev_snapshot = &ei->vfs_inode;

	if (!next3_snapshot_file(*prev_snapshot))
		/* non snapshot file on the list? */
		return -EIO;

	return 1;
#else
	return next3_snapshot_is_active(inode) ? 1 : 0;
#endif
}
#endif

#ifdef CONFIG_NEXT3_FS_SNAPSHOT_BLOCK_COW
/*
 * COW helper functions
 */

/*
 * copy buffer @bh to (locked) snapshot buffer @sbh and mark it uptodate
 */
static inline void
__next3_snapshot_copy_buffer(struct buffer_head *sbh,
		struct buffer_head *bh)
{
	memcpy(sbh->b_data, bh->b_data, SNAPSHOT_BLOCK_SIZE);
	set_buffer_uptodate(sbh);
}

#ifdef CONFIG_NEXT3_FS_SNAPSHOT_BLOCK_BITMAP
/*
 * use @mask to clear exclude bitmap bits from block bitmap
 * when creating COW bitmap and mark snapshot buffer @sbh uptodate
 */
static inline void
__next3_snapshot_copy_bitmap(struct buffer_head *sbh,
		char *dst, const char *src, const char *mask)
{
	const u32 *ps = (const u32 *)src, *pm = (const u32 *)mask;
	u32 *pd = (u32 *)dst;
	int i;

	if (mask) {
		for (i = 0; i < SNAPSHOT_ADDR_PER_BLOCK; i++)
			*pd++ = *ps++ & ~*pm++;
	} else
		memcpy(dst, src, SNAPSHOT_BLOCK_SIZE);

	set_buffer_uptodate(sbh);
}
#endif

/*
 * next3_snapshot_complete_cow()
 * Unlock a newly COWed snapshot buffer and complete the COW operation.
 * Optionally, sync the buffer to disk or add it to the current transaction
 * as dirty data.
 */
static inline int
next3_snapshot_complete_cow(handle_t *handle,
		struct buffer_head *sbh, struct buffer_head *bh, int sync)
{
	int err = 0;
#ifdef CONFIG_NEXT3_FS_SNAPSHOT_RACE_READ
	
	/* wait for completion of tracked reads before completing COW */
	while (bh && buffer_tracked_readers_count(bh) > 0) {
		snapshot_debug_once(2, "waiting for tracked reads: "
			"block = [%lu/%lu], "
			"tracked_readers_count = %d...\n",
			SNAPSHOT_BLOCK_TUPLE(bh->b_blocknr),
			buffer_tracked_readers_count(bh));
		/*
		 * Quote from LVM snapshot pending_complete() function:
	         * "Check for conflicting reads. This is extremely improbable,
		 *  so msleep(1) is sufficient and there is no need for a wait
		 *  queue." (drivers/md/dm-snap.c).
		 */
		msleep(1);
		/* XXX: Should we fail after N retries? */
	}
#endif

	unlock_buffer(sbh);
	if (handle) {
		err = next3_journal_dirty_data(handle, sbh);
		if (err)
			goto out;
	}
	mark_buffer_dirty(sbh);
	if (sync)
		sync_dirty_buffer(sbh);

out:
#ifdef CONFIG_NEXT3_FS_SNAPSHOT_RACE_COW
	/* COW operation is complete */
	next3_snapshot_end_pending_cow(sbh);
#endif
	return err;
}

/*
 * next3_snapshot_copy_buffer_cow()
 * helper function for next3_snapshot_test_and_cow()
 * copy COWed buffer to new allocated (locked) snapshot buffer
 * add complete the COW operation
 */
static inline int
next3_snapshot_copy_buffer_cow(handle_t *handle,
				   struct buffer_head *sbh,
				   struct buffer_head *bh)
{
	__next3_snapshot_copy_buffer(sbh, bh);
	return next3_snapshot_complete_cow(handle, sbh, bh, 0);
}

/*
 * next3_snapshot_copy_buffer()
 * helper function for next3_snapshot_take()
 * used for initializing pre-allocated snapshot blocks
 * copy buffer to snapshot buffer and sync to disk
 * 'mask' block bitmap with exclude bitmap before copying to snapshot.
 */
void next3_snapshot_copy_buffer(struct buffer_head *sbh,
		struct buffer_head *bh, const char *mask)
{
	lock_buffer(sbh);
#ifdef CONFIG_NEXT3_FS_SNAPSHOT_BLOCK_BITMAP
	if (mask)
		__next3_snapshot_copy_bitmap(sbh,
				sbh->b_data, bh->b_data, mask);
	else
		__next3_snapshot_copy_buffer(sbh, bh);
#else
	__next3_snapshot_copy_buffer(sbh, bh);
#endif
	unlock_buffer(sbh);
	mark_buffer_dirty(sbh);
	sync_dirty_buffer(sbh);
}

#ifdef CONFIG_NEXT3_FS_SNAPSHOT_EXCLUDE_FILES
/*
 * XXX: Experimental code
 * next3_snapshot_zero_buffer()
 * helper function for next3_snapshot_test_and_cow()
 * reset snapshot data buffer to zero and
 * add to current transaction (as dirty data)
 * 'blk' is the logical snapshot block number
 * 'blocknr' is the physical block number
 */
static int
next3_snapshot_zero_buffer(handle_t *handle, struct inode *inode,
		next3_snapblk_t blk, next3_fsblk_t blocknr)
{
	int err;
	struct buffer_head *sbh;
	sbh = sb_getblk(inode->i_sb, blocknr);
	if (!sbh)
		return -EIO;

	snapshot_debug(3, "zeroing snapshot block [%lu/%lu] = [%lu/%lu]\n",
			SNAPSHOT_BLOCK_TUPLE(blk),
			SNAPSHOT_BLOCK_TUPLE(blocknr));

	lock_buffer(sbh);
	memset(sbh->b_data, 0, SNAPSHOT_BLOCK_SIZE);
	set_buffer_uptodate(sbh);
	unlock_buffer(sbh);
	err = next3_journal_dirty_data(handle, sbh);
	mark_buffer_dirty(sbh);
	brelse(sbh);
	return err;
}
#endif

#ifdef CONFIG_NEXT3_FS_SNAPSHOT_BLOCK_BITMAP
/*
 * COW bitmap functions
 */

/*
 * next3_snapshot_init_cow_bitmap() init a new allocated (locked) COW bitmap
 * buffer on first time block group access after snapshot take.
 * COW bitmap is created by masking the block bitmap with exclude bitmap.
 */
static int
next3_snapshot_init_cow_bitmap(struct super_block *sb,
		unsigned int block_group, struct buffer_head *cow_bh)
{
	struct buffer_head *bitmap_bh;
#ifdef CONFIG_NEXT3_FS_SNAPSHOT_EXCLUDE_BITMAP
	struct buffer_head *exclude_bitmap_bh = NULL;
#endif
	char *dst, *src, *mask = NULL;
	struct journal_head *jh;

	bitmap_bh = read_block_bitmap(sb, block_group);
	if (!bitmap_bh)
		return -EIO;

	src = bitmap_bh->b_data;
#ifdef CONFIG_NEXT3_FS_SNAPSHOT_EXCLUDE_BITMAP
	exclude_bitmap_bh = read_exclude_bitmap(sb, block_group);
	if (exclude_bitmap_bh)
		/* mask block bitmap with exclude bitmap */
		mask = exclude_bitmap_bh->b_data;
#endif
	/*
	 * Another COWing task may be changing this block bitmap
	 * (allocating active snapshot blocks) while we are trying
	 * to copy it.  Copying committed_data will keep us
	 * protected from these changes.  At this point we are
	 * guaranteed that the only difference between block bitmap
	 * and committed_data are the new active snapshot blocks,
	 * because before allocating/freeing any other blocks a task
	 * must first get_undo_access() and get here.
	 */
	jbd_lock_bh_journal_head(bitmap_bh);
	jbd_lock_bh_state(bitmap_bh);
	jh = bh2jh(bitmap_bh);
	if (jh && jh->b_committed_data)
		src = jh->b_committed_data;

	/*
	 * in the path coming from next3_snapshot_read_block_bitmap(),
	 * cow_bh is a user page buffer so it has to be kmapped.
	 */
	dst = kmap_atomic(cow_bh->b_page, KM_USER0);
	__next3_snapshot_copy_bitmap(cow_bh, dst, src, mask);
	kunmap_atomic(dst, KM_USER0);

	jbd_unlock_bh_state(bitmap_bh);
	jbd_unlock_bh_journal_head(bitmap_bh);

#ifdef CONFIG_NEXT3_FS_SNAPSHOT_EXCLUDE_BITMAP
	brelse(exclude_bitmap_bh);
#endif
	brelse(bitmap_bh);
	return 0;
}

/*
 * next3_snapshot_read_block_bitmap()
 * helper function for next3_snapshot_get_block()
 * used for fixing the block bitmap user page buffer when
 * reading through to block device.
 */
int next3_snapshot_read_block_bitmap(struct super_block *sb,
		unsigned int block_group, struct buffer_head *bitmap_bh)
{
	int err;

	lock_buffer(bitmap_bh);
	err = next3_snapshot_init_cow_bitmap(sb, block_group, bitmap_bh);
	unlock_buffer(bitmap_bh);
	return err;
}

/*
 * next3_snapshot_read_cow_bitmap - read COW bitmap from active snapshot
 * @handle:	JBD handle
 * @snapshot:	active snapshot
 * @block_group: block group
 *
 * Reads the COW bitmap block (i.e., the active snapshot copy of block bitmap).
 * Creates the COW bitmap on first access to @block_group after snapshot take.
 * COW bitmap cache is non-persistent, so no need to mark the group descriptor
 * block dirty.  COW bitmap races are handled internally, so no locks are
 * required when calling this function, only a valid @handle.
 *
 * Return COW bitmap buffer on success or NULL in case of failure.
 */
static struct buffer_head *
next3_snapshot_read_cow_bitmap(handle_t *handle, struct inode *snapshot,
			       unsigned int block_group)
{
	struct super_block *sb = snapshot->i_sb;
	struct next3_sb_info *sbi = NEXT3_SB(sb);
	struct next3_group_info *gi = sbi->s_group_info + block_group;
	struct next3_group_desc *desc;
	struct buffer_head *cow_bh;
	next3_fsblk_t bitmap_blk;
	next3_fsblk_t cow_bitmap_blk;
	int err = 0;

	desc = next3_get_group_desc(sb, block_group, NULL);
	if (!desc)
		return NULL;

	bitmap_blk = le32_to_cpu(desc->bg_block_bitmap);

#ifdef CONFIG_NEXT3_FS_SNAPSHOT_RACE_BITMAP
	/*
	 * Handle concurrent COW bitmap operations.
	 * bg_cow_bitmap has 3 states:
	 * = 0 - uninitialized (after mount and after snapshot take).
	 * = bg_block_bitmap - marks pending COW of block bitmap.
	 * other - location of initialized COW bitmap block.
	 *
	 * The first task to access block group after mount or snapshot take,
	 * will read the uninitialized state, mark pending COW state, initialize
	 * the COW bitmap block and update COW bitmap cache.  Other tasks will
	 * busy wait until the COW bitmap cache is in initialized state, before
	 * reading the COW bitmap block.
	 */
	do {
		spin_lock(sb_bgl_lock(sbi, block_group));
		cow_bitmap_blk = gi->bg_cow_bitmap;
		if (cow_bitmap_blk == 0)
			/* mark pending COW of bitmap block */
			gi->bg_cow_bitmap = bitmap_blk;
		spin_unlock(sb_bgl_lock(sbi, block_group));

		if (cow_bitmap_blk == 0) {
			snapshot_debug(3, "initializing COW bitmap #%u "
					"of snapshot (%u)...\n",
					block_group, snapshot->i_generation);
			/* sleep 1 tunable delay unit */
			snapshot_test_delay(SNAPTEST_BITMAP);
			break;
		}
		if (cow_bitmap_blk == bitmap_blk) {
			/* wait for another task to COW bitmap block */
			snapshot_debug_once(2, "waiting for pending COW "
					    "bitmap #%d...\n", block_group);
			/*
			 * This is an unlikely event that can happen only once
			 * per block_group/snapshot, so msleep(1) is sufficient
			 * and there is no need for a wait queue.
			 */
			msleep(1);
		}
		/* XXX: Should we fail after N retries? */
	} while (cow_bitmap_blk == 0 || cow_bitmap_blk == bitmap_blk);
#else
	spin_lock(sb_bgl_lock(sbi, block_group));
	cow_bitmap_blk = gi->bg_cow_bitmap;
	spin_unlock(sb_bgl_lock(sbi, block_group));
#endif
	if (cow_bitmap_blk)
		return sb_bread(sb, cow_bitmap_blk);

	/*
	 * Try to read cow bitmap block from snapshot file.  If COW bitmap
	 * is not yet allocated, create the new COW bitmap block.
	 */
	cow_bh = next3_bread(handle, snapshot, SNAPSHOT_IBLOCK(bitmap_blk),
				SNAPMAP_READ, &err);
	if (cow_bh)
		goto out;

	/* allocate snapshot block for COW bitmap */
	cow_bh = next3_getblk(handle, snapshot, SNAPSHOT_IBLOCK(bitmap_blk),
				SNAPMAP_BITMAP, &err);
	if (!cow_bh || err < 0)
		goto out;
	if (!err) {
		/*
		 * err should be 1 to indicate new allocated (locked) buffer.
		 * if err is 0, it means that someone mapped this block
		 * before us, while we are updating the COW bitmap cache.
		 * the pending COW bitmap code should prevent that.
		 */
		WARN_ON(1);
		err = -EIO;
		goto out;
	}

	err = next3_snapshot_init_cow_bitmap(sb, block_group, cow_bh);
	if (err)
		goto out;
	/*
	 * complete pending COW operation. no need to wait for tracked reads
	 * of block bitmap, because it is copied directly to page buffer by
	 * next3_snapshot_read_block_bitmap()
	 */
	err = next3_snapshot_complete_cow(handle, cow_bh, NULL, 1);
	if (err)
		goto out;

	trace_cow_inc(handle, bitmaps);
out:
	if (!err && cow_bh) {
		/* initialized COW bitmap block */
		cow_bitmap_blk = cow_bh->b_blocknr;
		snapshot_debug(3, "COW bitmap #%u of snapshot (%u) "
				"mapped to block [%lu/%lu]\n",
				block_group, snapshot->i_generation,
				SNAPSHOT_BLOCK_GROUP_OFFSET(cow_bitmap_blk),
				SNAPSHOT_BLOCK_GROUP(cow_bitmap_blk));
	} else {
		/* uninitialized COW bitmap block */
		cow_bitmap_blk = 0;
		snapshot_debug(1, "failed to read COW bitmap #%u of snapshot "
				"(%u)\n", block_group, snapshot->i_generation);
		brelse(cow_bh);
		cow_bh = NULL;
	}

	/* update or reset COW bitmap cache */
	spin_lock(sb_bgl_lock(sbi, block_group));
	gi->bg_cow_bitmap = cow_bitmap_blk;
	spin_unlock(sb_bgl_lock(sbi, block_group));

	return cow_bh;
}

/*
 * next3_snapshot_test_cow_bitmap - test if blocks are in use by snapshot
 * @handle:	JBD handle
 * @snapshot:	active snapshot
 * @block:	address of block
 * @maxblocks:	max no. of blocks to be tested
 * @excluded:	if not NULL, blocks belong to this excluded inode
 *
 * If the block bit is set in the COW bitmap, than it was allocated at the time
 * that the active snapshot was taken and is therefore "in use" by the snapshot.
 *
 * Return values:
 * > 0 - no. of blocks that are in use by snapshot
 * = 0 - @block is not in use by snapshot
 * < 0 - error
 */
static int
next3_snapshot_test_cow_bitmap(handle_t *handle, struct inode *snapshot,
		next3_fsblk_t block, int maxblocks, struct inode *excluded)
{
	struct buffer_head *cow_bh;
	unsigned long block_group = SNAPSHOT_BLOCK_GROUP(block);
	next3_grpblk_t bit = SNAPSHOT_BLOCK_GROUP_OFFSET(block);
	next3_fsblk_t snapshot_blocks = SNAPSHOT_BLOCKS(snapshot);
	int inuse, err = 0;

	if (block >= snapshot_blocks)
		/*
		 * Block is not is use by snapshot because it is past the
		 * last f/s block at the time that the snapshot was taken.
		 * (suggests that f/s was resized after snapshot take)
		 */
		return 0;

	cow_bh = next3_snapshot_read_cow_bitmap(handle, snapshot, block_group);
	if (!cow_bh)
		return -EIO;
	/*
	 * if the bit is set in the COW bitmap,
	 * then the block is in use by snapshot
	 */
	for (inuse = 0; inuse < maxblocks && bit+inuse < SNAPSHOT_BLOCKS_PER_GROUP;
			inuse++) {
		if (!next3_test_bit(bit+inuse, cow_bh->b_data))
			break;
	}

#ifdef CONFIG_NEXT3_FS_SNAPSHOT_EXCLUDE_BITMAP
	if (inuse && excluded) {
		int i;

		/*
		 * We should never get here because excluded file blocks should
		 * be excluded from COW bitmap.  The blocks will not be COWed
		 * anyway, but this can indicate a messed up exclude bitmap.
		 * Mark that exclude bitmap needs to be fixed and clear blocks
		 * from COW bitmap.
		 */
		NEXT3_SET_FLAGS(excluded->i_sb, NEXT3_FLAGS_FIX_EXCLUDE);
		next3_warning(excluded->i_sb, __func__,
			"clearing excluded file (ino=%lu) blocks [%d-%d/%lu] "
			"from COW bitmap! - running fsck to fix exclude bitmap "
			"is recommended.\n",
			excluded->i_ino, bit, bit+inuse-1, block_group);
		for (i = 0; i < inuse; i++)
			next3_clear_bit(bit+i, cow_bh->b_data);
		inuse = 0;
		err = next3_journal_dirty_data(handle, cow_bh);
		mark_buffer_dirty(cow_bh);
	}

#endif
	brelse(cow_bh);
	return err ? err : inuse;
}
#endif

#ifdef CONFIG_NEXT3_FS_SNAPSHOT_EXCLUDE_BITMAP
/*
 * next3_snapshot_test_and_exclude() marks blocks in exclude bitmap
 * @where:	name of caller function
 * @handle:	JBD handle
 * @sb:		super block handle
 * @block:	address of first block to exclude
 * @maxblocks:	max. blocks to exclude
 * @exclude:	if false, return -EIO if block needs to be excluded
 *
 * Return values:
 * >= 0 - no. of blocks set in exclude bitmap
 * < 0 - error
 */
int next3_snapshot_test_and_exclude(const char *where, handle_t *handle,
		struct super_block *sb, next3_fsblk_t block, int maxblocks,
		int exclude)
{
	struct buffer_head *exclude_bitmap_bh = NULL;
	unsigned long block_group = SNAPSHOT_BLOCK_GROUP(block);
	next3_grpblk_t bit = SNAPSHOT_BLOCK_GROUP_OFFSET(block);
	int err = 0, n = 0, excluded = 0;
	int count = maxblocks;

	exclude_bitmap_bh = read_exclude_bitmap(sb, block_group);
	if (!exclude_bitmap_bh)
		return 0;

	if (exclude)
		err = next3_journal_get_write_access(handle, exclude_bitmap_bh);
	if (err)
		goto out;

	while (count > 0 && bit < SNAPSHOT_BLOCKS_PER_GROUP) {
		if (!next3_set_bit_atomic(sb_bgl_lock(NEXT3_SB(sb),
						block_group),
					bit, exclude_bitmap_bh->b_data)) {
			n++;
			if (!exclude)
				break;
		} else if (n) {
			snapshot_debug(2, "excluded blocks: [%d-%d/%ld]\n",
					bit-n, bit-1, block_group);
			excluded += n;
			n = 0;
		}
		bit++;
		count--;
	}

	if (n && !exclude) {
		NEXT3_SET_FLAGS(sb, NEXT3_FLAGS_FIX_EXCLUDE);
		next3_error(sb, where,
			"snapshot file block [%d/%lu] not in exclude bitmap! - "
			"running fsck to fix exclude bitmap is recommended.\n",
			bit, block_group);
		err = -EIO;
		goto out;
	}

	if (n) {
		snapshot_debug(2, "excluded blocks: [%d-%d/%ld]\n",
				bit-n, bit-1, block_group);
		excluded += n;
	}

	if (exclude && excluded) {
		err = next3_journal_dirty_metadata(handle, exclude_bitmap_bh);
		trace_cow_add(handle, excluded, excluded);
	}
out:
	brelse(exclude_bitmap_bh);
	return err ? err : excluded;
}
#endif

/*
 * COW functions
 */

#ifdef CONFIG_NEXT3_FS_DEBUG
static void
__next3_snapshot_trace_cow(const char *where, handle_t *handle,
		struct super_block *sb, struct inode *inode,
		struct buffer_head *bh, next3_fsblk_t block, int cmd)
{
	unsigned long inode_group = 0;
	next3_grpblk_t inode_offset = 0;

	if (inode) {
		inode_group = (inode->i_ino - 1) /
			NEXT3_INODES_PER_GROUP(sb);
		inode_offset = (inode->i_ino - 1) %
			NEXT3_INODES_PER_GROUP(sb);
	}
	snapshot_debug_hl(4, "%s(i:%d/%ld, b:%lu/%lu)"
			" h_ref=%d, cmd=%d\n",
			where, inode_offset, inode_group,
			SNAPSHOT_BLOCK_GROUP_OFFSET(block),
			SNAPSHOT_BLOCK_GROUP(block),
			handle->h_ref, cmd);
}

#define next3_snapshot_trace_cow(where, handle, sb, inode, bh, block, cmd) \
	if (snapshot_enable_debug >= 4)					\
		__next3_snapshot_trace_cow(where, handle, sb, inode,	\
				bh, block, cmd)
#else
#define next3_snapshot_trace_cow(where, handle, sb, inode, bh, block, cmd)
#endif

#ifdef CONFIG_NEXT3_FS_SNAPSHOT_JOURNAL_CACHE
/*
 * The last transaction ID during which the buffer has been COWed is stored in
 * the b_cow_tid field of the journal_head struct.  If we know that the buffer
 * was COWed during the current transaction, we don't need to COW it again.
 * Find the offset of the b_cow_tid field by checking for free space in the
 * journal_head struct. If there is no free space, don't use cow tid cache.
 * This method is used so the next3 module could be loaded without rebuilding
 * the kernel with modified journal_head struct.
 * [jbd_lock_bh_state()]
 */

static int cow_tid_offset;

void init_next3_snapshot_cow_cache(void)
{
	const struct journal_head *jh = NULL;
	char *pos, *end;

	if (cow_tid_offset)
		return;

#ifdef CONFIG_64BIT
	/* check for 32bit padding to 64bit alignment after b_modified */
	pos = (char *)&jh->b_modified + sizeof(jh->b_modified);
	end = (char *)&jh->b_frozen_data;
	if (pos + sizeof(tid_t) <= end)
		goto found;

#endif
	/* check for extra jbd2 fields after last jbd field */
	pos = (char *)&jh->b_cpprev + sizeof(jh->b_cpprev);
	end = (char *)jh + sizeof(*jh);
	if (pos + sizeof(tid_t) <= end)
		goto found;

	/* no free space found - disable cow cache */
	cow_tid_offset = -1;
	return;
found:
	cow_tid_offset = pos - (char *)NULL;
#ifdef CONFIG_NEXT3_FS_DEBUG
	cow_cache_offset = cow_tid_offset;
#endif
}

#define cow_cache_enabled()	(cow_tid_offset > 0)
#define jh_cow_tid(jh)		\
	*(tid_t *)(((char *)(jh))+cow_tid_offset)

#define test_cow_tid(jh, handle)	\
	(jh_cow_tid(jh) == (handle)->h_transaction->t_tid)
#define set_cow_tid(jh, handle)		\
	jh_cow_tid(jh) = (handle)->h_transaction->t_tid

/*
 * Journal COW cache functions.
 * a block can only be COWed once per snapshot,
 * so a block can only be COWed once per transaction,
 * so a buffer that was COWed in the current transaction,
 * doesn't need to be COWed.
 *
 * Return values:
 * 1 - block was COWed in current transaction
 * 0 - block wasn't COWed in current transaction
 */
static int
next3_snapshot_test_cowed(handle_t *handle, struct buffer_head *bh)
{
	struct journal_head *jh;

	if (!cow_cache_enabled())
		return 0;

	/* check the COW tid in the journal head */
	if (bh && buffer_jbd(bh)) {
		jbd_lock_bh_state(bh);
		jh = bh2jh(bh);
		if (jh && !test_cow_tid(jh, handle))
			jh = NULL;
		jbd_unlock_bh_state(bh);
		if (jh)
			/*
			 * Block was already COWed in the running transaction,
			 * so we don't need to COW it again.
			 */
			return 1;
	}
	return 0;
}

static void
next3_snapshot_mark_cowed(handle_t *handle, struct buffer_head *bh)
{
	struct journal_head *jh;

	if (!cow_cache_enabled())
		return;

	if (bh && buffer_jbd(bh)) {
		jbd_lock_bh_state(bh);
		jh = bh2jh(bh);
		if (jh && !test_cow_tid(jh, handle))
			/*
			 * this is the first time this block was COWed
			 * in the running transaction.
			 * update the COW tid in the journal head
			 * to mark that this block doesn't need to be COWed.
			 */
			set_cow_tid(jh, handle);
		jbd_unlock_bh_state(bh);
	}
}
#endif

/*
 * Begin COW or move operation.
 * No locks needed here, because @handle is a per-task struct.
 */
static inline void next3_snapshot_cow_begin(handle_t *handle)
{
#ifdef CONFIG_NEXT3_FS_SNAPSHOT_JOURNAL_CREDITS
	if (!NEXT3_SNAPSHOT_HAS_TRANS_BLOCKS(handle, 1)) {
		/*
		 * The test above is based on lower limit heuristics of
		 * user_credits/buffer_credits, which is not always accurate,
		 * so it is possible that there is no bug here, just another
		 * false alarm.
		 */
		snapshot_debug_hl(1, "warning: insufficient buffer/user "
				  "credits (%d/%d) for COW operation?\n",
				  handle->h_buffer_credits,
				  ((next3_handle_t *)handle)->h_user_credits);
	}
#endif
	snapshot_debug_hl(4, "{\n");
	IS_COWING(handle) = 1;
}

/*
 * End COW or move operation.
 * No locks needed here, because @handle is a per-task struct.
 */
static inline void next3_snapshot_cow_end(const char *where,
		handle_t *handle, next3_fsblk_t block, int err)
{
	IS_COWING(handle) = 0;
	snapshot_debug_hl(4, "} = %d\n", err);
	snapshot_debug_hl(4, ".\n");
	if (err < 0)
		snapshot_debug(1, "%s(b:%lu/%lu) failed!"
				" h_ref=%d, err=%d\n", where,
				SNAPSHOT_BLOCK_GROUP_OFFSET(block),
				SNAPSHOT_BLOCK_GROUP(block),
				handle->h_ref, err);
}

/*
 * next3_snapshot_test_and_cow - COW metadata block
 * @where:	name of caller function
 * @handle:	JBD handle
 * @inode:	owner of blocks (NULL for global metadata blocks)
 * @bh:		buffer head of metadata block
 * @cow:	if false, return -EIO if block needs to be COWed
 *
 * Return values:
 * = 0 - @block was COWed or doesn't need to be COWed
 * < 0 - error
 */
int next3_snapshot_test_and_cow(const char *where, handle_t *handle,
		struct inode *inode, struct buffer_head *bh, int cow)
{
	struct super_block *sb = handle->h_transaction->t_journal->j_private;
	struct inode *active_snapshot = next3_snapshot_has_active(sb);
	struct buffer_head *sbh = NULL;
	next3_fsblk_t block = bh->b_blocknr, blk = 0;
	int err = 0, clear = 0;

	if (!active_snapshot)
		/* no active snapshot - no need to COW */
		return 0;

	next3_snapshot_trace_cow(where, handle, sb, inode, bh, block, cow);

#ifdef CONFIG_NEXT3_FS_SNAPSHOT_EXCLUDE_INODE
	if (inode && next3_snapshot_exclude_inode(inode)) {
		snapshot_debug_hl(4, "exclude bitmap update - "
				  "skip block cow!\n");
		return 0;
	}
#endif
	if (IS_COWING(handle)) {
		/* avoid recursion on active snapshot updates */
		WARN_ON(inode && inode != active_snapshot);
		snapshot_debug_hl(4, "active snapshot update - "
				  "skip block cow!\n");
		return 0;
	} else if (inode == active_snapshot) {
		/* active snapshot may only be modified during COW */
		snapshot_debug_hl(4, "active snapshot access denied!\n");
		return -EPERM;
	}

#ifdef CONFIG_NEXT3_FS_SNAPSHOT_JOURNAL_CACHE
	/* check if the buffer was COWed in the current transaction */
	if (next3_snapshot_test_cowed(handle, bh)) {
		snapshot_debug_hl(4, "buffer found in COW cache - "
				  "skip block cow!\n");
		trace_cow_inc(handle, ok_jh);
		return 0;
	}
#endif

	/* BEGIN COWing */
	next3_snapshot_cow_begin(handle);

	if (inode)
		clear = next3_snapshot_excluded(inode);
	if (clear < 0) {
		/*
		 * excluded file block access - don't COW and
		 * mark block in exclude bitmap
		 */
		snapshot_debug_hl(4, "file (%lu) excluded from snapshot - "
				"mark block (%lu) in exclude bitmap\n",
				inode->i_ino, block);
		cow = 0;
	}

#ifdef CONFIG_NEXT3_FS_SNAPSHOT_BLOCK_BITMAP
	/* get the COW bitmap and test if blocks are in use by snapshot */
	err = next3_snapshot_test_cow_bitmap(handle, active_snapshot,
			block, 1, clear < 0 ? inode : NULL);
	if (err < 0)
		goto out;
#else
	if (clear < 0)
		goto cowed;
#endif
	if (!err) {
		trace_cow_inc(handle, ok_bitmap);
		goto cowed;
	}

	/* block is in use by snapshot - check if it is mapped */
	err = next3_snapshot_map_blocks(handle, active_snapshot, block, 1, &blk,
					SNAPMAP_READ);
	if (err < 0)
		goto out;
	if (err > 0) {
		sbh = sb_find_get_block(sb, blk);
		trace_cow_inc(handle, ok_mapped);
		err = 0;
		goto test_pending_cow;
	}

	/* block needs to be COWed */
	err = -EIO;
	if (!cow)
		/* don't COW - we were just checking */
		goto out;

	/* make sure we hold an uptodate source buffer */
	if (!bh || !buffer_mapped(bh))
		goto out;
	if (!buffer_uptodate(bh)) {
		snapshot_debug(1, "warning: non uptodate buffer (%lu)"
				" needs to be copied to active snapshot!\n",
				block);
		ll_rw_block(READ, 1, &bh);
		wait_on_buffer(bh);
		if (!buffer_uptodate(bh))
			goto out;
	}

	/* try to allocate snapshot block to make a backup copy */
	sbh = next3_getblk(handle, active_snapshot, SNAPSHOT_IBLOCK(block),
			   SNAPMAP_COW, &err);
	if (!sbh || err < 0)
		goto out;

	blk = sbh->b_blocknr;
	if (!err) {
		/*
		 * we didn't allocate this block -
		 * another COWing task must have allocated it
		 */
		trace_cow_inc(handle, ok_mapped);
		goto test_pending_cow;
	}

	/*
	 * we allocated this block -
	 * copy block data to snapshot and complete COW operation
	 */
#ifdef CONFIG_NEXT3_FS_SNAPSHOT_RACE_COW
	snapshot_debug(3, "COWing block [%lu/%lu] of snapshot "
			"(%u)...\n",
			SNAPSHOT_BLOCK_GROUP_OFFSET(block),
			SNAPSHOT_BLOCK_GROUP(block),
			active_snapshot->i_generation);
	/* sleep 1 tunable delay unit */
	snapshot_test_delay(SNAPTEST_COW);
#endif
	err = next3_snapshot_copy_buffer_cow(handle, sbh, bh);
	if (err)
		goto out;
	snapshot_debug(3, "block [%lu/%lu] of snapshot (%u) "
			"mapped to block [%lu/%lu]\n",
			SNAPSHOT_BLOCK_TUPLE(block),
			active_snapshot->i_generation,
			SNAPSHOT_BLOCK_TUPLE(sbh->b_blocknr));

	trace_cow_inc(handle, copied);
test_pending_cow:
#ifdef CONFIG_NEXT3_FS_SNAPSHOT_RACE_COW
	if (sbh)
		/* wait for pending COW to complete */
		next3_snapshot_test_pending_cow(sbh, block);
#endif
#ifdef CONFIG_NEXT3_FS_SNAPSHOT_EXCLUDE_FILES
	if (clear && blk) {
		/*
		 * XXX: Experimental code
		 * zero out snapshot block data
		 */
		err = next3_snapshot_zero_buffer(handle, active_snapshot,
				block, blk);
		if (err)
			goto out;
	}
#endif

cowed:
#ifdef CONFIG_NEXT3_FS_SNAPSHOT_JOURNAL_CACHE
	/* mark the buffer COWed in the current transaction */
	next3_snapshot_mark_cowed(handle, bh);
#endif
#ifdef CONFIG_NEXT3_FS_SNAPSHOT_EXCLUDE_BITMAP
	if (clear) {
		/* mark COWed block in exclude bitmap */
		clear = next3_snapshot_exclude_blocks(handle, sb,
				block, 1);
		if (clear < 0)
			err = clear;
	}
#endif
out:
	brelse(sbh);
	/* END COWing */
	next3_snapshot_cow_end(where, handle, block, err);
	return err;
}

#endif
#ifdef CONFIG_NEXT3_FS_SNAPSHOT_BLOCK_MOVE
/*
 * next3_snapshot_test_and_move - move blocks to active snapshot
 * @where:	name of caller function
 * @handle:	JBD handle
 * @inode:	owner of blocks (NULL for global metadata blocks)
 * @block:	address of first block to move
 * @maxblocks:	max. blocks to move
 * @move:	if false, only test if @block needs to be moved
 *
 * Return values:
 * > 0 - no. of blocks that were (or needs to be) moved to snapshot
 * = 0 - @block doesn't need to be moved
 * < 0 - error
 */
int next3_snapshot_test_and_move(const char *where, handle_t *handle,
	struct inode *inode, next3_fsblk_t block, int maxblocks, int move)
{
	struct super_block *sb = handle->h_transaction->t_journal->j_private;
	struct inode *active_snapshot = next3_snapshot_has_active(sb);
	next3_fsblk_t blk = 0;
	int err = 0, count = maxblocks;
	int excluded = 0;

	if (!active_snapshot)
		/* no active snapshot - no need to move */
		return 0;

	next3_snapshot_trace_cow(where, handle, sb, inode, NULL, block, move);

	BUG_ON(IS_COWING(handle) || inode == active_snapshot);

	/* BEGIN moving */
	next3_snapshot_cow_begin(handle);

	if (inode)
		excluded = next3_snapshot_excluded(inode);
	if (excluded) {
		/* don't move excluded file block to snapshot */
		snapshot_debug_hl(4, "file (%lu) excluded from snapshot\n",
				inode->i_ino);
		move = 0;
	}

#ifdef CONFIG_NEXT3_FS_SNAPSHOT_BLOCK_BITMAP
	/* get the COW bitmap and test if blocks are in use by snapshot */
	err = next3_snapshot_test_cow_bitmap(handle, active_snapshot,
			block, count, excluded ? inode : NULL);
	if (err < 0)
		goto out;
	count = err;
#else
	if (excluded)
		goto out;
#endif
	if (!err) {
		/* block not in COW bitmap - no need to move */
		trace_cow_inc(handle, ok_bitmap);
		goto out;
	}

#ifdef CONFIG_NEXT3_FS_DEBUG
	if (inode == NULL &&
		!(NEXT3_I(active_snapshot)->i_flags & NEXT3_UNRM_FL)) {
		/*
		 * This is next3_group_extend() "freeing" the blocks that
		 * were added to the block group.  These block should not be
		 * moved to snapshot, unless the snapshot is marked with the
		 * UNRM flag for large snapshot creation test.
		 */
		trace_cow_inc(handle, ok_bitmap);
		err = 0;
		goto out;
	}
#endif

	/* count blocks are in use by snapshot - check if @block is mapped */
	err = next3_snapshot_map_blocks(handle, active_snapshot, block, 1, &blk,
					SNAPMAP_READ);
	if (err < 0)
		goto out;
	if (err > 0) {
		/* block already mapped in snapshot - no need to move */
		trace_cow_inc(handle, ok_mapped);
		err = 0;
		goto out;
	}

	/* @count blocks need to be moved */
	err = count;
	if (!move)
		/* don't move - we were just checking */
		goto out;

	/* try to move @count blocks from inode to snapshot */
	err = next3_snapshot_map_blocks(handle, active_snapshot, block,
			count, NULL, SNAPMAP_MOVE);
	if (err <= 0)
		goto out;
	count = err;
	/*
	 * User should no longer be charged for these blocks.
	 * Snapshot file owner was charged for these blocks
	 * when they were mapped to snapshot file.
	 */
	if (inode)
		dquot_free_block(inode, count);
#ifdef CONFIG_NEXT3_FS_SNAPSHOT_EXCLUDE_BITMAP
	/* mark moved blocks in exclude bitmap */
	excluded = next3_snapshot_exclude_blocks(handle, sb, block, count);
	if (excluded < 0)
		err = excluded;
#endif
	trace_cow_add(handle, moved, count);
out:
	/* END moving */
	next3_snapshot_cow_end(where, handle, block, err);
	return err;
}

#endif
#ifdef CONFIG_NEXT3_FS_SNAPSHOT_RACE_READ
/*
 * next3_snapshot_get_read_access - get read through access to block device.
 * Sanity test to verify that the read block is allocated and not excluded.
 * This test has performance penalty and is only called if SNAPTEST_READ
 * is enabled.  An attempt to read through to block device of a non allocated
 * or excluded block may indicate a corrupted filesystem, corrupted snapshot
 * or corrupted exclude bitmap.  However, it may also be a read-ahead, which
 * was not implicitly requested by the user, so be sure to disable read-ahead
 * on block device (blockdev --setra 0 <bdev>) before enabling SNAPTEST_READ.
 *
 * Return values:
 * = 0 - block is allocated and not excluded
 * < 0 - error (or block is not allocated or excluded)
 */
int next3_snapshot_get_read_access(struct super_block *sb,
				   struct buffer_head *bh)
{
	unsigned long block_group = SNAPSHOT_BLOCK_GROUP(bh->b_blocknr);
	next3_grpblk_t bit = SNAPSHOT_BLOCK_GROUP_OFFSET(bh->b_blocknr);
	struct buffer_head *bitmap_bh;
#ifdef CONFIG_NEXT3_FS_SNAPSHOT_EXCLUDE_BITMAP
	struct buffer_head *exclude_bitmap_bh = NULL;
#endif
	int err = 0;

	if (PageReadahead(bh->b_page))
		return 0;

	bitmap_bh = read_block_bitmap(sb, block_group);
	if (!bitmap_bh)
		return -EIO;

	if (!next3_test_bit(bit, bitmap_bh->b_data)) {
		snapshot_debug(2, "warning: attempt to read through to "
				"non-allocated block [%d/%lu] - read ahead?\n",
				bit, block_group);
		brelse(bitmap_bh);
		return -EIO;
	}

#ifdef CONFIG_NEXT3_FS_SNAPSHOT_EXCLUDE_BITMAP
	exclude_bitmap_bh = read_exclude_bitmap(sb, block_group);
	if (exclude_bitmap_bh &&
		next3_test_bit(bit, exclude_bitmap_bh->b_data)) {
		snapshot_debug(2, "warning: attempt to read through to "
				"excluded block [%d/%lu] - read ahead?\n",
				bit, block_group);
		err = -EIO;
	}
#endif

#ifdef CONFIG_NEXT3_FS_SNAPSHOT_EXCLUDE_BITMAP
	brelse(exclude_bitmap_bh);
#endif
	brelse(bitmap_bh);
	return err;
}
#endif

