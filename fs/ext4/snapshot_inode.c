/*
 * linux/fs/ext4/snapshot_inode.c
 *
 * Written by Amir Goldstein <amir73il@users.sf.net>, 2008
 *
 * Copyright (C) 2008-2010 CTERA Networks
 *
 * This file is part of the Linux kernel and is made available under
 * the terms of the GNU General Public License, version 2, or at your
 * option, any later version, incorporated herein by reference.
 *
 * Ext4 snapshots inode functions.
 */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/time.h>
#include <linux/jbd2.h>
#include <linux/highuid.h>
#include <linux/pagemap.h>
#include <linux/quotaops.h>
#include <linux/string.h>
#include <linux/buffer_head.h>
#include <linux/writeback.h>
#include <linux/pagevec.h>
#include <linux/mpage.h>
#include <linux/namei.h>
#include <linux/uio.h>
#include <linux/bio.h>
#include <linux/workqueue.h>
#include <linux/kernel.h>
#include <linux/slab.h>

#include "ext4_jbd2.h"
#include "xattr.h"
#include "acl.h"
#include "ext4_extents.h"

#include <trace/events/ext4.h>
#include "snapshot.h"

#ifdef CONFIG_EXT4_FS_SNAPSHOT_CLEANUP_SHRINK
/**
 * ext4_blks_to_skip - count the number blocks that can be skipped
 * @inode: inode in question
 * @i_block: start block number
 * @maxblocks: max number of data blocks to be skipped
 * @chain: chain of indirect blocks
 * @depth: length of chain from inode to data block
 * @offsets: array of offsets in chain blocks
 * @k: number of allocated blocks in the chain
 *
 * Counts the number of non-allocated data blocks (holes) at offset @i_block.
 * Called from ext4_snapshot_merge_blocks() and ext4_snapshot_shrink_blocks()
 * under snapshot_mutex.
 * Returns the total number of data blocks to be skipped.
 */

static int ext4_blks_to_skip(struct inode *inode, long i_block,
		unsigned long maxblocks, Indirect chain[4], int depth,
		int *offsets, int k)
{
	int ptrs = EXT4_ADDR_PER_BLOCK(inode->i_sb);
	int ptrs_bits = EXT4_ADDR_PER_BLOCK_BITS(inode->i_sb);
	const long direct_blocks = EXT4_NDIR_BLOCKS,
		indirect_blocks = ptrs,
		double_blocks = (1 << (ptrs_bits * 2));
	/* number of data blocks mapped with a single splice to the chain */
	int data_ptrs_bits = ptrs_bits * (depth - k - 1);
	int max_ptrs = maxblocks >> data_ptrs_bits;
	int final = 0;
	unsigned long count = 0;

	switch (depth) {
	case 4: /* tripple indirect */
		i_block -= double_blocks;
		/* fall through */
	case 3: /* double indirect */
		i_block -= indirect_blocks;
		/* fall through */
	case 2: /* indirect */
		i_block -= direct_blocks;
		final = (k == 0 ? 1 : ptrs);
		break;
	case 1: /* direct */
		final = direct_blocks;
		break;
	}
	/* offset of block from start of splice point */
	i_block &= ((1 << data_ptrs_bits) - 1);

	count++;
	while (count <= max_ptrs &&
		offsets[k] + count < final &&
		le32_to_cpu(*(chain[k].p + count)) == 0) {
		count++;
	}
	/* number of data blocks mapped by 'count' splice points */
	count <<= data_ptrs_bits;
	count -= i_block;
	return count < maxblocks ? count : maxblocks;
}

/*
 * ext4_snapshot_shrink_blocks - free unused blocks from deleted snapshot
 * @handle: JBD handle for this transaction
 * @inode:	inode we're shrinking
 * @iblock:	inode offset to first data block to shrink
 * @maxblocks:	inode range of data blocks to shrink
 * @cow_bh:	buffer head to map the COW bitmap block
 *		if NULL, don't look for COW bitmap block
 * @shrink:	shrink mode: 0 (don't free), >0 (free unused), <0 (free all)
 * @pmapped:	return no. of mapped blocks or 0 for skipped holes
 *
 * Frees @maxblocks blocks starting at offset @iblock in @inode, which are not
 * 'in-use' by non-deleted snapshots (blocks 'in-use' are set in COW bitmap).
 * If @shrink is false, just count mapped blocks and look for COW bitmap block.
 * The first time that a COW bitmap block is found in @inode, whether @inode is
 * deleted or not, it is stored in @cow_bh and is used in subsequent calls to
 * this function with other deleted snapshots within the block group boundaries.
 * Called from ext4_snapshot_shrink_blocks() under snapshot_mutex.
 *
 * Return values:
 * >= 0 - no. of shrunk blocks (*@pmapped ? mapped blocks : skipped holes)
 *  < 0 - error
 */
int ext4_snapshot_shrink_blocks(handle_t *handle, struct inode *inode,
		sector_t iblock, unsigned long maxblocks,
		struct buffer_head *cow_bh,
		int shrink, int *pmapped)
{
	int offsets[4];
	Indirect chain[4], *partial;
	int err, blocks_to_boundary, depth, count;
	struct buffer_head *sbh = NULL;
	struct ext4_group_desc *desc = NULL;
	ext4_snapblk_t block_bitmap, block = SNAPSHOT_BLOCK(iblock);
	unsigned long block_group = SNAPSHOT_BLOCK_GROUP(block);
	int mapped_blocks = 0, freed_blocks = 0;
	const char *cow_bitmap;

	BUG_ON(shrink &&
		(!(EXT4_I(inode)->i_flags & EXT4_SNAPFILE_DELETED_FL) ||
		ext4_snapshot_is_active(inode)));

	depth = ext4_block_to_path(inode, iblock, offsets,
			&blocks_to_boundary);
	if (depth == 0)
		return -EIO;

	desc = ext4_get_group_desc(inode->i_sb, block_group, NULL);
	if (!desc)
		return -EIO;
	block_bitmap = ext4_block_bitmap(inode->i_sb, desc);
	partial = ext4_get_branch(inode, depth, offsets, chain, &err);
	if (err)
		return err;

	if (partial) {
		/* block not mapped (hole) - count the number of holes to
		 * skip */
		count = ext4_blks_to_skip(inode, iblock, maxblocks, chain,
					   depth, offsets, (partial - chain));
		snapshot_debug(3, "skipping snapshot (%u) blocks: block=0x%llx"
			       ", count=0x%x\n", inode->i_generation,
			       block, count);
		goto shrink_indirect_blocks;
	}

	/* data block mapped - check if data blocks should be freed */
	partial = chain + depth - 1;
	/* scan all blocks upto maxblocks/boundary */
	count = 0;
	while (count < maxblocks && count <= blocks_to_boundary) {
		ext4_fsblk_t blk = le32_to_cpu(*(partial->p + count));
		if (blk && block + count == block_bitmap &&
			cow_bh && !buffer_mapped(cow_bh)) {
			/*
			 * 'blk' is the COW bitmap physical block -
			 * store it in cow_bh for subsequent calls
			 */
			map_bh(cow_bh, inode->i_sb, blk);
			set_buffer_new(cow_bh);
			snapshot_debug(3, "COW bitmap #%lu: snapshot "
				"(%u), bitmap_blk=(+%lld)\n",
				block_group, inode->i_generation,
				SNAPSHOT_BLOCK_GROUP_OFFSET(block_bitmap));
		}
		if (blk)
			/* count mapped blocks in range */
			mapped_blocks++;
		else if (shrink >= 0)
			/*
			 * Unless we are freeing all block in range,
			 * we cannot have holes inside mapped range
			 */
			break;
		/* count size of range */
		count++;
	}

	if (!shrink)
		goto done_shrinking;

	cow_bitmap = NULL;
	if (shrink > 0 && cow_bh && buffer_mapped(cow_bh)) {
		/* we found COW bitmap - consult it when shrinking */
		sbh = sb_bread(inode->i_sb, cow_bh->b_blocknr);
		if (!sbh) {
			err = -EIO;
			goto cleanup;
		}
		cow_bitmap = sbh->b_data;
	}
	if (shrink < 0 || cow_bitmap) {
		int bit = SNAPSHOT_BLOCK_GROUP_OFFSET(block);

		BUG_ON(bit + count > SNAPSHOT_BLOCKS_PER_GROUP);
		/* free blocks with or without consulting COW bitmap */
		ext4_free_data_cow(handle, inode, partial->bh,
				partial->p, partial->p + count,
				cow_bitmap, bit, &freed_blocks, NULL);
	}

shrink_indirect_blocks:
	/* check if the indirect block should be freed */
	if (shrink && partial == chain + depth - 1) {
		Indirect *ind = partial - 1;
		__le32 *p = NULL;
		if (freed_blocks == mapped_blocks &&
		    count > blocks_to_boundary) {
			for (p = (__le32 *)(partial->bh->b_data);
			     !*p && p < partial->p; p++)
				;
		}
		if (p == partial->p)
			/* indirect block maps zero data blocks - free it */
			ext4_free_data(handle, inode, ind->bh, ind->p,
					ind->p+1);
	}

done_shrinking:
	snapshot_debug(3, "shrinking snapshot (%u) blocks: shrink=%d, "
			"block=0x%llx, count=0x%x, mapped=0x%x, freed=0x%x\n",
			inode->i_generation, shrink, block, count,
			mapped_blocks, freed_blocks);

	if (pmapped)
		*pmapped = mapped_blocks;
	err = count;
cleanup:
	while (partial > chain) {
		brelse(partial->bh);
		partial--;
	}
	brelse(sbh);
return err;
}

#endif
#ifdef CONFIG_EXT4_FS_SNAPSHOT_CLEANUP_MERGE
/*
 * ext4_move_branches - move an array of branches
 * @handle: JBD handle for this transaction
 * @src:	inode we're moving blocks from
 * @ps:		array of src block numbers
 * @pd:		array of dst block numbers
 * @depth:	depth of the branches to move
 * @count:	max branches to move
 * @pmoved:	pointer to counter of moved blocks
 *
 * We move whole branches from src to dst, skipping the holes in src
 * and stopping at the first branch that needs to be merged at higher level.
 * Called from ext4_snapshot_merge_blocks() under snapshot_mutex.
 * Returns the number of merged branches.
 */
static int ext4_move_branches(handle_t *handle, struct inode *src,
		__le32 *ps, __le32 *pd, int depth,
		int count, int *pmoved)
{
	int i;

	for (i = 0; i < count; i++, ps++, pd++) {
		__le32 s = *ps, d = *pd;
		if (s && d && depth)
			/* can't move or skip entire branch, need to merge
			   these 2 branches */
			break;
		if (!s || d)
			/* skip holes is src and mapped data blocks in dst */
			continue;

		/* count moved blocks (and verify they are excluded) */
		ext4_free_branches_cow(handle, src, NULL,
				ps, ps+1, depth, pmoved);

		/* move the entire branch from src to dst inode */
		*pd = s;
		*ps = 0;
	}
	return i;
}

/*
 * ext4_snapshot_merge_blocks - merge blocks from @src to @dst inode
 * @handle: JBD handle for this transaction
 * @src:	inode we're merging blocks from
 * @dst:	inode we're merging blocks to
 * @iblock:	inode offset to first data block to merge
 * @maxblocks:	inode range of data blocks to merge
 *
 * Merges @maxblocks data blocks starting at @iblock and all the indirect
 * blocks that map them.
 * Called from ext4_snapshot_merge() under snapshot_mutex.
 * Returns the merged blocks range and <0 on error.
 */
int ext4_snapshot_merge_blocks(handle_t *handle,
		struct inode *src, struct inode *dst,
		sector_t iblock, unsigned long maxblocks)
{
	Indirect S[4], D[4], *pS, *pD;
	int offsets[4];
	int ks, kd, depth, count;
	int ptrs = EXT4_ADDR_PER_BLOCK(src->i_sb);
	int ptrs_bits = EXT4_ADDR_PER_BLOCK_BITS(src->i_sb);
	int data_ptrs_bits, data_ptrs_mask, max_ptrs;
	int moved = 0, err;

	depth = ext4_block_to_path(src, iblock, offsets, NULL);
	if (depth < 3)
		/* snapshot blocks are mapped with double and tripple
		   indirect blocks */
		return -1;

	memset(D, 0, sizeof(D));
	memset(S, 0, sizeof(S));
	pD = ext4_get_branch(dst, depth, offsets, D, &err);
	kd = (pD ? pD - D : depth - 1);
	if (err)
		goto out;
	pS = ext4_get_branch(src, depth, offsets, S, &err);
	ks = (pS ? pS - S : depth - 1);
	if (err)
		goto out;

	if (ks < 1 || kd < 1) {
		/* snapshot double and tripple tree roots are pre-allocated */
		err = -EIO;
		goto out;
	}

	if (ks < kd) {
		/* nothing to move from src to dst */
		count = ext4_blks_to_skip(src, iblock, maxblocks,
					S, depth, offsets, ks);
		snapshot_debug(3, "skipping src snapshot (%u) holes: "
			       "block=0x%llx, count=0x%x\n", src->i_generation,
			       SNAPSHOT_BLOCK(iblock), count);
		err = count;
		goto out;
	}

	/* move branches from level kd in src to dst */
	pS = S+kd;
	pD = D+kd;

	/* compute max branches that can be moved */
	data_ptrs_bits = ptrs_bits * (depth - kd - 1);
	data_ptrs_mask = (1 << data_ptrs_bits) - 1;
	max_ptrs = (maxblocks >> data_ptrs_bits) + 1;
	if (max_ptrs > ptrs-offsets[kd])
		max_ptrs = ptrs-offsets[kd];

	/* get write access for the splice point */
	err = ext4_journal_get_write_access_inode(handle, src, pS->bh);
	if (err)
		goto out;
	err = ext4_journal_get_write_access_inode(handle, dst, pD->bh);
	if (err)
		goto out;

	/* move as many whole branches as possible */
	err = ext4_move_branches(handle, src, pS->p, pD->p, depth-1-kd,
			max_ptrs, &moved);
	if (err < 0)
		goto out;
	count = err;
	if (moved) {
		snapshot_debug(3, "moved snapshot (%u) -> snapshot (%d) "
			       "branches: block=0x%llx, count=0x%x, k=%d/%d, "
			       "moved_blocks=%d\n", src->i_generation,
			       dst->i_generation, SNAPSHOT_BLOCK(iblock),
			       count, kd, depth, moved);
		/* update src and dst inodes blocks usage */
		dquot_free_block(src, moved);
		dquot_alloc_block_nofail(dst, moved);
		err = ext4_handle_dirty_metadata(handle, NULL, pD->bh);
		if (err)
			goto out;
		err = ext4_handle_dirty_metadata(handle, NULL, pS->bh);
		if (err)
			goto out;
	}

	/* we merged at least 1 partial branch and optionally count-1 full
	   branches */
	err = (count << data_ptrs_bits) -
		(SNAPSHOT_BLOCK(iblock) & data_ptrs_mask);
out:
	/* count_branch_blocks may use the entire depth of S */
	for (ks = 1; ks < depth; ks++) {
		if (S[ks].bh)
			brelse(S[ks].bh);
		if (ks <= kd)
			brelse(D[ks].bh);
	}
	return err < maxblocks ? err : maxblocks;
}

#endif

#ifdef CONFIG_EXT4_FS_SNAPSHOT_FILE_READ
/*
 * ext4_snapshot_get_block_access() - called from ext4_snapshot_read_through()
 * on snapshot file access.
 * return value <0 indicates access not granted
 * return value 0 indicates snapshot inode read through access
 * in which case 'prev_snapshot' is pointed to the previous snapshot
 * on the list or set to NULL to indicate read through to block device.
 */
#ifdef CONFIG_EXT4_FS_SNAPSHOT_LIST_READ
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

static int ext4_snapshot_get_block_access(struct inode *inode,
		struct inode **prev_snapshot)
{
	struct ext4_inode_info *ei = EXT4_I(inode);
	unsigned int flags = ei->i_flags;
#ifdef CONFIG_EXT4_FS_SNAPSHOT_LIST_READ
	struct list_head *prev = ei->i_snaplist.prev;
#endif

#ifdef CONFIG_EXT4_FS_SNAPSHOT_LIST_READ
	if (!(flags & EXT4_SNAPFILE_LIST_FL)) 
	  	/* snapshot not on the list - read/write access denied */
		return -EPERM;
	
#endif

	/*
	 * Snapshot image read through access: (!cmd && !handle)
	 * indicates this is ext4_snapshot_readpage()
	 * calling ext4_snapshot_get_block()
	 */
	*prev_snapshot = NULL;
#ifdef CONFIG_EXT4_FS_SNAPSHOT_LIST_READ
	if (ext4_snapshot_is_active(inode) ||
			(flags & EXT4_SNAPFILE_ACTIVE_FL))
		/* read through from active snapshot to block device */
		return 0;

	if (list_empty(prev))
		/* not on snapshots list? */
		return -EIO;

	if (prev == &EXT4_SB(inode->i_sb)->s_snapshot_list)
		/* active snapshot not found on list? */
		return -EIO;

	/* read through to prev snapshot on the list */
	ei = list_entry(prev, struct ext4_inode_info, i_snaplist);
	*prev_snapshot = &ei->vfs_inode;

	if (!ext4_snapshot_file(*prev_snapshot))
		/* non snapshot file on the list? */
		return -EIO;

	return 0;

#endif
}

/*
 * ext4_snapshot_get_blockdev_access - get read through access to block device.
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
static int ext4_snapshot_get_blockdev_access(struct super_block *sb,
				   struct buffer_head *bh)
{
	unsigned long block_group = SNAPSHOT_BLOCK_GROUP(bh->b_blocknr);
	ext4_grpblk_t bit = SNAPSHOT_BLOCK_GROUP_OFFSET(bh->b_blocknr);
	struct buffer_head *bitmap_bh;
#ifdef CONFIG_EXT4_FS_SNAPSHOT_EXCLUDE_BITMAP
	struct buffer_head *exclude_bitmap_bh = NULL;
#endif
	int err = 0;

	if (PageReadahead(bh->b_page))
		return 0;

	bitmap_bh = ext4_read_block_bitmap(sb, block_group);
	if (!bitmap_bh)
		return -EIO;

	if (!ext4_test_bit(bit, bitmap_bh->b_data)) {
		snapshot_debug(2, "warning: attempt to read through to "
				"non-allocated block [%d/%lu] - read ahead?\n",
				bit, block_group);
		brelse(bitmap_bh);
		return -EIO;
	}

#ifdef CONFIG_EXT4_FS_SNAPSHOT_EXCLUDE_BITMAP
	exclude_bitmap_bh = ext4_read_exclude_bitmap(sb, block_group);
	if (exclude_bitmap_bh &&
		ext4_test_bit(bit, exclude_bitmap_bh->b_data)) {
		snapshot_debug(2, "warning: attempt to read through to "
				"excluded block [%d/%lu] - read ahead?\n",
				bit, block_group);
		err = -EIO;
	}
#endif

#ifdef CONFIG_EXT4_FS_SNAPSHOT_EXCLUDE_BITMAP
	brelse(exclude_bitmap_bh);
#endif
	brelse(bitmap_bh);
	return err;
}

/*
 * ext4_snapshot_read_through - get snapshot image block.
 * On read of snapshot file, an unmapped block is a peephole to prev snapshot.
 * On read of active snapshot, an unmapped block is a peephole to the block
 * device.  On first block write, the peephole is filled forever.
 */
static int ext4_snapshot_read_through(struct inode *inode, sector_t iblock,
				      struct buffer_head *bh_result)
{
	int err;
	struct ext4_map_blocks map;
	struct inode *prev_snapshot;
#ifdef CONFIG_EXT4_FS_SNAPSHOT_RACE_COW
	struct buffer_head *sbh = NULL;
#endif

	map.m_lblk = iblock;
	map.m_pblk = 0;
	map.m_len = bh_result->b_size >> inode->i_blkbits;

#ifdef CONFIG_EXT4_FS_SNAPSHOT_LIST_READ
get_block:
#endif
	prev_snapshot = NULL;
	/* request snapshot file read access */
	err = ext4_snapshot_get_block_access(inode, &prev_snapshot);
	if (err < 0)
		return err;
#ifdef CONFIG_EXT4_FS_SNAPSHOT_RACE_READ
		if (!prev_snapshot) {
		/*
		 * Possible read through to block device.
		 * Start tracked read before checking if block is mapped to
		 * avoid race condition with COW that maps the block after
		 * we checked if the block is mapped.  If we find that the
		 * block is mapped, we will cancel the tracked read before
		 * returning from this function.
		 */
		map_bh(bh_result, inode->i_sb, SNAPSHOT_BLOCK(iblock));
		err = start_buffer_tracked_read(bh_result);
		if (err < 0) {
			snapshot_debug(1,
					"snapshot (%u) failed to start "
					"tracked read on block (%lld) "
					"(err=%d)\n", inode->i_generation,
					(long long)bh_result->b_blocknr, err);
			return err;
		}
	}
#endif
	err = ext4_map_blocks(NULL, inode, &map, 0);
	snapshot_debug(4, "ext4_snapshot_read_through(%lld): block = "
		       "(%lld), err = %d\n prev_snapshot = %u",
		       (long long)iblock, map.m_pblk, err,
		       prev_snapshot ? prev_snapshot ->i_generation : 0);
#ifdef CONFIG_EXT4_FS_SNAPSHOT_RACE_READ
	/* if it's not a hole - cancel tracked read before we deadlock
	 * on pending COW */
	if (err && buffer_tracked_read(bh_result))
		cancel_buffer_tracked_read(bh_result);
#endif
	if (err < 0)
		return err;
#ifdef CONFIG_EXT4_FS_SNAPSHOT_LIST_READ
	if (!err && prev_snapshot) {
		/* hole in snapshot - check again with prev snapshot */
		inode = prev_snapshot;
		goto get_block;
	}
#endif
	if (!err)
		/* hole in active snapshot - read though to block device */
		return 0;

	map_bh(bh_result, inode->i_sb, map.m_pblk);
	bh_result->b_state = (bh_result->b_state & ~EXT4_MAP_FLAGS) |
		map.m_flags;

#ifdef CONFIG_EXT4_FS_SNAPSHOT_RACE_COW
	/*
	 * On read of active snapshot, a mapped block may belong to a non
	 * completed COW operation.  Use the buffer cache to test this
	 * condition.  if (bh_result->b_blocknr == SNAPSHOT_BLOCK(iblock)),
	 * then this is either read through to block device or moved block.
	 * Either way, it is not a COWed block, so it cannot be pending COW.
	 */
	if (ext4_snapshot_is_active(inode) &&
	    bh_result->b_blocknr != SNAPSHOT_BLOCK(iblock))
		sbh = sb_find_get_block(inode->i_sb, bh_result->b_blocknr);
	if (!sbh)
		return 0;
	/* wait for pending COW to complete */
	ext4_snapshot_test_pending_cow(sbh, SNAPSHOT_BLOCK(iblock));
	lock_buffer(sbh);
	if (buffer_uptodate(sbh)) {
		/*
		 * Avoid disk I/O and copy out snapshot page directly
		 * from block device page when possible.
		 */
		BUG_ON(!sbh->b_page);
		BUG_ON(!bh_result->b_page);
		lock_buffer(bh_result);
		copy_highpage(bh_result->b_page, sbh->b_page);
		set_buffer_uptodate(bh_result);
		unlock_buffer(bh_result);
	} else if (buffer_dirty(sbh)) {
		/*
		 * If snapshot data buffer is dirty (just been COWed),
		 * then it is not safe to read it from disk yet.
		 * We shouldn't get here because snapshot data buffer
		 * only becomes dirty during COW and because we waited
		 * for pending COW to complete, which means that a
		 * dirty snapshot data buffer should be uptodate.
		 */
		WARN_ON(1);
	}
	unlock_buffer(sbh);
	brelse(sbh);
#endif
	return 0;
}

static int ext4_snapshot_get_block(struct inode *inode, sector_t iblock,
			struct buffer_head *bh_result, int create)
{
	unsigned long block_group;
	struct ext4_group_desc *desc;
	struct ext4_group_info *grp;
	ext4_fsblk_t bitmap_blk = 0;
	int err;

	BUG_ON(create != 0);
	BUG_ON(buffer_tracked_read(bh_result));

	err = ext4_snapshot_read_through(inode, SNAPSHOT_IBLOCK(iblock),
					 bh_result);
	snapshot_debug(4, "ext4_snapshot_get_block(%lld): block = (%lld), "
		       "err = %d\n",
		       (long long)iblock, buffer_mapped(bh_result) ?
		       (long long)bh_result->b_blocknr : 0, err);
	if (err < 0)
		return err;

	if (!buffer_tracked_read(bh_result))
		return 0;

	/* check for read through to block bitmap */
	block_group = SNAPSHOT_BLOCK_GROUP(bh_result->b_blocknr);
	desc = ext4_get_group_desc(inode->i_sb, block_group, NULL);
	if (desc)
		bitmap_blk = ext4_block_bitmap(inode->i_sb, desc);
	if (bitmap_blk && bitmap_blk == bh_result->b_blocknr) {
		/* copy fixed block bitmap directly to page buffer */
		cancel_buffer_tracked_read(bh_result);
		/* cancel_buffer_tracked_read() clears mapped flag */
		set_buffer_mapped(bh_result);
		snapshot_debug(2, "fixing snapshot block bitmap #%lu\n",
			       block_group);
		/*
		 * XXX: if we return unmapped buffer, the page will be zeroed
		 * but if we return mapped to block device and uptodate buffer
		 * next readpage may read directly from block device without
		 * fixing block bitmap.  This only affects fsck of snapshots.
		 */
		return ext4_snapshot_read_block_bitmap(inode->i_sb,
						       block_group, bh_result);
	}
	/* check for read through to exclude bitmap */
	grp = ext4_get_group_info(inode->i_sb, block_group);
	bitmap_blk = grp->bg_exclude_bitmap;
	if (bitmap_blk && bitmap_blk == bh_result->b_blocknr) {
		/* return unmapped buffer to zero out page */
		cancel_buffer_tracked_read(bh_result);
		/* cancel_buffer_tracked_read() clears mapped flag */
		snapshot_debug(2, "zeroing snapshot exclude bitmap #%lu\n",
			       block_group);
		return 0;
	}

#ifdef CONFIG_EXT4_FS_DEBUG
	snapshot_debug(3, "started tracked read: block = [%llu/%llu]\n",
		       SNAPSHOT_BLOCK_TUPLE(bh_result->b_blocknr));
	if (snapshot_enable_test[SNAPTEST_READ]) {
		err = ext4_snapshot_get_blockdev_access(inode->i_sb,
						    bh_result);
		if (err) {
			/* read through access denied */
			cancel_buffer_tracked_read(bh_result);
			return err;
		}
		/* sleep 1 tunable delay unit */
		snapshot_test_delay(SNAPTEST_READ);
	}
#endif
		return 0;
}

int ext4_snapshot_readpage(struct file *file, struct page *page)
{
	/* do read I/O with buffer heads to enable tracked reads */
	return ext4_read_full_page(page, ext4_snapshot_get_block);
}
#endif
