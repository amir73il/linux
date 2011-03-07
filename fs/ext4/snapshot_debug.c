/*
 * linux/fs/ext4/snapshot_debug.c
 *
 * Written by Amir Goldstein <amir73il@users.sf.net>, 2008
 *
 * Copyright (C) 2008-2010 CTERA Networks
 *
 * This file is part of the Linux kernel and is made available under
 * the terms of the GNU General Public License, version 2, or at your
 * option, any later version, incorporated herein by reference.
 *
 * Ext4 snapshot debugging.
 */


#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/debugfs.h>
#include "snapshot.h"

/*
 * debugfs tunables
 */

const char *snapshot_indent = SNAPSHOT_INDENT_STR + SNAPSHOT_INDENT_MAX;

/*
 * Tunable delay values per snapshot operation for testing of
 * COW race conditions and master snapshot_mutex lock
 */
static const char *snapshot_test_names[SNAPSHOT_TESTS_NUM] = {
	/* delay completion of snapshot create|take */
	"test-take-delay-msec",
	/* delay completion of snapshot shrink|cleanup */
	"test-delete-delay-msec",
	/* delay completion of COW operation */
	"test-cow-delay-msec",
	/* delay submission of tracked read */
	"test-read-delay-msec",
	/* delay completion of COW bitmap operation */
	"test-bitmap-delay-msec",
};

#define SNAPSHOT_TEST_NAMES (sizeof(snapshot_test_names) / \
			     sizeof(snapshot_test_names[0]))

u16 snapshot_enable_test[SNAPSHOT_TESTS_NUM] __read_mostly = {0};
u8 snapshot_enable_debug __read_mostly = 1;
#ifdef CONFIG_EXT4_FS_SNAPSHOT_JOURNAL_CACHE
u8 cow_cache_offset __read_mostly = 0;
#endif

static struct dentry *snapshot_debug;
static struct dentry *snapshot_version;
static struct dentry *snapshot_test[SNAPSHOT_TESTS_NUM];
#ifdef CONFIG_EXT4_FS_SNAPSHOT_JOURNAL_CACHE
static struct dentry *cow_cache;
#endif

static char snapshot_version_str[] = EXT4_SNAPSHOT_VERSION;
static struct debugfs_blob_wrapper snapshot_version_blob = {
	.data = snapshot_version_str,
	.size = sizeof(snapshot_version_str)
};


/*
 * ext4_snapshot_create_debugfs_entry - register ext4 snapshot debug hooks
 * Void function doesn't return error if debug hooks are not registered.
 */
void ext4_snapshot_create_debugfs_entry(struct dentry *debugfs_dir)
{
	int i;

	BUG_ON(!debugfs_dir);
	snapshot_debug = debugfs_create_u8("snapshot-debug", S_IRUGO|S_IWUSR,
					   debugfs_dir,
					   &snapshot_enable_debug);
	snapshot_version = debugfs_create_blob("snapshot-version", S_IRUGO,
					       debugfs_dir,
					       &snapshot_version_blob);
	for (i = 0; i < SNAPSHOT_TESTS_NUM && i < SNAPSHOT_TEST_NAMES; i++)
		snapshot_test[i] = debugfs_create_u16(snapshot_test_names[i],
					      S_IRUGO|S_IWUSR,
					      debugfs_dir,
					      &snapshot_enable_test[i]);
#ifdef CONFIG_EXT4_FS_SNAPSHOT_JOURNAL_CACHE
	cow_cache = debugfs_create_u8("cow-cache", S_IRUGO,
					   debugfs_dir,
					   &cow_cache_offset);
#endif
}

/*
 * ext4_snapshot_remove_debugfs_entry - unregister ext4 snapshot debug hooks
 * checks if the hooks have been registered before unregistering them.
 */
void ext4_snapshot_remove_debugfs_entry(void)
{
	int i;

#ifdef CONFIG_EXT4_FS_SNAPSHOT_JOURNAL_CACHE
	if (cow_cache)
		debugfs_remove(cow_cache);
#endif
	for (i = 0; i < SNAPSHOT_TESTS_NUM && i < SNAPSHOT_TEST_NAMES; i++)
		if (snapshot_test[i])
			debugfs_remove(snapshot_test[i]);
	if (snapshot_version)
		debugfs_remove(snapshot_version);
	if (snapshot_debug)
		debugfs_remove(snapshot_debug);
}



#ifdef CONFIG_EXT4_FS_SNAPSHOT_CTL_DUMP
/* snapshot dump state */
struct ext4_dump_info {
	struct inode *di_inode; /* snapshot inode */
	int nmeta;	/* no. of meta blocks */
	int nind;	/* no. of ind blocks */
	int ncopied;	/* no. of copied data blocks */
	int nmoved;	/* no. of moved data blocks */
};

/*
 * ext4_snapshot_dump_read_array - read array of blocks and print header
 *	@n:	prints debug level
 *	@l:	prints indentation level
 *	@di:	snapshot dump state
 *	@nr:	address of indirect block
 *	@name:	print name of array (ind/dind/tind)
 *	@idx:	index of indirect block
 *
 * Sample output:
 *		ind[1120] = [30729/35]
 *
 * Returns buffer of blocks array
 */
static struct buffer_head *ext4_snapshot_read_array(int n, int l,
	struct ext4_dump_info *di,
		u32 nr, const char *name, int idx)
{
	struct buffer_head *bh;

	snapshot_debug_l(n, l, "%s[%d] = [%u/%u]\n", name, idx,
			SNAPSHOT_BLOCK_GROUP_OFFSET(nr),
			SNAPSHOT_BLOCK_GROUP(nr));
	di->nind++;

	bh = sb_bread(di->di_inode->i_sb, nr);
	if (!bh)
		snapshot_debug_l(n, l+1, "I/O error: failed to read block!\n");
	return bh;
}

/*
 * ext4_snapshot_dump_ind - dump indirect block
 *	@n:	prints debug level
 *	@l:	prints indentation level
 *	@di:	snapshot dump state
 *	@nr:	address of indirect block
 *	@idx:	index of indirect block
 *
 * Sample output:
 *		ind[1120] = [30729/35]
 *		{
 *			block[0-2/35] = [30730-30732/35]
 *		}
 */
static void ext4_snapshot_dump_ind(int n, int l,
		struct ext4_dump_info *di,
		u32 nr, int idx)
{
	/* buffer of data blocks array */
	struct buffer_head *bh;
	/* prev and curr data block address */
	u32 prev_key, key = 0;
	/* logical snapshot block (inode offset) */
	u32 blk = idx << SNAPSHOT_ADDR_PER_BLOCK_BITS;
	/* logical snapshot block group/start */
	u32 b0 = blk - SNAPSHOT_BLOCK_GROUP_OFFSET(blk);
	u32 grp = SNAPSHOT_BLOCK_GROUP(blk);
	int i, k = 0;

	bh = ext4_snapshot_read_array(n, l, di, nr, "ind", idx);
	if (!bh)
		return;

	snapshot_debug_l(n, l, "{\n");
	/* iterate on data blocks array */
	for (i = 0; i <= SNAPSHOT_ADDR_PER_BLOCK; i++, blk++) {
		prev_key = key;
		if (i < SNAPSHOT_ADDR_PER_BLOCK)
			/* read curr mapped block address */
			key = le32_to_cpu(((__le32 *)bh->b_data)[i]);
		else
			/* terminate mapped blocks array */
			key = 0;

		if (!prev_key)
			/* skip unmapped blocks */
			continue;
		if (key == prev_key+1) {
			/* count subsequent mapped blocks */
			k++;
			continue;
		}

		if (k == 0) {
			/* (blk-1) is a group of 1 */
			if (prev_key == blk - 1) {
				/* print moved block */
				snapshot_debug_l(n, l+1,
					"block[%u/%u]\n",
					blk-1-b0, grp);
				di->nmoved++;
			} else {
				/* print copied block */
				snapshot_debug_l(n, l+1, "block[%u/%u]"
					" = [%u/%u]\n",
					blk-1-b0, grp,
					SNAPSHOT_BLOCK_GROUP_OFFSET(prev_key),
					SNAPSHOT_BLOCK_GROUP(prev_key));
				di->ncopied++;
			}
			continue;
		}

		/* (blk-1)-k..(blk-1) is a group of k+1 subsequent blocks */
		if (prev_key == blk - 1) {
			/* print group of subsequent moved blocks */
			snapshot_debug_l(n, l+1,
				"block[%u-%u/%u]\n",
			blk-1-k-b0, blk-1-b0, grp);
			di->nmoved += k+1;
		} else {
			/* print group of subsequent copied blocks */
			snapshot_debug_l(n, l+1, "block[%u-%u/%u]"
				" = [%u-%u/%u]\n",
				blk-1-k-b0, blk-1-b0, grp,
				SNAPSHOT_BLOCK_GROUP_OFFSET(prev_key)-k,
				SNAPSHOT_BLOCK_GROUP_OFFSET(prev_key),
			SNAPSHOT_BLOCK_GROUP(prev_key));
			di->ncopied += k+1;
		}
		/* reset subsequent blocks count */
		k = 0;
	}
	snapshot_debug_l(n, l, "}\n");
	brelse(bh);
}

/*
 * ext4_snapshot_dump_dind - dump double indirect block
 *	@n:	prints debug level
 *	@l:	prints indentation level
 *	@di:	snapshot dump state
 *	@nr:	address of double indirect block
 *	@idx:	index of double indirect block
 *
 * Sample output:
 *	dind[1] = [30728/35]
 *	{
 *		ind[1120] = [30729/35]
 *		{
 *			block[0-2/35] = [30730-30732/35]
 *		}
 *		...
 */
static void ext4_snapshot_dump_dind(int n, int l,
		struct ext4_dump_info *di,
	u32 nr, int idx)
{
	/* buffer of indirect blocks array */
	struct buffer_head *bh;
	/* curr indirect block address */
	u32 key;
	int i;

	bh = ext4_snapshot_read_array(n, l, di, nr, "dind", idx);
	if (!bh)
		return;

	snapshot_debug_l(n, l, "{\n");
	for (i = 0; i < SNAPSHOT_ADDR_PER_BLOCK; i++) {
		key = le32_to_cpu(((__le32 *)bh->b_data)[i]);
		if (!key)
			continue;
		ext4_snapshot_dump_ind(n, l+1, di, key,
				(idx << SNAPSHOT_ADDR_PER_BLOCK_BITS) + i);
	}
	snapshot_debug_l(n, l, "}\n");
	brelse(bh);
}

/*
 * ext4_snapshot_dump_tind - dump triple indirect block
 *	@n:	prints debug level
 *	@l:	prints indentation level
 *	@di:	snapshot dump state
 *	@nr:	address of triple indirect block
 *	@idx:	index of triple indirect block
 *
 * Sample output:
 * tind[0] = [30721/35]
 * {
 *	dind[1] = [30728/35]
 *	{
 *		ind[1120] = [30729/35]
 *		{
 *			block[0-2/35] = [30730-30732/35]
 *		}
 *		...
 */
static void ext4_snapshot_dump_tind(int n, int l,
		struct ext4_dump_info *di,
		u32 nr, int idx)
{
	/* buffer of indirect blocks array */
	struct buffer_head *bh;
	/* curr indirect block address */
	u32 key;
	int i;

	bh = ext4_snapshot_read_array(n, l, di, nr, "tind", idx);
	if (!bh)
		return;

	snapshot_debug_l(n, l, "{\n");
	for (i = 0; i < SNAPSHOT_ADDR_PER_BLOCK; i++) {
		key = le32_to_cpu(((__le32 *)bh->b_data)[i]);
		if (!key)
			continue;
		ext4_snapshot_dump_dind(n, l+1, di, key,
				(idx << SNAPSHOT_ADDR_PER_BLOCK_BITS) + i + 1);
	}
	snapshot_debug_l(n, l, "}\n");
	brelse(bh);
}

/*
 * ext4_snapshot_dump - dump snapshot inode blocks map
 *	@n:	prints debug level
 *	@inode:	snapshot inode
 *
 * Called from snapshot_load() for all snapshots under sb_lock, on f/s mount.
 * Called from snapshot_take() under i_mutex and snapshot_mutex.
 * Called from snapshot_set_flags() under i_mutex and snapshot_mutex,
 * when setting the 'No_Dump' flag of a snapshot file (chattr +d).
 * The 'No_Dump' flag is cleared at the end of snapshot_dump().
 *
 * Sample output:
 * snapshot (4) block map:
 * dind[0] = [30720/35]
 * {
 *	ind[0] = [30722/35]
 *	{
 *		block[0-1/0] = [30723-30724/35]
 *		block[129-131/0] = [30725-30727/35]
 *	}
 * }
 * tind[0] = [30721/35]
 * {
 *	dind[1] = [30728/35]
 *	{
 *		ind[1120] = [30729/35]
 *		{
 *			block[0-2/35] = [30730-30732/35]
 *		}
 *		ind[1124] = [30733/35]
 *		{
 *			block[4097/35] = [30734/35]
 *			block[4103/35]
 *			block[4108/35]
 *		}
 *	}
 * }
 * snapshot (4) contains: 0 (meta) + 6 (indirect) + 11 (data) = 17 blocks = 68K
 * snapshot (4) maps: 9 (copied) + 2 (moved) = 11 blocks
 */
void ext4_snapshot_dump(int n, struct inode *inode)
{
	struct ext4_inode_info *ei = EXT4_I(inode);
	struct ext4_dump_info di;
	u32 nr;
	int i, nblocks;

	if (n > snapshot_enable_debug)
		return;

	memset(&di, 0, sizeof(di));
	di.di_inode = inode;

	snapshot_debug(n, "snapshot (%u) block map:\n", inode->i_generation);
	/* print direct blocks (snapshot meta blocks) */
	for (i = 0; i < EXT4_NDIR_BLOCKS; i++) {
		if (ei->i_data[i]) {
			nr = le32_to_cpu(ei->i_data[i]);
			snapshot_debug_l(n, 0, "meta[%d] = [%u/%u] !!!\n", i,
					SNAPSHOT_BLOCK_GROUP_OFFSET(nr),
					SNAPSHOT_BLOCK_GROUP(nr));
			di.nmeta++;
		}
	}
	/* print indirect branch (snapshot reserved blocks) */
	nr = le32_to_cpu(ei->i_data[i++]);
	if (nr)
		snapshot_debug_l(n, 0, "ind[-1] = [%u/%u] !!!\n",
				SNAPSHOT_BLOCK_GROUP_OFFSET(nr),
				SNAPSHOT_BLOCK_GROUP(nr));
	/* print double indirect branch (start of snapshot image) */
	nr = le32_to_cpu(ei->i_data[i++]);
	if (nr)
		ext4_snapshot_dump_dind(n, 0, &di, nr, 0);
	/* print triple indirect branches (rest of snapshot image) */
	do {
		nr = le32_to_cpu(ei->i_data[i%EXT4_N_BLOCKS]);
		if (nr)
			ext4_snapshot_dump_tind(n, 0, &di, nr,
					i - EXT4_TIND_BLOCK);
	} while (++i < EXT4_SNAPSHOT_N_BLOCKS);

	nblocks = di.nmeta + di.nind + di.ncopied + di.nmoved;
	snapshot_debug(n, "snapshot (%u) contains: %d (meta) + %d (indirect) "
		       "+ %d (data) = %d blocks = %dK = %dM\n",
		       inode->i_generation,
		       di.nmeta, di.nind, di.ncopied + di.nmoved,
		       nblocks, nblocks << (SNAPSHOT_BLOCK_SIZE_BITS - 10),
		       nblocks >> (20 - SNAPSHOT_BLOCK_SIZE_BITS));
	snapshot_debug(n, "snapshot (%u) maps: %d (copied) + %d (moved) = "
		       "%d blocks\n", inode->i_generation,
		       di.ncopied, di.nmoved, di.ncopied + di.nmoved);
}
#endif
