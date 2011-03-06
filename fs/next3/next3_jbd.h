/*
 * linux/fs/next3/next3_jbd.h
 *
 * Written by Stephen C. Tweedie <sct@redhat.com>, 1999
 *
 * Copyright 1998--1999 Red Hat corp --- All Rights Reserved
 *
 * This file is part of the Linux kernel and is made available under
 * the terms of the GNU General Public License, version 2, or at your
 * option, any later version, incorporated herein by reference.
 *
 * Next3-specific journaling extensions.
 *
 * Copyright (C) 2008-2010 CTERA Networks
 * Added snapshot support, Amir Goldstein <amir73il@users.sf.net>, 2008
 */

#ifndef _LINUX_NEXT3_JBD_H
#define _LINUX_NEXT3_JBD_H

#include <linux/fs.h>
#include <linux/jbd.h>
#include "next3.h"
#include "snapshot_debug.h"

#define NEXT3_JOURNAL(inode)	(NEXT3_SB((inode)->i_sb)->s_journal)

/* Define the number of blocks we need to account to a transaction to
 * modify one block of data.
 *
 * We may have to touch one inode, one bitmap buffer, up to three
 * indirection blocks, the group and superblock summaries, and the data
 * block to complete the transaction.  */

#define NEXT3_SINGLEDATA_TRANS_BLOCKS	8U

/* Extended attribute operations touch at most two data buffers,
 * two bitmap buffers, and two group summaries, in addition to the inode
 * and the superblock, which are already accounted for. */

#define NEXT3_XATTR_TRANS_BLOCKS		6U

/* Define the minimum size for a transaction which modifies data.  This
 * needs to take into account the fact that we may end up modifying two
 * quota files too (one for the group, one for the user quota).  The
 * superblock only gets updated once, of course, so don't bother
 * counting that again for the quota updates. */

#define NEXT3_DATA_TRANS_BLOCKS(sb)	(NEXT3_SINGLEDATA_TRANS_BLOCKS + \
					 NEXT3_XATTR_TRANS_BLOCKS - 2 + \
					 NEXT3_MAXQUOTAS_TRANS_BLOCKS(sb))

/* Delete operations potentially hit one directory's namespace plus an
 * entire inode, plus arbitrary amounts of bitmap/indirection data.  Be
 * generous.  We can grow the delete transaction later if necessary. */

#define NEXT3_DELETE_TRANS_BLOCKS(sb)   (NEXT3_MAXQUOTAS_TRANS_BLOCKS(sb) + 64)

/* Define an arbitrary limit for the amount of data we will anticipate
 * writing to any given transaction.  For unbounded transactions such as
 * write(2) and truncate(2) we can write more than this, but we always
 * start off at the maximum transaction size and grow the transaction
 * optimistically as we go. */

#define NEXT3_MAX_TRANS_DATA		64U

/* We break up a large truncate or write transaction once the handle's
 * buffer credits gets this low, we need either to extend the
 * transaction or to start a new one.  Reserve enough space here for
 * inode, bitmap, superblock, group and indirection updates for at least
 * one block, plus two quota updates.  Quota allocations are not
 * needed. */

#ifdef CONFIG_NEXT3_FS_SNAPSHOT_JOURNAL_CREDITS
/* on block write we have to journal the block itself */
#define NEXT3_WRITE_CREDITS 1
/* on snapshot block alloc we have to journal block group bitmap, exclude
   bitmap and gdb */
#define NEXT3_ALLOC_CREDITS 3
/* number of credits for COW bitmap operation (allocated blocks are not
   journalled): alloc(dind+ind+cow) = 9 */
#define NEXT3_COW_BITMAP_CREDITS	(3*NEXT3_ALLOC_CREDITS)
/* number of credits for other block COW operations:
   alloc(ind+cow)+write(dind+ind) = 8 */
#define NEXT3_COW_BLOCK_CREDITS	(2*NEXT3_ALLOC_CREDITS+2*NEXT3_WRITE_CREDITS)
/* number of credits for the first COW operation in the block group:
   9+8 = 17 */
#define NEXT3_COW_CREDITS	(NEXT3_COW_BLOCK_CREDITS +	\
				 NEXT3_COW_BITMAP_CREDITS)
/* number of credits for snapshot operations counted once per transaction:
   write(sb+inode+tind) = 3 */
#define NEXT3_SNAPSHOT_CREDITS 	(3*NEXT3_WRITE_CREDITS)
/*
 * in total, for N COW operations, we may have to journal 17N+3 blocks,
 * and we also want to reserve 17+3 credits for the last COW operation,
 * so we add 17(N-1)+3+(17+3) to the requested N buffer credits
 * and request 18N+6 buffer credits.
 *
 * we are going to need a bigger journal to accommodate the
 * extra snapshot credits.
 * mke2fs uses the following default formula for fs-size above 1G:
 * journal-size = MIN(128M, fs-size/32)
 * use the following formula and override the default (-J size=):
 * journal-size = MIN(3G, fs-size/32)
 */
#define NEXT3_SNAPSHOT_TRANS_BLOCKS(n) \
	((n)*(1+NEXT3_COW_CREDITS)+NEXT3_SNAPSHOT_CREDITS)
#define NEXT3_SNAPSHOT_START_TRANS_BLOCKS(n) \
	((n)*(1+NEXT3_COW_CREDITS)+2*NEXT3_SNAPSHOT_CREDITS)

/*
 * check for sufficient buffer and COW credits
 */
#define NEXT3_SNAPSHOT_HAS_TRANS_BLOCKS(handle, n)			\
	((handle)->h_buffer_credits >= NEXT3_SNAPSHOT_TRANS_BLOCKS(n) && \
	 ((next3_handle_t *)(handle))->h_user_credits >= (n))

#define NEXT3_RESERVE_COW_CREDITS	(NEXT3_COW_CREDITS +		\
					 NEXT3_SNAPSHOT_CREDITS)

/*
 * Next3 is not designed for filesystems under 4G with journal size < 128M
 * Recommended journal size is 2G (created with 'mke2fs -j -J big')
 */
#define NEXT3_MIN_JOURNAL_BLOCKS	32768U
#define NEXT3_BIG_JOURNAL_BLOCKS	(16*NEXT3_MIN_JOURNAL_BLOCKS)
#else
#define NEXT3_SNAPSHOT_HAS_TRANS_BLOCKS(handle, n) \
	(handle->h_buffer_credits >= (n))
#endif

#define NEXT3_RESERVE_TRANS_BLOCKS	12U

#define NEXT3_INDEX_EXTRA_TRANS_BLOCKS	8

#ifdef CONFIG_QUOTA
/* Amount of blocks needed for quota update - we know that the structure was
 * allocated so we need to update only inode+data */
#define NEXT3_QUOTA_TRANS_BLOCKS(sb) (test_opt(sb, QUOTA) ? 2 : 0)
/* Amount of blocks needed for quota insert/delete - we do some block writes
 * but inode, sb and group updates are done only once */
#define NEXT3_QUOTA_INIT_BLOCKS(sb) (test_opt(sb, QUOTA) ? (DQUOT_INIT_ALLOC*\
		(NEXT3_SINGLEDATA_TRANS_BLOCKS-3)+3+DQUOT_INIT_REWRITE) : 0)
#define NEXT3_QUOTA_DEL_BLOCKS(sb) (test_opt(sb, QUOTA) ? (DQUOT_DEL_ALLOC*\
		(NEXT3_SINGLEDATA_TRANS_BLOCKS-3)+3+DQUOT_DEL_REWRITE) : 0)
#else
#define NEXT3_QUOTA_TRANS_BLOCKS(sb) 0
#define NEXT3_QUOTA_INIT_BLOCKS(sb) 0
#define NEXT3_QUOTA_DEL_BLOCKS(sb) 0
#endif
#define NEXT3_MAXQUOTAS_TRANS_BLOCKS(sb) (MAXQUOTAS*NEXT3_QUOTA_TRANS_BLOCKS(sb))
#define NEXT3_MAXQUOTAS_INIT_BLOCKS(sb) (MAXQUOTAS*NEXT3_QUOTA_INIT_BLOCKS(sb))
#define NEXT3_MAXQUOTAS_DEL_BLOCKS(sb) (MAXQUOTAS*NEXT3_QUOTA_DEL_BLOCKS(sb))

#ifdef CONFIG_NEXT3_FS_SNAPSHOT_BLOCK
/*
 * This struct is binary compatible to struct handle_s in include/linux/jbd.h
 * for building a standalone next3 module.
 * XXX: be aware of changes to the original struct!!!
 */
struct next3_handle_s
{
	/* Which compound transaction is this update a part of? */
	transaction_t		*h_transaction;

	/* Number of remaining buffers we are allowed to dirty: */
	int			h_buffer_credits;

	/* Reference count on this handle */
	int			h_ref;

	/* Field for caller's use to track errors through large fs */
	/* operations */
	int			h_err;

	/* Flags [no locking] */
	unsigned int	h_sync:		1;	/* sync-on-close */
	unsigned int	h_jdata:	1;	/* force data journaling */
	unsigned int	h_aborted:	1;	/* fatal error on handle */
	unsigned int	h_cowing:	1;	/* COWing block to snapshot */
#ifdef CONFIG_NEXT3_FS_SNAPSHOT_JOURNAL_CREDITS
	/* Number of buffers requested by user:
	 * (before adding the COW credits factor) */
	unsigned int	h_base_credits:	14;

	/* Number of buffers the user is allowed to dirty:
	 * (counts only buffers dirtied when !h_cowing) */
	unsigned int	h_user_credits:	14;
#endif

#ifdef CONFIG_DEBUG_LOCK_ALLOC
	struct lockdep_map	h_lockdep_map;
#endif
#ifdef CONFIG_NEXT3_FS_SNAPSHOT_JOURNAL_TRACE

#ifdef CONFIG_JBD_DEBUG
	/* Statistics counters: */
	unsigned int h_cow_moved; /* blocks moved to snapshot */
	unsigned int h_cow_copied; /* blocks copied to snapshot */
	unsigned int h_cow_ok_jh; /* blocks already COWed during current
				     transaction */
	unsigned int h_cow_ok_bitmap; /* blocks not set in COW bitmap */
	unsigned int h_cow_ok_mapped;/* blocks already mapped in snapshot */
	unsigned int h_cow_bitmaps; /* COW bitmaps created */
	unsigned int h_cow_excluded; /* blocks set in exclude bitmap */
#endif
#endif
};

#ifndef _NEXT3_HANDLE_T
#define _NEXT3_HANDLE_T
typedef struct next3_handle_s		next3_handle_t;	/* Next3 COW handle */
#endif

#define IS_COWING(handle) \
	((next3_handle_t *)(handle))->h_cowing

#ifdef CONFIG_NEXT3_FS_SNAPSHOT_JOURNAL_TRACE
/*
 * macros for next3 to update transaction COW statistics.
 * when next3 is compiled as a module with CONFIG_JBD_DEBUG,
 * if sizeof(next3_handle_t) doesn't match the sizeof(handle_t),
 * then the kernel was compiled without CONFIG_JBD_DEBUG or without the next3
 * patch and the h_cow_* fields are not allocated in handle objects.
 */
#ifdef CONFIG_JBD_DEBUG
#define trace_cow_enabled()	\
	(sizeof(next3_handle_t) == sizeof(handle_t))

#define trace_cow_add(handle, name, num)			\
	do {							\
		if (trace_cow_enabled())			\
			((next3_handle_t *)(handle))->h_cow_##name += (num);	\
	} while (0)

#define trace_cow_inc(handle, name)				\
	do {							\
		if (trace_cow_enabled())			\
			((next3_handle_t *)(handle))->h_cow_##name++;	\
	} while (0)

#else
#define trace_cow_enabled()	0
#define trace_cow_add(handle, name, num)
#define trace_cow_inc(handle, name)
#endif
#else
#define trace_cow_add(handle, name, num)
#define trace_cow_inc(handle, name)
#endif

#endif
int
next3_mark_iloc_dirty(handle_t *handle,
		     struct inode *inode,
		     struct next3_iloc *iloc);

/*
 * On success, We end up with an outstanding reference count against
 * iloc->bh.  This _must_ be cleaned up later.
 */

int next3_reserve_inode_write(handle_t *handle, struct inode *inode,
			struct next3_iloc *iloc);

int next3_mark_inode_dirty(handle_t *handle, struct inode *inode);

/*
 * Wrapper functions with which next3 calls into JBD.  The intent here is
 * to allow these to be turned into appropriate stubs so next3 can control
 * ext2 filesystems, so ext2+next3 systems only nee one fs.  This work hasn't
 * been done yet.
 */

#ifdef CONFIG_NEXT3_FS_SNAPSHOT_JOURNAL_RELEASE
int __next3_journal_release_buffer(const char *where, handle_t *handle,
				struct buffer_head *bh);

#define next3_journal_release_buffer(handle, bh) \
	__next3_journal_release_buffer(__func__, (handle), (bh))

#else
static inline void next3_journal_release_buffer(handle_t *handle,
						struct buffer_head *bh)
{
	journal_release_buffer(handle, bh);
}
#endif

void next3_journal_abort_handle(const char *caller, const char *err_fn,
		struct buffer_head *bh, handle_t *handle, int err);

int __next3_journal_get_undo_access(const char *where, handle_t *handle,
				struct buffer_head *bh);

#ifdef CONFIG_NEXT3_FS_SNAPSHOT_HOOKS_JBD
int __next3_journal_get_write_access_inode(const char *where, handle_t *handle,
				struct inode *inode, struct buffer_head *bh);
#else
int __next3_journal_get_write_access(const char *where, handle_t *handle,
				struct buffer_head *bh);
#endif

int __next3_journal_forget(const char *where, handle_t *handle,
				struct buffer_head *bh);

int __next3_journal_revoke(const char *where, handle_t *handle,
				unsigned long blocknr, struct buffer_head *bh);

int __next3_journal_get_create_access(const char *where,
				handle_t *handle, struct buffer_head *bh);

int __next3_journal_dirty_metadata(const char *where,
				handle_t *handle, struct buffer_head *bh);

#define next3_journal_get_undo_access(handle, bh) \
	__next3_journal_get_undo_access(__func__, (handle), (bh))
#ifdef CONFIG_NEXT3_FS_SNAPSHOT_HOOKS_JBD
#define next3_journal_get_write_access(handle, bh) \
	__next3_journal_get_write_access_inode(__func__, (handle), NULL, (bh))
#define next3_journal_get_write_access_inode(handle, inode, bh) \
	__next3_journal_get_write_access_inode(__func__, (handle), (inode), \
					       (bh))
#else
#define next3_journal_get_write_access(handle, bh) \
	__next3_journal_get_write_access(__func__, (handle), (bh))
#endif
#define next3_journal_revoke(handle, blocknr, bh) \
	__next3_journal_revoke(__func__, (handle), (blocknr), (bh))
#define next3_journal_get_create_access(handle, bh) \
	__next3_journal_get_create_access(__func__, (handle), (bh))
#define next3_journal_dirty_metadata(handle, bh) \
	__next3_journal_dirty_metadata(__func__, (handle), (bh))
#define next3_journal_forget(handle, bh) \
	__next3_journal_forget(__func__, (handle), (bh))

int next3_journal_dirty_data(handle_t *handle, struct buffer_head *bh);

#ifdef CONFIG_NEXT3_FS_SNAPSHOT_JOURNAL_CREDITS
#ifdef CONFIG_NEXT3_FS_SNAPSHOT_JOURNAL_TRACE
#ifdef CONFIG_NEXT3_FS_DEBUG
void __next3_journal_trace(int debug, const char *fn, const char *caller,
		next3_handle_t *handle, int nblocks);

#define next3_journal_trace(n, caller, handle, nblocks)			\
	do {								\
		if ((n) <= snapshot_enable_debug)			\
			__next3_journal_trace((n), __func__, (caller),	\
				(next3_handle_t *)(handle), (nblocks));	\
	} while (0)

#else
#define next3_journal_trace(n, caller, handle, nblocks)
#endif
#else
#define next3_journal_trace(n, caller, handle, nblocks)
#endif

handle_t *__next3_journal_start(const char *where,
		struct super_block *sb, int nblocks);

#define next3_journal_start_sb(sb, nblocks) \
	__next3_journal_start(__func__, 	\
			(sb), (nblocks))

#define next3_journal_start(inode, nblocks) \
	__next3_journal_start(__func__, 	\
			(inode)->i_sb, (nblocks))

#else
handle_t *next3_journal_start_sb(struct super_block *sb, int nblocks);

static inline handle_t *next3_journal_start(struct inode *inode, int nblocks)
{
	return next3_journal_start_sb(inode->i_sb, nblocks);
}
#endif

int __next3_journal_stop(const char *where, handle_t *handle);

#define next3_journal_stop(handle) \
	__next3_journal_stop(__func__, (handle))

static inline handle_t *next3_journal_current_handle(void)
{
	return journal_current_handle();
}

#ifdef CONFIG_NEXT3_FS_SNAPSHOT_JOURNAL_CREDITS
/*
 * Next3 wrapper for journal_extend()
 * When transaction runs out of buffer credits it is possible to try and
 * extend the buffer credits without restarting the transaction.
 * Next3 wrapper for journal_start() has increased the user requested buffer
 * credits to include the extra credits for COW operations.
 * This wrapper checks the remaining user credits and how many COW credits
 * are missing and then tries to extend the transaction.
 */
static inline int __next3_journal_extend(const char *where,
		next3_handle_t *handle, int nblocks)
{
	int lower = NEXT3_SNAPSHOT_TRANS_BLOCKS(handle->h_user_credits+nblocks);
	int err = 0;
	int missing = lower - handle->h_buffer_credits;
	if (missing > 0)
		/* extend transaction to keep buffer credits above lower
		 * limit */
		err = journal_extend((handle_t *)handle, missing);
	if (!err) {
		handle->h_base_credits += nblocks;
		handle->h_user_credits += nblocks;
		next3_journal_trace(SNAP_WARN, where, handle, nblocks);
	}
	return err;
}

/*
 * Next3 wrapper for journal_restart()
 * When transaction runs out of buffer credits and cannot be extended,
 * the alternative is to restart it (start a new transaction).
 * This wrapper increases the user requested buffer credits to include the
 * extra credits for COW operations.
 */
static inline int __next3_journal_restart(const char *where,
		next3_handle_t *handle, int nblocks)
{
	int err = journal_restart((handle_t *)handle,
				  NEXT3_SNAPSHOT_START_TRANS_BLOCKS(nblocks));
	if (!err) {
		handle->h_base_credits = nblocks;
		handle->h_user_credits = nblocks;
		next3_journal_trace(SNAP_WARN, where, handle, nblocks);
	}
	return err;
}

#define next3_journal_extend(handle, nblocks) \
	__next3_journal_extend(__func__, 	\
			(next3_handle_t *)(handle), (nblocks))

#define next3_journal_restart(handle, nblocks) \
	__next3_journal_restart(__func__, 	\
			(next3_handle_t *)(handle), (nblocks))
#else
static inline int __next3_journal_extend(const char *where,
		handle_t *handle, int nblocks)
{
	return journal_extend(handle, nblocks);
}

static inline int __next3_journal_restart(const char *where,
		handle_t *handle, int nblocks)
{
	return journal_restart(handle, nblocks);
}

#define next3_journal_extend(handle, nblocks) \
	__next3_journal_extend(__func__, 	\
			(handle), (nblocks))

#define next3_journal_restart(handle, nblocks) \
	__next3_journal_restart(__func__, 	\
			(handle), (nblocks))
#endif


static inline int next3_journal_blocks_per_page(struct inode *inode)
{
	return journal_blocks_per_page(inode);
}

static inline int next3_journal_force_commit(journal_t *journal)
{
	return journal_force_commit(journal);
}

/* super.c */
int next3_force_commit(struct super_block *sb);

static inline int next3_should_journal_data(struct inode *inode)
{
	if (!S_ISREG(inode->i_mode))
		return 1;
#ifdef CONFIG_NEXT3_FS_SNAPSHOT
	if (NEXT3_HAS_RO_COMPAT_FEATURE(inode->i_sb,
				NEXT3_FEATURE_RO_COMPAT_HAS_SNAPSHOT))
		/* snapshots require ordered data mode */
		return 0;
#endif
	if (test_opt(inode->i_sb, DATA_FLAGS) == NEXT3_MOUNT_JOURNAL_DATA)
		return 1;
	if (NEXT3_I(inode)->i_flags & NEXT3_JOURNAL_DATA_FL)
		return 1;
	return 0;
}

static inline int next3_should_order_data(struct inode *inode)
{
	if (!S_ISREG(inode->i_mode))
		return 0;
#ifdef CONFIG_NEXT3_FS_SNAPSHOT
	if (NEXT3_HAS_RO_COMPAT_FEATURE(inode->i_sb,
				NEXT3_FEATURE_RO_COMPAT_HAS_SNAPSHOT))
		/* snapshots require ordered data mode */
		return 1;
#endif
	if (NEXT3_I(inode)->i_flags & NEXT3_JOURNAL_DATA_FL)
		return 0;
	if (test_opt(inode->i_sb, DATA_FLAGS) == NEXT3_MOUNT_ORDERED_DATA)
		return 1;
	return 0;
}

static inline int next3_should_writeback_data(struct inode *inode)
{
	if (!S_ISREG(inode->i_mode))
		return 0;
#ifdef CONFIG_NEXT3_FS_SNAPSHOT
	if (NEXT3_HAS_RO_COMPAT_FEATURE(inode->i_sb,
				NEXT3_FEATURE_RO_COMPAT_HAS_SNAPSHOT))
		/* snapshots require ordered data mode */
		return 0;
#endif
	if (NEXT3_I(inode)->i_flags & NEXT3_JOURNAL_DATA_FL)
		return 0;
	if (test_opt(inode->i_sb, DATA_FLAGS) == NEXT3_MOUNT_WRITEBACK_DATA)
		return 1;
	return 0;
}

#endif	/* _LINUX_NEXT3_JBD_H */
