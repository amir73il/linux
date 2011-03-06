/*
 * Interface between next3 and JBD
 *
 * Copyright (C) 2008-2010 CTERA Networks
 * Added snapshot support, Amir Goldstein <amir73il@users.sf.net>, 2008
 */

#include "next3_jbd.h"
#include "snapshot.h"

int __next3_journal_get_undo_access(const char *where, handle_t *handle,
				struct buffer_head *bh)
{
	int err = journal_get_undo_access(handle, bh);
#ifdef CONFIG_NEXT3_FS_SNAPSHOT_HOOKS_JBD
	if (!err)
		err = next3_snapshot_get_undo_access(handle, bh);
#endif
	if (err)
		next3_journal_abort_handle(where, __func__, bh, handle,err);
#ifdef CONFIG_NEXT3_FS_SNAPSHOT_JOURNAL_TRACE
	next3_journal_trace(SNAP_DEBUG, where, handle, 1);
#endif
	return err;
}

#ifdef CONFIG_NEXT3_FS_SNAPSHOT_HOOKS_JBD
int __next3_journal_get_write_access_inode(const char *where, handle_t *handle,
				struct inode *inode, struct buffer_head *bh)
#else
int __next3_journal_get_write_access(const char *where, handle_t *handle,
				struct buffer_head *bh)
#endif
{
	int err = journal_get_write_access(handle, bh);
#ifdef CONFIG_NEXT3_FS_SNAPSHOT_HOOKS_JBD
	if (!err)
		err = next3_snapshot_get_write_access(handle, inode, bh);
#endif
	if (err)
		next3_journal_abort_handle(where, __func__, bh, handle,err);
#ifdef CONFIG_NEXT3_FS_SNAPSHOT_JOURNAL_TRACE
	next3_journal_trace(SNAP_DEBUG, where, handle, 1);
#endif
	return err;
}

int __next3_journal_forget(const char *where, handle_t *handle,
				struct buffer_head *bh)
{
	int err = journal_forget(handle, bh);
	if (err)
		next3_journal_abort_handle(where, __func__, bh, handle,err);
#ifdef CONFIG_NEXT3_FS_SNAPSHOT_JOURNAL_TRACE
	next3_journal_trace(SNAP_DEBUG, where, handle, 1);
#endif
	return err;
}

int __next3_journal_revoke(const char *where, handle_t *handle,
				unsigned long blocknr, struct buffer_head *bh)
{
	int err = journal_revoke(handle, blocknr, bh);
	if (err)
		next3_journal_abort_handle(where, __func__, bh, handle,err);
#ifdef CONFIG_NEXT3_FS_SNAPSHOT_JOURNAL_TRACE
	next3_journal_trace(SNAP_DEBUG, where, handle, 1);
#endif
	return err;
}

int __next3_journal_get_create_access(const char *where,
				handle_t *handle, struct buffer_head *bh)
{
	int err = journal_get_create_access(handle, bh);
#ifdef CONFIG_NEXT3_FS_SNAPSHOT_HOOKS_JBD
	if (!err)
		err = next3_snapshot_get_create_access(handle, bh);
#endif
	if (err)
		next3_journal_abort_handle(where, __func__, bh, handle,err);
#ifdef CONFIG_NEXT3_FS_SNAPSHOT_JOURNAL_TRACE
	next3_journal_trace(SNAP_DEBUG, where, handle, -1);
#endif
	return err;
}

int __next3_journal_dirty_metadata(const char *where,
				handle_t *handle, struct buffer_head *bh)
{
	int err = journal_dirty_metadata(handle, bh);
	if (err)
		next3_journal_abort_handle(where, __func__, bh, handle,err);
#ifdef CONFIG_NEXT3_FS_SNAPSHOT_JOURNAL_CREDITS
	if (err)
		return err;

	if (!IS_COWING(handle)) {
		struct journal_head *jh = bh2jh(bh);
		jbd_lock_bh_state(bh);
		if (jh->b_modified == 1) {
			/*
			 * buffer_credits was decremented when buffer was
			 * modified for the first time in the current
			 * transaction, which may have been during a COW
			 * operation.  We decrement user_credits and mark
			 * b_modified = 2, on the first time that the buffer
			 * is modified not during a COW operation (!h_cowing).
			 */
			jh->b_modified = 2;
			((next3_handle_t *)handle)->h_user_credits--;
		}
		jbd_unlock_bh_state(bh);
	}
#ifdef CONFIG_NEXT3_FS_SNAPSHOT_JOURNAL_TRACE
	next3_journal_trace(SNAP_DEBUG, where, handle, -1);
#endif
#endif
	return err;
}
#ifdef CONFIG_NEXT3_FS_SNAPSHOT_JOURNAL
#ifdef CONFIG_NEXT3_FS_SNAPSHOT_JOURNAL_RELEASE
int __next3_journal_release_buffer(const char *where, handle_t *handle,
				struct buffer_head *bh)
{
	int err = 0;

	if (IS_COWING(handle))
		goto out;

	/*
	 * Trying to cancel a previous call to get_write_access(), which may
	 * have resulted in a single COW operation.  We don't need to add
	 * user credits, but if COW credits are too low we will try to
	 * extend the transaction to compensate for the buffer credits used
	 * by the extra COW operation.
	 */
	err = next3_journal_extend(handle, 0);
	if (err > 0) {
		/* well, we can't say we didn't try - now lets hope
		 * we have enough buffer credits to spare */
		snapshot_debug(handle->h_buffer_credits < NEXT3_MAX_TRANS_DATA
				? 1 : 2,
				"%s: warning: couldn't extend transaction "
				"from %s (credits=%d/%d)\n", __func__,
				where, handle->h_buffer_credits,
				((next3_handle_t *)handle)->h_user_credits);
		err = 0;
	}
	next3_journal_trace(SNAP_WARN, where, handle, -1);
out:
	journal_release_buffer(handle, bh);
	return err;
}

#endif
#ifdef CONFIG_NEXT3_FS_SNAPSHOT_JOURNAL_TRACE
#ifdef CONFIG_JBD_DEBUG
static void next3_journal_cow_stats(int n, next3_handle_t *handle)
{
	if (!trace_cow_enabled())
		return;
	snapshot_debug(n, "COW stats: moved/copied=%d/%d, "
			 "mapped/bitmap/cached=%d/%d/%d, "
			 "bitmaps/cleared=%d/%d\n", handle->h_cow_moved,
			 handle->h_cow_copied, handle->h_cow_ok_mapped,
			 handle->h_cow_ok_bitmap, handle->h_cow_ok_jh,
			 handle->h_cow_bitmaps, handle->h_cow_excluded);
}
#else
#define next3_journal_cow_stats(n, handle)
#endif

#ifdef CONFIG_NEXT3_FS_DEBUG
void __next3_journal_trace(int n, const char *fn, const char *caller,
		next3_handle_t *handle, int nblocks)
{
	struct super_block *sb = handle->h_transaction->t_journal->j_private;
	struct inode *active_snapshot = next3_snapshot_has_active(sb);
	int upper = NEXT3_SNAPSHOT_START_TRANS_BLOCKS(handle->h_base_credits);
	int lower = NEXT3_SNAPSHOT_TRANS_BLOCKS(handle->h_user_credits);
	int final = (nblocks == 0 && handle->h_ref == 1 &&
		     !IS_COWING(handle));

	switch (snapshot_enable_debug) {
	case SNAP_INFO:
		/* trace final journal_stop if any credits have been used */
		if (final && (handle->h_buffer_credits < upper ||
			      handle->h_user_credits < handle->h_base_credits))
			break;
	case SNAP_WARN:
		/*
		 * trace if buffer credits are too low - lower limit is only
		 * valid if there is an active snapshot and not during COW
		 */
		if (handle->h_buffer_credits < lower &&
		    active_snapshot && !IS_COWING(handle))
			break;
	case SNAP_ERR:
		/* trace if user credits are too low */
		if (handle->h_user_credits < 0)
			break;
	case 0:
		/* no trace */
		return;

	case SNAP_DEBUG:
	default:
		/* trace all calls */
		break;
	}

	snapshot_debug_l(n, IS_COWING(handle), "%s(%d): credits=%d, limit=%d/%d,"
			 " user=%d/%d, ref=%d, caller=%s\n", fn, nblocks,
			 handle->h_buffer_credits, lower, upper,
			 handle->h_user_credits, handle->h_base_credits,
			 handle->h_ref, caller);
	if (!final)
		return;

	next3_journal_cow_stats(n, handle);
}
#endif
#endif
#endif
