// SPDX-License-Identifier: GPL-2.0
/*
 * Deferred unlinked inode cleanup worker.
 *
 * Copyright (c) 2026 CTERA Networks.
 */
#include "xfs_platform.h"
#include "xfs_shared.h"
#include "xfs_format.h"
#include "xfs_trans_resv.h"
#include "xfs_sb.h"
#include "xfs_mount.h"
#include "xfs_ag.h"
#include "xfs_ialloc.h"
#include "xfs_iunlink_gc.h"
#include "xfs_health.h"
#include "xfs_inode.h"
#include "xfs_icache.h"
#include "xfs_log_format.h"
#include "xfs_trans.h"
#include "xfs_buf.h"
#include "xfs_error.h"

#include <linux/freezer.h>
#include <linux/kthread.h>

/*
 * This is a variation of xlog_recover_iunlink_bucket that skips the inodes
 * that were unlinked since mount time.
 */
static int
xfs_iunlink_gc_process_bucket(
	struct xfs_perag	*pag,
	int			bucket)
{
	struct xfs_mount	*mp = pag_mount(pag);
	struct xfs_buf		*agibp;
	struct xfs_agi		*agi;
	struct xfs_inode	*prev_ip = NULL;
	xfs_agino_t		prev_agino = NULLAGINO;
	xfs_agino_t		agino;
	xfs_agino_t		zombie_agino;
	bool			found_zombie = false;
	int			error = 0;

	zombie_agino = pag->pag_iunlink_zombie[bucket];
	if (zombie_agino == NULLAGINO)
		return 0;

	error = xfs_read_agi(pag, NULL, 0, &agibp);
	if (error)
		return error;

	agi = agibp->b_addr;
	agino = be32_to_cpu(agi->agi_unlinked[bucket]);
	xfs_buf_rele(agibp);

	while (agino != NULLAGINO) {
		struct xfs_inode	*ip;
		xfs_agino_t		next_agino;

		error = -ESHUTDOWN;
		if (xfs_is_shutdown(mp))
			goto out_error;
		error = -EINTR;
		if (kthread_should_stop() || kthread_should_park())
			goto out_error;

		error = xfs_iget(mp, NULL, xfs_agino_to_ino(pag, agino), 0, 0,
				&ip);
		if (error)
			goto out_warn;

		ASSERT(VFS_I(ip)->i_nlink == 0);
		ASSERT(VFS_I(ip)->i_mode != 0);
		xfs_iflags_clear(ip, XFS_IRECOVERY);

		next_agino = ip->i_next_unlinked;

		if (!found_zombie) {
			if (agino == zombie_agino) {
				found_zombie = true;
				prev_agino = agino;
				prev_ip = ip;
			} else {
				xfs_irele(ip);
				prev_agino = agino;
			}
			agino = next_agino;
			cond_resched();
			continue;
		}

		ip->i_prev_unlinked = prev_agino;
		xfs_irele(prev_ip);
		error = xfs_inodegc_flush(mp);
		if (error) {
			xfs_irele(ip);
			goto out_warn;
		}
		pag->pag_iunlink_zombie[bucket] = agino;

		prev_agino = agino;
		prev_ip = ip;
		agino = next_agino;
		cond_resched();
	}

	if (prev_ip) {
		xfs_irele(prev_ip);
		error = xfs_inodegc_flush(mp);
		if (error)
			goto out_error;
	}

	pag->pag_iunlink_zombie[bucket] = NULLAGINO;
	return 0;

out_warn:
	xfs_warn(mp, "%s: failed to clean agi %u bucket %d. Continuing.",
		 __func__, pag_agno(pag), bucket);
	pag->pag_iunlink_zombie[bucket] = NULLAGINO;
	error = 0;
out_error:
	if (prev_ip)
		xfs_irele(prev_ip);
	return error;
}

static int
xfs_iunlink_gc_process_ag(
	struct xfs_perag	*pag)
{
	int			bucket;
	int			error;

	for (bucket = 0; bucket < XFS_AGI_UNLINKED_BUCKETS; bucket++) {
		error = xfs_iunlink_gc_process_bucket(pag, bucket);
		if (error)
			return error;
		if (error)
			goto corrupt;
		cond_resched();
	}

	return 0;

corrupt:
	return -EFSCORRUPTED;
}

static int
xfs_iunlink_gc_run(
	struct xfs_mount	*mp)
{
	struct xfs_perag	*pag = NULL;
	int			error = 0;

	while ((pag = xfs_perag_next(mp, pag))) {
		if (xfs_is_shutdown(mp))
			return -ESHUTDOWN;
		if (kthread_should_stop() || kthread_should_park())
			return -EINTR;

		error = xfs_iunlink_gc_process_ag(pag);
		if (error)
			return error;
		cond_resched();
	}
	return 0;
}

static int
xfs_iunlink_gcd(
	void			*data)
{
	struct xfs_mount	*mp = data;

	set_freezable();
	for (;;) {
		if (kthread_should_stop())
			break;
		if (kthread_should_park())
			kthread_parkme();

		wait_event_freezable(mp->m_iunlinkgc_wait,
				kthread_should_stop() ||
				kthread_should_park() ||
				xfs_is_iunlink_cleanup(mp));
		if (kthread_should_stop())
			break;
		if (kthread_should_park())
			continue;
		if (!xfs_is_iunlink_cleanup(mp))
			continue;

		if (xfs_iunlink_gc_run(mp) != -EINTR)
			xfs_clear_iunlink_cleanup(mp);
		wake_up(&mp->m_iunlinkgc_wait);
	}

	return 0;
}

void
xfs_iunlink_gc_kick(
	struct xfs_mount	*mp)
{
	if (!xfs_has_defer_unlinked(mp) || xfs_has_norecovery(mp))
		return;
	if (xfs_set_iunlink_cleanup(mp))
		return;
	wake_up(&mp->m_iunlinkgc_wait);
}

void
xfs_iunlink_gc_flush(
	struct xfs_mount	*mp)
{
	if (!xfs_has_defer_unlinked(mp) || xfs_has_norecovery(mp) ||
	    !mp->m_iunlinkgc_task)
		return;
	if (!xfs_is_iunlink_cleanup(mp))
		return;

	kthread_unpark(mp->m_iunlinkgc_task);
	wake_up(&mp->m_iunlinkgc_wait);

	wait_event(mp->m_iunlinkgc_wait, !xfs_is_iunlink_cleanup(mp));
}

void
xfs_iunlink_gc_start(
	struct xfs_mount	*mp)
{
	if (!xfs_has_defer_unlinked(mp) || xfs_has_norecovery(mp) ||
	    !mp->m_iunlinkgc_task)
		return;
	kthread_unpark(mp->m_iunlinkgc_task);
}

void
xfs_iunlink_gc_stop(
	struct xfs_mount	*mp)
{
	if (!xfs_has_defer_unlinked(mp) || xfs_has_norecovery(mp) ||
	    !mp->m_iunlinkgc_task)
		return;
	kthread_park(mp->m_iunlinkgc_task);
}

int
xfs_iunlink_gc_mount(
	struct xfs_mount	*mp)
{
	if (!xfs_has_defer_unlinked(mp) || xfs_has_norecovery(mp))
		return 0;

	init_waitqueue_head(&mp->m_iunlinkgc_wait);
	mp->m_iunlinkgc_task = kthread_create(xfs_iunlink_gcd, mp,
			"xfs-iunlink-gc/%s", mp->m_super->s_id);
	if (IS_ERR(mp->m_iunlinkgc_task)) {
		int error = PTR_ERR(mp->m_iunlinkgc_task);

		mp->m_iunlinkgc_task = NULL;
		return error;
	}

	/* xfs_iunlink_gc_start will unpark for rw mounts */
	kthread_park(mp->m_iunlinkgc_task);
	return 0;
}

void
xfs_iunlink_gc_unmount(
	struct xfs_mount	*mp)
{
	if (!mp->m_iunlinkgc_task)
		return;
	kthread_stop(mp->m_iunlinkgc_task);
	mp->m_iunlinkgc_task = NULL;
}
