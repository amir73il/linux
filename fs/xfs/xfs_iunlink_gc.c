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
#include "xfs_iunlink_gc.h"

#include <linux/freezer.h>
#include <linux/kthread.h>

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

		/*
		 * Placeholder: real cleanup work will be added in later patches.
		 */
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
