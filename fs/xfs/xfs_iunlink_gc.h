/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __XFS_IUNLINK_GC_H__
#define __XFS_IUNLINK_GC_H__

struct xfs_mount;

int xfs_iunlink_gc_mount(struct xfs_mount *mp);
void xfs_iunlink_gc_unmount(struct xfs_mount *mp);
void xfs_iunlink_gc_start(struct xfs_mount *mp);
void xfs_iunlink_gc_stop(struct xfs_mount *mp);
void xfs_iunlink_gc_kick(struct xfs_mount *mp);
void xfs_iunlink_gc_flush(struct xfs_mount *mp);

#endif /* __XFS_IUNLINK_GC_H__ */
