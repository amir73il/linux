// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2001-2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef __XFS_ACL_H__
#define __XFS_ACL_H__

struct inode;
struct posix_acl;

#ifdef CONFIG_XFS_POSIX_ACL
/* .get_inode_acl — enforcement; returns NULL when aclnoenforce is active */
extern struct posix_acl *xfs_get_inode_acl(struct inode *inode, int type,
					   bool rcu);
/* .get_acl — explicit retrieval (getfacl); always returns real on-disk ACL */
extern struct posix_acl *xfs_get_acl(struct inode *inode, int type, bool rcu);
extern struct posix_acl *xfs_get_dentry_acl(struct mnt_idmap *idmap,
					    struct dentry *dentry, int type);
extern int xfs_set_acl(struct mnt_idmap *idmap, struct dentry *dentry,
		       struct posix_acl *acl, int type);
extern int __xfs_set_acl(struct inode *inode, struct posix_acl *acl, int type);
void xfs_forget_acl(struct inode *inode, const char *name);
#else
#define xfs_get_inode_acl	NULL
#define xfs_get_acl		NULL
#define xfs_get_dentry_acl	NULL
#define xfs_set_acl		NULL
static inline int __xfs_set_acl(struct inode *inode, struct posix_acl *acl,
				int type)
{
	return 0;
}
static inline void xfs_forget_acl(struct inode *inode, const char *name)
{
}
#endif /* CONFIG_XFS_POSIX_ACL */

#endif	/* __XFS_ACL_H__ */
