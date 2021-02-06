// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 CTERA Networks, Amir Goldstein <amir73il@gmail.com>
 * All Rights Reserved.
 */

#include <linux/lsm_hooks.h>
#include "fsnotify.h"

/*
 * Pre modify permission hooks
 */
#define FS_PERM_EVENT_TYPE(s)		\
	((struct fsnotify_event_type) {	\
		.sub_type = (s),	\
		.mask = FS_MODIFY_PERM,	\
	})

/*
 * Called before link/unlink of object to namespace.
 * @dentry may be negative before linking an object.
 */
static inline int fsnotify_dirent_perm(struct inode *dir, struct dentry *dentry,
				       __u32 mask, u32 cookie)
{
	return fsnotify(FS_PERM_EVENT_TYPE(mask), dentry, FSNOTIFY_EVENT_DENTRY,
			dir, &dentry->d_name, NULL, cookie);
}

/*
 * Called before modify of object metadata.
 */
static inline int fsnotify_dentry_perm(struct dentry *dentry, __u32 mask)
{
	return fsnotify_parent(dentry, FS_PERM_EVENT_TYPE(mask), dentry,
			       FSNOTIFY_EVENT_DENTRY);
}

static int fsnotify_inode_create(struct inode *dir, struct dentry *dentry,
				 umode_t mode)
{
	return fsnotify_dirent_perm(dir, dentry, FS_CREATE, 0);
}

static int fsnotify_inode_link(struct dentry *old_dentry, struct inode *dir,
			       struct dentry *new_dentry)
{
	return fsnotify_dirent_perm(dir, new_dentry, FS_CREATE, 0);
}

static int fsnotify_inode_unlink(struct inode *dir, struct dentry *dentry)
{
	return fsnotify_dirent_perm(dir, dentry, FS_DELETE, 0);
}

static int fsnotify_inode_symlink(struct inode *dir, struct dentry *dentry,
				  const char *old_name)
{
	return fsnotify_dirent_perm(dir, dentry, FS_CREATE, 0);
}

static int fsnotify_inode_mkdir(struct inode *dir, struct dentry *dentry,
				umode_t mode)
{
	/* dentry is negative. FS_ISDIR indicates create of directory */
	return fsnotify_dirent_perm(dir, dentry, FS_CREATE | FS_ISDIR, 0);
}

static int fsnotify_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
	return fsnotify_dirent_perm(dir, dentry, FS_DELETE | FS_ISDIR, 0);
}

static int fsnotify_inode_mknod(struct inode *dir, struct dentry *dentry,
				umode_t mode, dev_t dev)
{
	return fsnotify_dirent_perm(dir, dentry, FS_CREATE, 0);
}

static int fsnotify_inode_rename(struct inode *old_dir,
				 struct dentry *old_dentry,
				 struct inode *new_dir,
				 struct dentry *new_dentry)
{
	u32 cookie = fsnotify_get_cookie();
	__u32 old_mask = FS_MOVED_FROM;
	__u32 new_mask = FS_MOVED_TO;
	int ret;

	/* new_dentry may be negative. FS_ISDIR indicates rename of directory */
	if (d_is_dir(old_dentry)) {
		old_mask |= FS_ISDIR;
		new_mask |= FS_ISDIR;
	}

	ret = fsnotify_dirent_perm(old_dir, old_dentry, old_mask, cookie);
	if (ret)
		return ret;

	return fsnotify_dirent_perm(new_dir, new_dentry, new_mask, cookie);
}

static int fsnotify_inode_setattr(struct dentry *dentry, struct iattr *attr)
{
	return fsnotify_dentry_perm(dentry, FS_ATTRIB);
}

static int fsnotify_inode_setxattr(struct dentry *dentry, const char *name,
				   const void *value, size_t size, int flags)
{
	return fsnotify_dentry_perm(dentry, FS_ATTRIB);
}

static int fsnotify_inode_removexattr(struct dentry *dentry, const char *name)
{
	return fsnotify_dentry_perm(dentry, FS_ATTRIB);
}

static int fsnotify_file_open(struct file *file)
{
	return fsnotify_perm(file, MAY_OPEN);
}

static int fsnotify_file_permission(struct file *file, int mask)
{
	return fsnotify_perm(file, mask);
}

static struct security_hook_list fsnotify_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(inode_create, fsnotify_inode_create),
	LSM_HOOK_INIT(inode_link, fsnotify_inode_link),
	LSM_HOOK_INIT(inode_unlink, fsnotify_inode_unlink),
	LSM_HOOK_INIT(inode_symlink, fsnotify_inode_symlink),
	LSM_HOOK_INIT(inode_mkdir, fsnotify_inode_mkdir),
	LSM_HOOK_INIT(inode_rmdir, fsnotify_inode_rmdir),
	LSM_HOOK_INIT(inode_mknod, fsnotify_inode_mknod),
	LSM_HOOK_INIT(inode_rename, fsnotify_inode_rename),
	LSM_HOOK_INIT(inode_setattr, fsnotify_inode_setattr),
	LSM_HOOK_INIT(inode_setxattr, fsnotify_inode_setxattr),
	LSM_HOOK_INIT(inode_removexattr, fsnotify_inode_removexattr),
	LSM_HOOK_INIT(file_open, fsnotify_file_open),
	LSM_HOOK_INIT(file_permission, fsnotify_file_permission),
};

__init void fsnotify_add_security_hooks(void)
{
	security_add_hooks(fsnotify_hooks, ARRAY_SIZE(fsnotify_hooks),
			   "fsnotify");
}
