// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 CTERA Networks, Amir Goldstein <amir73il@gmail.com>
 * All Rights Reserved.
 */

#include <linux/lsm_hooks.h>
#include "fsnotify.h"


/*
 * Called before move of @old_dentry to @new_dentry.
 *
 * Caller is holding lock_rename() locks.
 */
static int fsnotify_inode_rename(struct inode *old_dir,
				 struct dentry *old_dentry,
				 struct inode *new_dir,
				 struct dentry *new_dentry)
{
	__u32 mask = FS_MOVE_PERM;

	if (d_is_dir(old_dentry))
		mask |= FS_ISDIR;

	return fsnotify(mask, old_dentry, FSNOTIFY_EVENT_DENTRY, NULL, NULL,
			d_inode(old_dentry), 0);
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
	LSM_HOOK_INIT(inode_rename, fsnotify_inode_rename),
	LSM_HOOK_INIT(file_open, fsnotify_file_open),
	LSM_HOOK_INIT(file_permission, fsnotify_file_permission),
};

__init void fsnotify_add_security_hooks(void)
{
	security_add_hooks(fsnotify_hooks, ARRAY_SIZE(fsnotify_hooks),
			   "fsnotify");
}
