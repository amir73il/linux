/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_FS_NOTIFY_H
#define _LINUX_FS_NOTIFY_H

/*
 * include/linux/fsnotify.h - generic hooks for filesystem notification, to
 * reduce in-source duplication from both dnotify and inotify.
 *
 * We don't compile any of this away in some complicated menagerie of ifdefs.
 * Instead, we rely on the code inside to optimize away as needed.
 *
 * (C) Copyright 2005 Robert Love
 */

#include <linux/fsnotify_backend.h>
#include <linux/audit.h>
#include <linux/slab.h>
#include <linux/bug.h>

/*
 * Notify this @dir inode about a change in a child directory entry.
 * The directory entry may have turned positive or negative or its inode may
 * have changed (i.e. renamed over).
 *
 * Unlike fsnotify_parent(), the event will be reported regardless of the
 * FS_EVENT_ON_CHILD mask on the parent inode and will not be reported if only
 * the child is interested and not the parent.
 */
static inline void fsnotify_name(struct user_namespace *userns,
				 struct inode *dir, __u32 mask,
				 struct inode *child,
				 const struct qstr *name, u32 cookie)
{
	__fsnotify(mask, &(struct fsnotify_event_info) {
			.data = child, .data_type = FSNOTIFY_EVENT_INODE,
			.dir = dir, .name = name, .cookie = cookie,
			});
}

static inline void fsnotify_dirent(struct user_namespace *userns,
				   struct inode *dir, struct dentry *dentry,
				   __u32 mask)
{
	fsnotify_name(userns, dir, mask, d_inode(dentry), &dentry->d_name, 0);
}

static inline void fsnotify_inode(struct inode *inode, __u32 mask)
{
	if (S_ISDIR(inode->i_mode))
		mask |= FS_ISDIR;

	__fsnotify(mask, &(struct fsnotify_event_info) {
			.data = inode, .data_type = FSNOTIFY_EVENT_INODE,
			.inode = inode,
			});
}

/* Notify this dentry's parent about a child's events. */
static inline int fsnotify_parent(struct dentry *dentry, __u32 mask,
				  const void *data, int data_type)
{
	struct inode *inode = d_inode(dentry);

	if (S_ISDIR(inode->i_mode)) {
		mask |= FS_ISDIR;

		/* sb/mount marks are not interested in name of directory */
		if (!(dentry->d_flags & DCACHE_FSNOTIFY_PARENT_WATCHED))
			goto notify_child;
	}

	/* disconnected dentry cannot notify parent */
	if (IS_ROOT(dentry))
		goto notify_child;

	return __fsnotify_parent(dentry, mask, data, data_type);

notify_child:
	return __fsnotify(mask, &(struct fsnotify_event_info) {
				.data = data, .data_type = data_type,
				.inode = inode,
				});
}

/*
 * Simple wrappers to consolidate calls to fsnotify_parent() when an event
 * is on a file/dentry.
 */
static inline void fsnotify_dentry(struct user_namespace *userns,
				   struct dentry *dentry, __u32 mask)
{
	fsnotify_parent(dentry, mask, d_inode(dentry), FSNOTIFY_EVENT_INODE);
}

static inline int fsnotify_file(struct file *file, __u32 mask)
{
	const struct path *path = &file->f_path;

	if (file->f_mode & FMODE_NONOTIFY)
		return 0;

	return fsnotify_parent(path->dentry, mask, path, FSNOTIFY_EVENT_PATH);
}

/* Simple call site for access decisions */
static inline int fsnotify_perm(struct file *file, int mask)
{
	int ret;
	__u32 fsnotify_mask = 0;

	if (!(mask & (MAY_READ | MAY_OPEN)))
		return 0;

	if (mask & MAY_OPEN) {
		fsnotify_mask = FS_OPEN_PERM;

		if (file->f_flags & __FMODE_EXEC) {
			ret = fsnotify_file(file, FS_OPEN_EXEC_PERM);

			if (ret)
				return ret;
		}
	} else if (mask & MAY_READ) {
		fsnotify_mask = FS_ACCESS_PERM;
	}

	return fsnotify_file(file, fsnotify_mask);
}

/*
 * fsnotify_link_count - inode's link count changed
 */
static inline void fsnotify_link_count(struct inode *inode)
{
	fsnotify_inode(inode, FS_ATTRIB);
}

/*
 * fsnotify_move - file old_name at old_dir was moved to new_name at new_dir
 */
static inline void fsnotify_ns_move(struct renamedata *rd,
				    const struct qstr *old_name)
{
	struct dentry *moved = rd->old_dentry;
	struct inode *source = moved->d_inode;
	u32 fs_cookie = fsnotify_get_cookie();
	__u32 old_dir_mask = FS_MOVED_FROM;
	__u32 new_dir_mask = FS_MOVED_TO;
	const struct qstr *new_name = &moved->d_name;
	struct inode *target = rd->new_dentry ? d_inode(rd->new_dentry) : NULL;
	bool overwrite = target && !(rd->flags & RENAME_EXCHANGE);

	if (rd->old_dir == rd->new_dir)
		old_dir_mask |= FS_DN_RENAME;

	if (d_is_dir(moved)) {
		old_dir_mask |= FS_ISDIR;
		new_dir_mask |= FS_ISDIR;
	}

	fsnotify_name(rd->old_mnt_userns, rd->old_dir, old_dir_mask, source,
		      old_name, fs_cookie);
	fsnotify_name(rd->new_mnt_userns, rd->new_dir, new_dir_mask, source,
		      new_name, fs_cookie);

	if (overwrite)
		fsnotify_link_count(target);
	fsnotify_inode(source, FS_MOVE_SELF);
	audit_inode_child(rd->new_dir, moved, AUDIT_TYPE_CHILD_CREATE);
}

/* Simple wrapper without mnt_userns and without the overwritten target */
static inline void fsnotify_move(struct inode *old_dir, struct inode *new_dir,
				 const struct qstr *old_name,
				 struct dentry *moved)
{
	struct renamedata rd = {
		.old_dir	= old_dir,
		.old_dentry	= moved,
		.old_mnt_userns	= old_dir->i_sb->s_user_ns,
		.new_dir	= new_dir,
		.new_dentry	= NULL,
		.new_mnt_userns	= new_dir->i_sb->s_user_ns,
	};

	fsnotify_ns_move(&rd, old_name);
}

/*
 * fsnotify_inode_delete - and inode is being evicted from cache, clean up is needed
 */
static inline void fsnotify_inode_delete(struct inode *inode)
{
	__fsnotify_inode_delete(inode);
}

/*
 * fsnotify_vfsmount_delete - a vfsmount is being destroyed, clean up is needed
 */
static inline void fsnotify_vfsmount_delete(struct vfsmount *mnt)
{
	__fsnotify_vfsmount_delete(mnt);
}

/*
 * fsnotify_inoderemove - an inode is going away
 */
static inline void fsnotify_inoderemove(struct inode *inode)
{
	fsnotify_inode(inode, FS_DELETE_SELF);
	__fsnotify_inode_delete(inode);
}

/*
 * fsnotify_create - 'name' was linked in
 */
static inline void fsnotify_ns_create(struct user_namespace *userns,
				      struct inode *inode,
				      struct dentry *dentry)
{
	audit_inode_child(inode, dentry, AUDIT_TYPE_CHILD_CREATE);

	fsnotify_dirent(userns, inode, dentry, FS_CREATE);
}

static inline void fsnotify_create(struct inode *dir, struct dentry *dentry)
{
	fsnotify_ns_create(dir->i_sb->s_user_ns, dir, dentry);
}

/*
 * fsnotify_link - new hardlink in 'inode' directory
 * Note: We have to pass also the linked inode ptr as some filesystems leave
 *   new_dentry->d_inode NULL and instantiate inode pointer later
 */
static inline void fsnotify_ns_link(struct user_namespace *userns,
				    struct inode *dir, struct inode *inode,
				    struct dentry *new_dentry)
{
	fsnotify_link_count(inode);
	audit_inode_child(dir, new_dentry, AUDIT_TYPE_CHILD_CREATE);

	fsnotify_name(userns, dir, FS_CREATE, inode, &new_dentry->d_name, 0);
}

static inline void fsnotify_link(struct inode *dir, struct inode *inode,
				 struct dentry *new_dentry)
{
	fsnotify_ns_link(dir->i_sb->s_user_ns, dir, inode, new_dentry);
}

/*
 * fsnotify_unlink - 'name' was unlinked
 *
 * Caller must make sure that dentry->d_name is stable.
 */
static inline void fsnotify_ns_unlink(struct user_namespace *userns,
				      struct inode *dir, struct dentry *dentry)
{
	/* Expected to be called before d_delete() */
	WARN_ON_ONCE(d_is_negative(dentry));

	fsnotify_dirent(userns, dir, dentry, FS_DELETE);
}

static inline void fsnotify_unlink(struct inode *dir, struct dentry *dentry)
{
	fsnotify_ns_unlink(dir->i_sb->s_user_ns, dir, dentry);
}

/*
 * fsnotify_mkdir - directory 'name' was created
 */
static inline void fsnotify_ns_mkdir(struct user_namespace *userns,
				     struct inode *inode, struct dentry *dentry)
{
	audit_inode_child(inode, dentry, AUDIT_TYPE_CHILD_CREATE);

	fsnotify_dirent(userns, inode, dentry, FS_CREATE | FS_ISDIR);
}

static inline void fsnotify_mkdir(struct inode *dir, struct dentry *dentry)
{
	fsnotify_ns_mkdir(dir->i_sb->s_user_ns, dir, dentry);
}

/*
 * fsnotify_rmdir - directory 'name' was removed
 *
 * Caller must make sure that dentry->d_name is stable.
 */
static inline void fsnotify_ns_rmdir(struct user_namespace *userns,
				     struct inode *dir, struct dentry *dentry)
{
	/* Expected to be called before d_delete() */
	WARN_ON_ONCE(d_is_negative(dentry));

	fsnotify_dirent(userns, dir, dentry, FS_DELETE | FS_ISDIR);
}

static inline void fsnotify_rmdir(struct inode *dir, struct dentry *dentry)
{
	fsnotify_ns_rmdir(dir->i_sb->s_user_ns, dir, dentry);
}

/*
 * fsnotify_access - file was read
 */
static inline void fsnotify_access(struct file *file)
{
	fsnotify_file(file, FS_ACCESS);
}

/*
 * fsnotify_modify - file was modified
 */
static inline void fsnotify_modify(struct file *file)
{
	fsnotify_file(file, FS_MODIFY);
}

/*
 * fsnotify_open - file was opened
 */
static inline void fsnotify_open(struct file *file)
{
	__u32 mask = FS_OPEN;

	if (file->f_flags & __FMODE_EXEC)
		mask |= FS_OPEN_EXEC;

	fsnotify_file(file, mask);
}

/*
 * fsnotify_close - file was closed
 */
static inline void fsnotify_close(struct file *file)
{
	__u32 mask = (file->f_mode & FMODE_WRITE) ? FS_CLOSE_WRITE :
						    FS_CLOSE_NOWRITE;

	fsnotify_file(file, mask);
}

/*
 * fsnotify_xattr - extended attributes were changed
 */
static inline void fsnotify_xattr(struct user_namespace *userns,
				  struct dentry *dentry)
{
	fsnotify_dentry(userns, dentry, FS_ATTRIB);
}

/*
 * fsnotify_change - notify_change event.  file was modified and/or metadata
 * was changed.
 */
static inline void fsnotify_change(struct user_namespace *userns,
				   struct dentry *dentry, unsigned int ia_valid)
{
	__u32 mask = 0;

	if (ia_valid & ATTR_UID)
		mask |= FS_ATTRIB;
	if (ia_valid & ATTR_GID)
		mask |= FS_ATTRIB;
	if (ia_valid & ATTR_SIZE)
		mask |= FS_MODIFY;

	/* both times implies a utime(s) call */
	if ((ia_valid & (ATTR_ATIME | ATTR_MTIME)) == (ATTR_ATIME | ATTR_MTIME))
		mask |= FS_ATTRIB;
	else if (ia_valid & ATTR_ATIME)
		mask |= FS_ACCESS;
	else if (ia_valid & ATTR_MTIME)
		mask |= FS_MODIFY;

	if (ia_valid & ATTR_MODE)
		mask |= FS_ATTRIB;

	if (mask)
		fsnotify_dentry(userns, dentry, mask);
}

#endif	/* _LINUX_FS_NOTIFY_H */
