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
 * vfs_xxx() wrappers that also generate fsnotify events.
 *
 * These helpers are called when the mount context is available, so that the
 * fsnotify event can be reported to mount marks.
 */
int vfs_create_notify(struct user_namespace *mnt_userns, struct path *path,
		      struct dentry *dentry, umode_t mode, bool want_excl);
int vfs_mknod_notify(struct user_namespace *mnt_userns, struct path *path,
		     struct dentry *dentry, umode_t mode, dev_t dev);
int vfs_symlink_notify(struct user_namespace *mnt_userns, struct path *path,
		       struct dentry *dentry, const char *oldname);
int vfs_mkdir_notify(struct user_namespace *mnt_userns, struct path *path,
		     struct dentry *dentry, umode_t mode);
int vfs_link_notify(struct dentry *old_dentry,
		    struct user_namespace *mnt_userns, struct path *path,
		    struct dentry *new_dentry, struct inode **delegated_inode);
int vfs_rmdir_notify(struct user_namespace *mnt_userns, struct path *path,
		     struct dentry *dentry);
int vfs_unlink_notify(struct user_namespace *mnt_userns, struct path *path,
		      struct dentry *dentry, struct inode **delegated_inode);
int vfs_rename_notify(struct vfsmount *mnt, struct renamedata *rd);

/*
 * Notify this @dir inode about a change in a child directory entry.
 * The directory entry may have turned positive or negative or its inode may
 * have changed (i.e. renamed over).
 *
 * Unlike fsnotify_parent(), the event will be reported regardless of the
 * FS_EVENT_ON_CHILD mask on the parent inode and will not be reported if only
 * the child is interested and not the parent.
 */
static inline void fsnotify_name(struct vfsmount *mnt, struct inode *dir,
				 __u32 mask, struct inode *child,
				 const struct qstr *name, u32 cookie)
{
	__fsnotify(mask, &(struct fsnotify_event_info) {
			.data = child, .data_type = FSNOTIFY_EVENT_INODE,
			.mnt = mnt, .dir = dir, .name = name, .cookie = cookie,
			});
}

static inline void __fsnotify_inode(struct vfsmount *mnt, struct inode *inode,
				    __u32 mask)
{
	if (S_ISDIR(inode->i_mode))
		mask |= FS_ISDIR;

	__fsnotify(mask, &(struct fsnotify_event_info) {
			.data = inode, .data_type = FSNOTIFY_EVENT_INODE,
			.inode = inode, .mnt = mnt,
			});
}

static inline void fsnotify_inode(struct inode *inode, __u32 mask)
{
	return __fsnotify_inode(NULL, inode, mask);
}

/* Notify this dentry's parent about a child's events. */
static inline int fsnotify_parent(const struct path *path, __u32 mask,
				  const void *data, int data_type)
{
	struct dentry *dentry = path->dentry;
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

	return __fsnotify_parent(path, mask, data, data_type);

notify_child:
	return __fsnotify(mask, &(struct fsnotify_event_info) {
				.data = data, .data_type = data_type,
				.inode = inode, .mnt = path->mnt,
				});
}

/*
 * Simple wrappers to consolidate calls to fsnotify_parent() when an event
 * is on a file/dentry.
 */
static inline void fsnotify_dentry(const struct path *path, __u32 mask)
{
	fsnotify_parent(path, mask, d_inode(path->dentry),
			FSNOTIFY_EVENT_INODE);
}

static inline int fsnotify_file(struct file *file, __u32 mask)
{
	const struct path *path = &file->f_path;

	if (file->f_mode & FMODE_NONOTIFY)
		return 0;

	return fsnotify_parent(path, mask, path, FSNOTIFY_EVENT_PATH);
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
static inline void fsnotify_move(struct vfsmount *mnt,
				 struct inode *old_dir, struct inode *new_dir,
				 const struct qstr *old_name,
				 struct inode *target, struct dentry *moved)
{
	struct inode *source = moved->d_inode;
	u32 cookie = fsnotify_get_cookie();
	__u32 old_mask = FS_MOVED_FROM;
	__u32 new_mask = FS_MOVED_TO;

	if (old_dir == new_dir)
		old_mask |= FS_DN_RENAME;

	if (S_ISDIR(source->i_mode)) {
		old_mask |= FS_ISDIR;
		new_mask |= FS_ISDIR;
	}

	fsnotify_name(mnt, old_dir, old_mask, source, old_name, cookie);
	fsnotify_name(mnt, new_dir, new_mask, source, &moved->d_name, cookie);

	if (target)
		fsnotify_link_count(target);

	audit_inode_child(new_dir, moved, AUDIT_TYPE_CHILD_CREATE);

	__fsnotify_inode(mnt, source, FS_MOVE_SELF);
}

/*
 * fsnotify_rename - old_name was moved to or exchanged with new_name
 */
static inline void fsnotify_rename(struct vfsmount *mnt, struct renamedata *rd,
				   const struct qstr *old_name)
{
	bool exchange = rd->flags & RENAME_EXCHANGE;
	struct inode *target = !exchange ? rd->new_dentry->d_inode : NULL;

	fsnotify_move(mnt, rd->old_dir, rd->new_dir, old_name, target,
		      rd->old_dentry);
	if (exchange) {
		fsnotify_move(mnt, rd->new_dir, rd->old_dir,
			      &rd->old_dentry->d_name, NULL, rd->new_dentry);
	}
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
 * fsnotify_mkobj - 'name' was created
 */
static inline void fsnotify_mkobj(struct vfsmount *mnt, struct inode *dir,
				  struct dentry *child, bool isdir)
{
	audit_inode_child(dir, child, AUDIT_TYPE_CHILD_CREATE);

	fsnotify_name(mnt, dir, FS_CREATE | (isdir ? FS_ISDIR : 0),
		      d_inode(child), &child->d_name, 0);
}

/*
 * fsnotify_create - 'name' was linked in
 */
static inline void fsnotify_create(struct vfsmount *mnt, struct inode *dir,
				   struct dentry *dentry)
{
	fsnotify_mkobj(mnt, dir, dentry, false);
}

/*
 * fsnotify_mkdir - directory 'name' was created
 */
static inline void fsnotify_mkdir(struct vfsmount *mnt, struct inode *dir,
				  struct dentry *dentry)
{
	fsnotify_mkobj(mnt, dir, dentry, true);
}

/*
 * fsnotify_link - new hardlink of 'inode'
 *
 * Note: We have to pass also the linked inode ptr as some filesystems leave
 *   new_dentry->d_inode NULL and instantiate inode pointer later
 */
static inline void fsnotify_link(struct vfsmount *mnt, struct inode *inode,
				 struct inode *dir, struct dentry *new_dentry)
{
	fsnotify_link_count(inode);
	audit_inode_child(dir, new_dentry, AUDIT_TYPE_CHILD_CREATE);

	fsnotify_name(mnt, dir, FS_CREATE, inode, &new_dentry->d_name, 0);
}

/*
 * fsnotify_delete - 'name' was removed
 *
 * Caller must hold a reference on victim inode and make sure that
 * dentry->d_name is stable.
 */
static inline void fsnotify_delete(struct vfsmount *mnt, struct inode *dir,
				   struct dentry *dentry, struct inode *victim,
				   bool isdir)
{
	WARN_ON_ONCE(atomic_read(&victim->i_count) < 1);

	fsnotify_name(mnt, dir, FS_DELETE | (isdir ? FS_ISDIR : 0), victim,
		      &dentry->d_name, 0);
}

/*
 * fsnotify_unlink - 'name' was unlinked
 *
 * Caller must make sure that dentry->d_name is stable.
 */
static inline void fsnotify_unlink(struct vfsmount *mnt, struct inode *dir,
				   struct dentry *dentry)
{
	/* Expected to be called before d_delete() */
	WARN_ON_ONCE(d_is_negative(dentry));

	fsnotify_delete(mnt, dir, dentry, d_inode(dentry), false);
}

/*
 * fsnotify_rmdir - directory 'name' was removed
 *
 * Caller must make sure that dentry->d_name is stable.
 */
static inline void fsnotify_rmdir(struct vfsmount *mnt, struct inode *dir,
				  struct dentry *dentry)
{
	/* Expected to be called before d_delete() */
	WARN_ON_ONCE(d_is_negative(dentry));

	fsnotify_delete(mnt, dir, dentry, d_inode(dentry), true);
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
static inline void fsnotify_xattr(const struct path *path)
{
	fsnotify_dentry(path, FS_ATTRIB);
}

/*
 * fsnotify_change - notify_change event.  file was modified and/or metadata
 * was changed.
 */
static inline void fsnotify_change(const struct path *path,
				   unsigned int ia_valid)
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
		fsnotify_dentry(path, mask);
}

#endif	/* _LINUX_FS_NOTIFY_H */
