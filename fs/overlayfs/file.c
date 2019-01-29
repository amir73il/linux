/*
 * Copyright (C) 2017 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 */

#include <linux/cred.h>
#include <linux/file.h>
#include <linux/mount.h>
#include <linux/xattr.h>
#include <linux/uio.h>
#include <linux/mm.h>
#include <linux/iomap.h>
#include <linux/pagemap.h>
#include <linux/fadvise.h>
#include <linux/writeback.h>
#include <linux/ratelimit.h>
#include <linux/workqueue.h>
#include "overlayfs.h"

static char ovl_whatisit(struct inode *inode, struct inode *realinode)
{
	if (realinode != ovl_inode_upper(inode))
		return 'l';
	if (ovl_has_upperdata(inode))
		return 'u';
	else
		return 'm';
}

static struct file *ovl_open_realfile(const struct file *file,
				      struct inode *realinode)
{
	struct inode *inode = file_inode(file);
	struct file *realfile;
	const struct cred *old_cred;
	int flags = (file->f_flags & O_ACCMODE) | O_NOATIME | O_LARGEFILE;

	old_cred = ovl_override_creds(inode->i_sb);
	realfile = open_with_fake_path(&file->f_path, flags,
				       realinode, current_cred());
	revert_creds(old_cred);

	pr_debug("open(%p[%pD2/%c], 0%o) -> (%p, 0%o)\n",
		 file, file, ovl_whatisit(inode, realinode), file->f_flags,
		 realfile, IS_ERR(realfile) ? 0 : realfile->f_flags);

	return realfile;
}

static struct file *ovl_open_upper(const struct file *file,
				   struct inode *realinode)
{
	struct inode *inode = file_inode(file);
	struct ovl_inode *oi = OVL_I(inode);
	struct file *realfile;
	const struct cred *old_cred;
	struct path realpath;
	int flags = O_RDWR | O_NOATIME | O_LARGEFILE;

	realfile = READ_ONCE(oi->upper_file);
	if (realfile)
		return realfile;

	ovl_path_upper(file_dentry(file), &realpath);

	old_cred = ovl_override_creds(inode->i_sb);
	realfile = open_with_fake_path(&realpath, flags,
				       realinode, current_cred());
	revert_creds(old_cred);

	pr_debug("open(%p[%pD2/%c], 0%o) -> (%p, 0%o)\n",
		 file, file, ovl_whatisit(inode, realinode), file->f_flags,
		 realfile, IS_ERR(realfile) ? 0 : realfile->f_flags);

	if (!IS_ERR(realfile)) {
		struct file *old = cmpxchg(&oi->upper_file, NULL, realfile);

		if (old) {
			fput(realfile);
			realfile = old;
		}
	}

	return realfile;
}

#if 0
#define OVL_SETFL_MASK (O_APPEND | O_NONBLOCK | O_NDELAY | O_DIRECT)

static int ovl_change_flags(struct file *file, unsigned int flags)
{
	struct inode *inode = file_inode(file);
	int err;

	/* No atime modificaton on underlying */
	flags |= O_NOATIME;

	/* If some flag changed that cannot be changed then something's amiss */
	if (WARN_ON((file->f_flags ^ flags) & ~OVL_SETFL_MASK))
		return -EIO;

	flags &= OVL_SETFL_MASK;

	if (((flags ^ file->f_flags) & O_APPEND) && IS_APPEND(inode))
		return -EPERM;

	if (flags & O_DIRECT) {
		if (!file->f_mapping->a_ops ||
		    !file->f_mapping->a_ops->direct_IO)
			return -EINVAL;
	}

	if (file->f_op->check_flags) {
		err = file->f_op->check_flags(flags);
		if (err)
			return err;
	}

	spin_lock(&file->f_lock);
	file->f_flags = (file->f_flags & ~OVL_SETFL_MASK) | flags;
	spin_unlock(&file->f_lock);

	return 0;
}
#endif

static bool ovl_filemap_support(const struct file *file)
{
	//struct ovl_fs *ofs = file_inode(file)->i_sb->s_fs_info;

	/* TODO: implement aops to upper inode data */
	return true;
}

static int ovl_file_maybe_copy_up(const struct file *file, bool allow_meta)
{
	int copy_up_flags = 0;

	if (file->f_flags & O_TRUNC) {
		copy_up_flags = OVL_COPY_UP_DATA | OVL_COPY_UP_TRUNC;
	} else if (allow_meta && (file->f_flags & O_ACCMODE) == O_RDWR) {
		/* On open O_RDWR, defer copy up data to first data access */
		copy_up_flags = OVL_COPY_UP_META;
	} else if (file->f_mode & FMODE_WRITE) {
		copy_up_flags = OVL_COPY_UP_DATA;
	}

	return ovl_maybe_copy_up(file_dentry(file), copy_up_flags);
}

static int ovl_real_fdget(const struct file *file, struct fd *real)
{
	struct inode *inode = file_inode(file);
	struct ovl_inode *oi = OVL_I(inode);
	struct inode *realinode;
	int err;

	real->flags = 0;
	real->file = READ_ONCE(oi->upper_file);
	if (!real->file)
		real->file = file->private_data;

	/*
	 * Lazy copy up caches the meta copy upper file on open O_RDWR.
	 * We need to promote upper inode to full data copy up before
	 * we allow access to real file data on a writable file, otherwise
	 * we may try to open a lower file O_RDWR or perform data operations
	 * (e.g. fallocate) on the metacopy inode.
	 */
	err = ovl_file_maybe_copy_up(file, false);
	if (err)
		return err;

	realinode = ovl_inode_realdata(inode);

	/* Has it been copied up since we'd opened it? */
	if (unlikely(file_inode(real->file) != realinode)) {
		real->file = ovl_open_upper(file, realinode);

		return PTR_ERR_OR_ZERO(real->file);
	}

#if 0
	/* Did the flags change since open? */
	if (unlikely((file->f_flags ^ real->file->f_flags) & ~O_NOATIME))
		return ovl_change_flags(real->file, file->f_flags);
#endif

	return 0;
}

static int ovl_real_fdget_meta(const struct file *file, struct fd *real,
			       bool allow_meta)
{
	struct inode *inode = file_inode(file);
	struct inode *upperinode = ovl_inode_upper(inode);

	if (!allow_meta || !upperinode || ovl_has_upperdata(inode))
		return ovl_real_fdget(file, real);

	real->flags = FDPUT_FPUT;
	real->file = ovl_open_realfile(file, upperinode);

	return PTR_ERR_OR_ZERO(real->file);
}

static bool ovl_should_use_filemap_meta(struct file *file, bool allow_meta)
{
	struct inode *inode = file_inode(file);
	int err;

	if (!ovl_filemap_support(file))
		return false;

	/*
	 * If file was opened O_RDWR with lazy copy up of data, the first
	 * data access file operation will trigger data copy up.
	 *
	 * For example, mmap() and fsync() are metadata only operations that
	 * do not trigger lazy copy up of data, but read() (on a file open for
	 * write) is a data access operation that does trigger data copy up.
	 */
	err = ovl_file_maybe_copy_up(file, allow_meta);
	if (err) {
		pr_warn_ratelimited("overlayfs: failed lazy copy up data (%pd2, err=%i)\n",
				    file_dentry(file), err);
		return false;
	}

	/*
	 * If file was opened O_RDWR and @allow_meta is true, we use overlay
	 * inode filemap operations, but defer data copy up further.
	 */
	if (allow_meta && file->f_mode & FMODE_WRITE)
		return true;

	/*
	 * Use overlay inode page cache for all inodes that could be dirty,
	 * including pure upper inodes, so ovl_sync_fs() can sync all dirty
	 * overlay inodes without having to sync all upper fs dirty inodes.
	 */
	return ovl_has_upperdata(inode);
}

static bool ovl_should_use_filemap(struct file *file)
{
	return ovl_should_use_filemap_meta(file, false);
}

static int ovl_flush_filemap(struct file *file, loff_t offset, loff_t len)
{
	if (!ovl_should_use_filemap_meta(file, true))
		return 0;

	return filemap_write_and_wait_range(file_inode(file)->i_mapping,
					    offset, len);
}

static int ovl_open(struct inode *inode, struct file *file)
{
	struct file *realfile;
	struct inode *realinode;
	int err;
	bool allow_meta = (file->f_mode & FMODE_WRITE) &&
			ovl_filemap_support(file);

	err = ovl_file_maybe_copy_up(file, allow_meta);
	if (err)
		return err;

	realinode = allow_meta ?
		ovl_inode_real(inode) : ovl_inode_realdata(inode);

	if (realinode == ovl_inode_upper(inode)) {
		realfile = ovl_open_upper(file, realinode);
		if (IS_ERR(realfile))
			return PTR_ERR(realfile);
	} else {
		realfile = ovl_open_realfile(file, realinode);
		if (IS_ERR(realfile))
			return PTR_ERR(realfile);

		file->private_data = realfile;
	}

	return 0;
}

static int ovl_release(struct inode *inode, struct file *file)
{
	if (file->private_data)
		fput(file->private_data);

	return 0;
}

static loff_t ovl_llseek(struct file *file, loff_t offset, int whence)
{
	struct inode *realinode = ovl_inode_real(file_inode(file));

	return generic_file_llseek_size(file, offset, whence,
					realinode->i_sb->s_maxbytes,
					i_size_read(file_inode(file)));
}

static void ovl_file_accessed(struct file *file)
{
	struct inode *inode, *upperinode;

	if (file->f_flags & O_NOATIME)
		return;

	inode = file_inode(file);
	upperinode = ovl_inode_upper(inode);

	if (!upperinode)
		return;

	if ((!timespec64_equal(&inode->i_mtime, &upperinode->i_mtime) ||
	     !timespec64_equal(&inode->i_ctime, &upperinode->i_ctime))) {
		inode->i_mtime = upperinode->i_mtime;
		inode->i_ctime = upperinode->i_ctime;
	}

	touch_atime(&file->f_path);
}

static rwf_t ovl_iocb_to_rwf(struct kiocb *iocb)
{
	int ifl = iocb->ki_flags;
	rwf_t flags = 0;

	if (ifl & IOCB_NOWAIT)
		flags |= RWF_NOWAIT;
	if (ifl & IOCB_HIPRI)
		flags |= RWF_HIPRI;
	if (ifl & IOCB_DSYNC)
		flags |= RWF_DSYNC;
	if (ifl & IOCB_SYNC)
		flags |= RWF_SYNC;
	if (ifl & IOCB_APPEND)
		flags |= RWF_APPEND;
	if (ifl & IOCB_DIRECT)
		flags |= RWF_DIRECT;

	return flags;
}

static ssize_t ovl_real_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;
	struct fd real;
	const struct cred *old_cred;
	ssize_t ret;

	if (!iov_iter_count(iter))
		return 0;

	ret = ovl_real_fdget(file, &real);
	if (ret)
		return ret;

	old_cred = ovl_override_creds(file_inode(file)->i_sb);
	ret = vfs_iter_read(real.file, iter, &iocb->ki_pos,
			    ovl_iocb_to_rwf(iocb));
	revert_creds(old_cred);

	ovl_file_accessed(file);

	fdput(real);

	return ret;
}

static ssize_t ovl_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;

	if (ovl_should_use_filemap(file))
		return generic_file_read_iter(iocb, iter);

	return ovl_real_read_iter(iocb, iter);
}

static ssize_t ovl_real_write_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);
	struct fd real;
	const struct cred *old_cred;
	ssize_t ret;

	if (!iov_iter_count(iter))
		return 0;

	inode_lock(inode);
	/* Update mode */
	ovl_copyattr(ovl_inode_real(inode), inode);
	ret = file_remove_privs(file);
	if (ret)
		goto out_unlock;

	ret = ovl_real_fdget(file, &real);
	if (ret)
		goto out_unlock;

	old_cred = ovl_override_creds(file_inode(file)->i_sb);
	file_start_write(real.file);
	ret = vfs_iter_write(real.file, iter, &iocb->ki_pos,
			     ovl_iocb_to_rwf(iocb));
	file_end_write(real.file);
	revert_creds(old_cred);

	/* Update size */
	ovl_copyattr_size(ovl_inode_real(inode), inode);

	fdput(real);

out_unlock:
	inode_unlock(inode);

	return ret;
}

static ssize_t ovl_write_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);

	if (ovl_should_use_filemap(file)) {
		/* Update mode for file_remove_privs() */
		ovl_copyattr(ovl_inode_real(inode), inode);

		return generic_file_write_iter(iocb, iter);
	}

	return ovl_real_write_iter(iocb, iter);
}


static int ovl_real_fsync(struct file *file, loff_t start, loff_t end,
			  int datasync)
{
	struct fd real;
	struct inode *inode = file_inode(file);
	const struct cred *old_cred;
	int ret;

	ret = ovl_real_fdget_meta(file, &real, !datasync);
	if (ret)
		return ret;

	/* Don't sync lower file for fear of receiving EROFS error */
	if (file_inode(real.file) == ovl_inode_upper(inode)) {
		old_cred = ovl_override_creds(inode->i_sb);
		ret = vfs_fsync_range(real.file, start, end, datasync);
		revert_creds(old_cred);
	}
	fdput(real);

	return ret;
}

static int ovl_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	int err;

	if (ovl_should_use_filemap_meta(file, true)) {
		err = file_write_and_wait_range(file, start, end);
		if (err)
			return err;
	}

	return ovl_real_fsync(file, start, end, datasync);
}

static vm_fault_t ovl_fault(struct vm_fault *vmf)
{
	struct file *file = vmf->vma->vm_file;
	struct inode *inode = file_inode(file);
	bool blocking = (vmf->flags & FAULT_FLAG_KILLABLE) ||
			((vmf->flags & FAULT_FLAG_ALLOW_RETRY) &&
			 !(vmf->flags & FAULT_FLAG_RETRY_NOWAIT));
	bool is_upper = ovl_has_upperdata(inode);
	int ret = VM_FAULT_NOPAGE;
	int err = 0;

	/*
	 * Handle fault of pages in maps that were created from file that was
	 * opened O_RDWR and before data copy up.
	 */
	if (!is_upper) {
		/* TODO: async copy up data? */
		if (!blocking)
			goto out_err;

		up_read(&vmf->vma->vm_mm->mmap_sem);
		/* We must return VM_FAULT_RETRY if we released mmap_sem */
		ret = VM_FAULT_RETRY;
		err = ovl_maybe_copy_up(file_dentry(file), OVL_COPY_UP_DATA);
		if (err)
			goto out_err;

		return ret;
	}
	return filemap_fault(vmf);

out_err:
	pr_warn_ratelimited("overlayfs: %s %s data on page fault (%pd2, err=%i)\n",
			    blocking ? "failed to" : "no wait for",
			    is_upper ? "readahead" : "copy up",
			    file_dentry(file), err);

	return ret;
}

static const struct vm_operations_struct ovl_file_vm_ops = {
	.fault		= ovl_fault,
	.map_pages	= filemap_map_pages,
	.page_mkwrite   = filemap_page_mkwrite,
};

static int ovl_real_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct file *realfile = file->private_data;
	const struct cred *old_cred;
	int ret;

	if (!realfile->f_op->mmap)
		return -ENODEV;

	if (WARN_ON(file != vma->vm_file))
		return -EIO;

	vma->vm_file = get_file(realfile);

	old_cred = ovl_override_creds(file_inode(file)->i_sb);
	ret = call_mmap(vma->vm_file, vma);
	revert_creds(old_cred);

	if (ret) {
		/* Drop reference count from new vm_file value */
		fput(realfile);
	} else {
		/* Drop reference count from previous vm_file value */
		fput(file);
	}

	ovl_file_accessed(file);

	return ret;
}

static int ovl_mmap(struct file *file, struct vm_area_struct *vma)
{
	/*
	 * All maps (also private and non writable) that are created from file
	 * that was opened after copy up, map overlay inode pages. If the file
	 * was opened O_RDWR with lazy copy up of data, the first page fault
	 * will trigger data copy up.
	 *
	 * FIXME: SHARED maps that are created from file opened O_RDONLY before
	 * data copy up will stay mapped to lower real file also after copy up.
	 */
	if (ovl_should_use_filemap_meta(file, true)) {
		vma->vm_ops = &ovl_file_vm_ops;
		file_accessed(file);
		return 0;
	}

	return ovl_real_mmap(file, vma);
}

static long ovl_fallocate(struct file *file, int mode, loff_t offset,
			  loff_t len)
{
	struct inode *inode = file_inode(file);
	struct fd real;
	const struct cred *old_cred;
	int ret;

	inode_lock(inode);

	/* XXX: Different modes need to flush different ranges... */
	ret = ovl_flush_filemap(file, 0, LLONG_MAX);
	if (ret)
		goto unlock;

	ret = ovl_real_fdget(file, &real);
	if (ret)
		goto unlock;

	old_cred = ovl_override_creds(file_inode(file)->i_sb);
	ret = vfs_fallocate(real.file, mode, offset, len);
	revert_creds(old_cred);

	/* Update size */
	ovl_copyattr_size(ovl_inode_real(inode), inode);

	/* and invalidate mappings and page cache */
	truncate_pagecache_range(inode, 0, LLONG_MAX);

	fdput(real);
unlock:
	inode_unlock(inode);

	return ret;
}

static int ovl_real_fadvise(struct file *file, loff_t offset, loff_t len,
			    int advice)
{
	struct fd real;
	const struct cred *old_cred;
	int ret;

	ret = ovl_real_fdget(file, &real);
	if (ret)
		return ret;

	old_cred = ovl_override_creds(file_inode(file)->i_sb);
	ret = vfs_fadvise(real.file, offset, len, advice);
	revert_creds(old_cred);

	fdput(real);

	return ret;
}

extern int generic_fadvise(struct file *file, loff_t offset, loff_t len,
			   int advice);

static int ovl_fadvise(struct file *file, loff_t offset, loff_t len, int advice)
{
	if (ovl_should_use_filemap_meta(file, true))
		return generic_fadvise(file, offset, len, advice);

	/* XXX: Should we allow messing with lower shared page cache? */
	return ovl_real_fadvise(file, offset, len, advice);
}

static long ovl_real_ioctl(struct file *file, unsigned int cmd,
			   unsigned long arg)
{
	struct fd real;
	const struct cred *old_cred;
	long ret;

	ret = ovl_real_fdget(file, &real);
	if (ret)
		return ret;

	old_cred = ovl_override_creds(file_inode(file)->i_sb);
	ret = vfs_ioctl(real.file, cmd, arg);
	revert_creds(old_cred);

	fdput(real);

	return ret;
}

static long ovl_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	long ret;
	struct inode *inode = file_inode(file);

	switch (cmd) {
	case FS_IOC_GETFLAGS:
		ret = ovl_real_ioctl(file, cmd, arg);
		break;

	case FS_IOC_SETFLAGS:
		if (!inode_owner_or_capable(inode))
			return -EACCES;

		ret = mnt_want_write_file(file);
		if (ret)
			return ret;

		ret = ovl_maybe_copy_up(file_dentry(file), OVL_COPY_UP_DATA);
		if (!ret) {
			ret = ovl_real_ioctl(file, cmd, arg);

			inode_lock(inode);
			ovl_copyflags(ovl_inode_real(inode), inode);
			inode_unlock(inode);
		}

		mnt_drop_write_file(file);
		break;

	default:
		ret = -ENOTTY;
	}

	return ret;
}

static long ovl_compat_ioctl(struct file *file, unsigned int cmd,
			     unsigned long arg)
{
	switch (cmd) {
	case FS_IOC32_GETFLAGS:
		cmd = FS_IOC_GETFLAGS;
		break;

	case FS_IOC32_SETFLAGS:
		cmd = FS_IOC_SETFLAGS;
		break;

	default:
		return -ENOIOCTLCMD;
	}

	return ovl_ioctl(file, cmd, arg);
}

enum ovl_copyop {
	OVL_COPY,
	OVL_CLONE,
	OVL_DEDUPE,
};

static loff_t ovl_copyfile(struct file *file_in, loff_t pos_in,
			    struct file *file_out, loff_t pos_out,
			    loff_t len, unsigned int flags, enum ovl_copyop op)
{
	struct inode *inode_out = file_inode(file_out);
	struct fd real_in, real_out;
	const struct cred *old_cred;
	loff_t ret;

	inode_lock(inode_out);

	ret = ovl_flush_filemap(file_out, pos_out, LLONG_MAX);
	if (ret)
		goto unlock;

	ret = ovl_flush_filemap(file_in, pos_in, LLONG_MAX);
	if (ret)
		goto unlock;

	ret = ovl_real_fdget(file_out, &real_out);
	if (ret)
		goto unlock;

	ret = ovl_real_fdget(file_in, &real_in);
	if (ret)
		goto fdput_out;

	old_cred = ovl_override_creds(file_inode(file_out)->i_sb);
	switch (op) {
	case OVL_COPY:
		ret = vfs_copy_file_range(real_in.file, pos_in,
					  real_out.file, pos_out, len, flags);
		break;

	case OVL_CLONE:
		ret = vfs_clone_file_range(real_in.file, pos_in,
					   real_out.file, pos_out, len, flags);
		break;

	case OVL_DEDUPE:
		ret = vfs_dedupe_file_range_one(real_in.file, pos_in,
						real_out.file, pos_out, len,
						flags);
		break;
	}
	revert_creds(old_cred);

	/* Update size */
	ovl_copyattr_size(ovl_inode_real(inode_out), inode_out);

	if (op != OVL_DEDUPE)
		truncate_pagecache_range(inode_out,
					 round_down(pos_out, PAGE_SIZE),
					 LLONG_MAX);

	fdput(real_in);
fdput_out:
	fdput(real_out);
unlock:
	inode_unlock(inode_out);

	return ret;
}

static ssize_t ovl_copy_file_range(struct file *file_in, loff_t pos_in,
				   struct file *file_out, loff_t pos_out,
				   size_t len, unsigned int flags)
{
	return ovl_copyfile(file_in, pos_in, file_out, pos_out, len, flags,
			    OVL_COPY);
}

static loff_t ovl_remap_file_range(struct file *file_in, loff_t pos_in,
				   struct file *file_out, loff_t pos_out,
				   loff_t len, unsigned int remap_flags)
{
	enum ovl_copyop op;

	if (remap_flags & ~(REMAP_FILE_DEDUP | REMAP_FILE_ADVISORY))
		return -EINVAL;

	if (remap_flags & REMAP_FILE_DEDUP)
		op = OVL_DEDUPE;
	else
		op = OVL_CLONE;

	/*
	 * Don't copy up because of a dedupe request, this wouldn't make sense
	 * most of the time (data would be duplicated instead of deduplicated).
	 */
	if (op == OVL_DEDUPE &&
	    (!ovl_inode_upper(file_inode(file_in)) ||
	     !ovl_inode_upper(file_inode(file_out))))
		return -EPERM;

	return ovl_copyfile(file_in, pos_in, file_out, pos_out, len,
			    remap_flags, op);
}

const struct file_operations ovl_file_operations = {
	.open		= ovl_open,
	.release	= ovl_release,
	.llseek		= ovl_llseek,
	.read_iter	= ovl_read_iter,
	.write_iter	= ovl_write_iter,
	.fsync		= ovl_fsync,
	.mmap		= ovl_mmap,
	.fallocate	= ovl_fallocate,
	.fadvise	= ovl_fadvise,
	.unlocked_ioctl	= ovl_ioctl,
	.compat_ioctl	= ovl_compat_ioctl,

	.copy_file_range	= ovl_copy_file_range,
	.remap_file_range	= ovl_remap_file_range,
};

static int ovl_real_readpage(struct file *realfile, struct page *page)
{
	struct bio_vec bvec = {
		.bv_page = page,
		.bv_len = PAGE_SIZE,
		.bv_offset = 0,
	};
	loff_t pos = page->index << PAGE_SHIFT;
	struct iov_iter iter;
	ssize_t ret;

	iov_iter_bvec(&iter, READ, &bvec, 1, PAGE_SIZE);

	ret = vfs_iter_read(realfile, &iter, &pos, RWF_DIRECT);
	if (ret >= 0 && ret < PAGE_SIZE)
		zero_user_segment(page, ret, PAGE_SIZE);

	return ret < 0 ? ret : 0;
}

static int ovl_do_readpage(struct file *file, struct page *page)
{
	struct inode *inode = file_inode(file);
	struct ovl_inode *oi = OVL_I(inode);
	struct file *realfile = READ_ONCE(oi->upper_file);
	const struct cred *old_cred;
	int ret;

	if (!realfile)
		realfile = file->private_data;

	old_cred = ovl_override_creds(file_inode(file)->i_sb);
	ret = ovl_real_readpage(realfile, page);
	revert_creds(old_cred);

	if (!ret)
		SetPageUptodate(page);

	return 0;
}

struct ovl_readpage_work {
	struct file *file;
	struct page *page;
	struct work_struct work;
};

static void ovl_readpage_work_fn(struct work_struct *work)
{
	struct ovl_readpage_work *ow;

	ow = container_of(work, struct ovl_readpage_work, work);

	ovl_do_readpage(ow->file, ow->page);
	unlock_page(ow->page);
	kfree(ow);
}

static int ovl_readpage(struct file *file, struct page *page)
{
	struct ovl_readpage_work *ow;

	ow = kmalloc(sizeof(*ow), GFP_KERNEL);
	if (!ow) {
		unlock_page(page);
		return -ENOMEM;
	}
	ow->file = file;
	ow->page = page;
	INIT_WORK(&ow->work, ovl_readpage_work_fn);
	queue_work(ovl_wq, &ow->work);

	return 0;
}

static int ovl_write_begin(struct file *file, struct address_space *mapping,
			   loff_t pos, unsigned len, unsigned flags,
			   struct page **pagep, void **fsdata)
{
	struct page *page;
	pgoff_t index;
	int err;

	index = pos >> PAGE_SHIFT;

	page = grab_cache_page_write_begin(mapping, index, flags);
	if (!page)
		return -ENOMEM;

	if (!PageUptodate(page) && len != PAGE_SIZE) {
		err = ovl_do_readpage(file, page);
		if (err) {
			pr_warn("ovl_do_readpage: %i", err);
			unlock_page(page);
			put_page(page);

			return -EIO;
		}
	}

	*pagep = page;

	return 0;
}

static int ovl_write_end(struct file *file, struct address_space *mapping,
			 loff_t pos, unsigned len, unsigned copied,
			 struct page *page, void *fsdata)
{
	int res;

	res = simple_write_end(file, mapping, pos, len, copied, page, fsdata);

	//pr_info("ovl_write_end: page->flags: %lx\n", page->flags);

	return res;
}

static int ovl_real_writepage(struct page *page, struct writeback_control *wbc)
{
	struct ovl_inode *oi = OVL_I(page->mapping->host);
	struct file *realfile = oi->upper_file;
	loff_t pos = page->index << PAGE_SHIFT;
	loff_t size = i_size_read(page->mapping->host);
	size_t len = PAGE_SIZE;
	struct bio_vec bvec = {
		.bv_page = page,
		.bv_len = PAGE_SIZE,
		.bv_offset = 0,
	};
	struct iov_iter iter;
	ssize_t ret;
	rwf_t flags = 0;

	if (size <= pos) {
		pr_info("ovl_writepage: size = %lli pos = %lli\n", size, pos);
		return 0;
	}
	
	if (size < pos + PAGE_SIZE) {
		/* Can't do direct I/O for tail pages */
		len = size - pos;
	} else if (realfile->f_mapping->a_ops &&
		   realfile->f_mapping->a_ops->direct_IO) {
		flags |= RWF_DIRECT;
	}

	//pr_info("ovl_real_writepage(%lli)\n", pos);
	iov_iter_bvec(&iter, WRITE, &bvec, 1, len);

	ret = vfs_iter_write(realfile, &iter, &pos, flags);
	if (ret != len)
		pr_warn("ovl_read_writepage: write returned %zi (not %zi)\n",
			ret, len);

	/* FADV_DONTNEED for tail pages*/

	//pr_info("ovl_real_writepage(%lli) = %li\n", pos, ret);

	return ret < 0 ? ret : 0;
}

static int ovl_writepage(struct page *page, struct writeback_control *wbc)
{
	int ret;
	const struct cred *old_cred;

	set_page_writeback(page);

	old_cred = ovl_override_creds(page->mapping->host->i_sb);
	ret = ovl_real_writepage(page, wbc);
	revert_creds(old_cred);

	unlock_page(page);

	/*
	 * writepage responsibility is to get the data to our backing store.
	 * Persisting backing store to media requires a call to ovl_sync_fs.
	 */
	end_page_writeback(page);

	return ret;
}

static ssize_t ovl_direct_IO(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);
	rwf_t flags = ovl_iocb_to_rwf(iocb);
	const struct cred *old_cred;
	struct fd real;
	ssize_t ret;

	ret = ovl_real_fdget(file, &real);
	if (ret)
		goto out;

	old_cred = ovl_override_creds(file_inode(file)->i_sb);
	if (iov_iter_rw(iter) == READ) {
		ret = vfs_iter_read(real.file,iter, &iocb->ki_pos, flags);
	} else {
		file_start_write(real.file);
		ret = vfs_iter_write(real.file, iter, &iocb->ki_pos, flags);
		file_end_write(real.file);

		/* Update size */
		ovl_copyattr_size(ovl_inode_real(inode), inode);
	}
	revert_creds(old_cred);
	fdput(real);
out:
	return ret;
}

const struct address_space_operations ovl_aops = {
	.readpage	= ovl_readpage,
	.write_begin	= ovl_write_begin,
	.write_end	= ovl_write_end,
	.set_page_dirty	= __set_page_dirty_nobuffers,
	.writepage	= ovl_writepage,
	/* For O_DIRECT dentry_open() checks f_mapping->a_ops->direct_IO */
	.direct_IO	= ovl_direct_IO,
};
