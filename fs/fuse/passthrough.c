// SPDX-License-Identifier: GPL-2.0
/*
 * FUSE passthrough support.
 *
 * Copyright (c) 2021 Google LLC.
 * Copyright (c) 2023 CTERA Networks.
 */

#include "fuse_i.h"

#include <linux/file.h>
#include <linux/idr.h>
#include <linux/backing-fs.h>

static void fuse_file_start_write(struct file *file, loff_t pos, size_t count)
{
	struct inode *inode = file_inode(file);
	struct fuse_inode *fi = get_fuse_inode(inode);

	if (inode->i_size < pos + count)
		set_bit(FUSE_I_SIZE_UNSTABLE, &fi->state);
}

static void fuse_file_end_write(struct file *file, loff_t pos, ssize_t res)
{
	struct inode *inode = file_inode(file);
	struct fuse_inode *fi = get_fuse_inode(inode);

	fuse_write_update_attr(inode, pos, res);
	clear_bit(FUSE_I_SIZE_UNSTABLE, &fi->state);
}

static void fuse_file_accessed(struct file *file, struct file *backing_file)
{
	struct inode *inode = file_inode(file);
	struct inode *backing_inode = file_inode(backing_file);

	/* Mimic atime update policy of backing inode, not the actual value */
	if (!timespec64_equal(&backing_inode->i_atime, &inode->i_atime))
		fuse_invalidate_atime(inode);
}

/* Completion for submitted/failed sync/async rw io */
static void fuse_rw_complete(struct kiocb *iocb, long res)
{
	struct file *file = iocb->ki_filp;
	struct fuse_file *ff = file->private_data;

	if (iocb->ki_flags & IOCB_WRITE) {
		/* Update size/mtime */
		fuse_file_end_write(file, iocb->ki_pos, res);
	} else {
		/* Update atime */
		fuse_file_accessed(file, ff->passthrough->filp);
	}
}

ssize_t fuse_passthrough_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;
	struct fuse_file *ff = file->private_data;
	struct file *backing_file = ff->passthrough->filp;
	const struct cred *old_cred;
	ssize_t ret;

	if (!iov_iter_count(iter))
		return 0;

	old_cred = override_creds(ff->passthrough->cred);
	ret = backing_file_read_iter(backing_file, iter, iocb, iocb->ki_flags,
				     fuse_rw_complete);
	revert_creds(old_cred);

	return ret;
}

ssize_t fuse_passthrough_write_iter(struct kiocb *iocb,
				    struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);
	struct fuse_file *ff = file->private_data;
	struct file *backing_file = ff->passthrough->filp;
	size_t count = iov_iter_count(iter);
	const struct cred *old_cred;
	ssize_t ret;

	if (!count)
		return 0;

	inode_lock(inode);
	fuse_file_start_write(file, iocb->ki_pos, count);
	old_cred = override_creds(ff->passthrough->cred);
	ret = backing_file_write_iter(backing_file, iter, iocb, iocb->ki_flags,
				      fuse_rw_complete);
	revert_creds(old_cred);
	inode_unlock(inode);

	return ret;
}

ssize_t fuse_passthrough_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct fuse_file *ff = file->private_data;
	struct file *backing_file = ff->passthrough->filp;
	const struct cred *old_cred;
	int ret;

	if (!backing_file->f_op->mmap)
		return -ENODEV;

	if (WARN_ON(file != vma->vm_file))
		return -EIO;

	vma->vm_file = get_file(backing_file);

	old_cred = override_creds(ff->passthrough->cred);
	ret = call_mmap(vma->vm_file, vma);
	revert_creds(old_cred);
	fuse_file_accessed(file, backing_file);

	if (ret)
		fput(backing_file);
	else
		fput(file);

	return ret;
}

int fuse_passthrough_readdir(struct file *file, struct dir_context *ctx)
{
	struct fuse_file *ff = file->private_data;
	struct inode *inode = file_inode(file);
	struct file *backing_file = ff->passthrough->filp;
	const struct cred *old_cred;
	bool locked;
	int ret;

	locked = fuse_lock_inode(inode);
	old_cred = override_creds(ff->passthrough->cred);
	ret = iterate_dir(backing_file, ctx);
	revert_creds(old_cred);
	fuse_file_accessed(file, backing_file);
	fuse_unlock_inode(inode, locked);

	return ret;
}

/*
 * Returns passthrough_fh id that can be passed with FOPEN_PASSTHROUGH
 * open response and needs to be released with fuse_passthrough_close().
 */
int fuse_passthrough_open(struct fuse_conn *fc, int backing_fd)
{
	struct file *passthrough_filp;
	struct inode *passthrough_inode;
	struct super_block *passthrough_sb;
	struct fuse_passthrough *passthrough;
	int res;

	if (!fc->passthrough)
		return -EPERM;

	passthrough_filp = fget(backing_fd);
	if (!passthrough_filp)
		return -EBADF;

	res = -EOPNOTSUPP;
	if (!passthrough_filp->f_op->iterate_shared &&
	    !(passthrough_filp->f_op->read_iter &&
	      passthrough_filp->f_op->write_iter))
		goto out_fput;

	passthrough_inode = file_inode(passthrough_filp);
	passthrough_sb = passthrough_inode->i_sb;
	res = -ELOOP;
	if (passthrough_sb->s_stack_depth >= FILESYSTEM_MAX_STACK_DEPTH)
		goto out_fput;

	passthrough = kmalloc(sizeof(struct fuse_passthrough), GFP_KERNEL);
	res = -ENOMEM;
	if (!passthrough)
		goto out_fput;

	passthrough->filp = passthrough_filp;
	passthrough->cred = prepare_creds();
	refcount_set(&passthrough->count, 1);

	idr_preload(GFP_KERNEL);
	spin_lock(&fc->lock);
	res = idr_alloc_cyclic(&fc->passthrough_files_map, passthrough, 1, 0,
			       GFP_ATOMIC);
	spin_unlock(&fc->lock);
	idr_preload_end();

	if (res < 0)
		fuse_passthrough_free(passthrough);

	return res;

out_fput:
	fput(passthrough_filp);

	return res;
}

int fuse_passthrough_close(struct fuse_conn *fc, int passthrough_fh)
{
	struct fuse_passthrough *passthrough;

	if (!fc->passthrough)
		return -EPERM;

	if (passthrough_fh <= 0)
		return -EINVAL;

	spin_lock(&fc->lock);
	passthrough = idr_remove(&fc->passthrough_files_map, passthrough_fh);
	spin_unlock(&fc->lock);

	if (!passthrough)
		return -ENOENT;

	fuse_passthrough_put(passthrough);

	return 0;
}

int fuse_passthrough_setup(struct fuse_conn *fc, struct fuse_file *ff,
			   struct fuse_open_out *openarg)
{
	int passthrough_fh = openarg->passthrough_fh;
	struct fuse_passthrough *passthrough;

	if (passthrough_fh <= 0)
		return -EINVAL;

	rcu_read_lock();
	passthrough = idr_find(&fc->passthrough_files_map, passthrough_fh);
	if (passthrough && !refcount_inc_not_zero(&passthrough->count))
		passthrough = NULL;
	rcu_read_unlock();
	if (!passthrough)
		return -ENOENT;

	ff->passthrough = passthrough;

	return 0;
}

void fuse_passthrough_put(struct fuse_passthrough *passthrough)
{
	if (passthrough && refcount_dec_and_test(&passthrough->count))
		fuse_passthrough_free(passthrough);
}

void fuse_passthrough_free(struct fuse_passthrough *passthrough)
{
	if (!passthrough)
	       return;

	if (passthrough->filp) {
		fput(passthrough->filp);
		passthrough->filp = NULL;
	}
	if (passthrough->cred) {
		put_cred(passthrough->cred);
		passthrough->cred = NULL;
	}
	kfree_rcu(passthrough, rcu);
}
