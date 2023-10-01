// SPDX-License-Identifier: GPL-2.0
/*
 * FUSE passthrough to backing file.
 *
 * Copyright (c) 2023 CTERA Networks.
 */

#include "fuse_i.h"

#include <linux/file.h>
#include <linux/backing-file.h>
#include <linux/splice.h>

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

static void fuse_file_accessed(struct file *file)
{
	struct inode *inode = file_inode(file);
	struct fuse_file *ff = file->private_data;
	struct fuse_backing *fb = fuse_file_passthrough(ff);
	struct inode *backing_inode = file_inode(fb->file);

	/* Mimic atime update policy of backing inode, not the actual value */
	if (!timespec64_equal(&backing_inode->i_atime, &inode->i_atime))
		fuse_invalidate_atime(inode);
}

ssize_t fuse_passthrough_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;
	struct fuse_file *ff = file->private_data;
	struct fuse_backing *fb = fuse_file_passthrough(ff);
	size_t count = iov_iter_count(iter);
	const struct cred *old_cred;
	ssize_t ret;

	pr_debug("%s: fb=0x%p, pos=%lld, len=%zu\n", __func__,
		 fb, iocb->ki_pos, count);

	if (!count)
		return 0;

	old_cred = override_creds(fb->cred);
	ret = backing_file_read_iter(fb->file, iter, iocb, iocb->ki_flags,
				     fuse_file_accessed);
	revert_creds(old_cred);

	return ret;
}

ssize_t fuse_passthrough_write_iter(struct kiocb *iocb,
				    struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);
	struct fuse_file *ff = file->private_data;
	struct fuse_backing *fb = fuse_file_passthrough(ff);
	size_t count = iov_iter_count(iter);
	const struct cred *old_cred;
	ssize_t ret;

	pr_debug("%s: fb=0x%p, pos=%lld, len=%zu\n", __func__,
		 fb, iocb->ki_pos, count);

	if (!count)
		return 0;

	inode_lock(inode);
	fuse_file_start_write(file, iocb->ki_pos, count);
	old_cred = override_creds(fb->cred);
	ret = backing_file_write_iter(fb->file, iter, iocb, iocb->ki_flags,
				      fuse_file_end_write);
	revert_creds(old_cred);
	inode_unlock(inode);

	return ret;
}

ssize_t fuse_passthrough_splice_read(struct file *in, loff_t *ppos,
				     struct pipe_inode_info *pipe,
				     size_t len, unsigned int flags)
{
	struct fuse_file *ff = in->private_data;
	struct fuse_backing *fb = fuse_file_passthrough(ff);
	const struct cred *old_cred;
	ssize_t ret;

	pr_debug("%s: fb=0x%p, pos=%lld, len=%zu, flags=0x%x\n", __func__,
		 fb, ppos ? *ppos : 0, len, flags);

	old_cred = override_creds(fb->cred);
	ret = vfs_splice_read(fb->file, ppos, pipe, len, flags);
	revert_creds(old_cred);
	fuse_file_accessed(in);

	return ret;
}

ssize_t fuse_passthrough_splice_write(struct pipe_inode_info *pipe,
				      struct file *out, loff_t *ppos,
				      size_t len, unsigned int flags)
{
	struct fuse_file *ff = out->private_data;
	struct fuse_backing *fb = fuse_file_passthrough(ff);
	const struct cred *old_cred;
	struct inode *inode = file_inode(out);
	ssize_t ret;

	pr_debug("%s: fb=0x%p, pos=%lld, len=%zu, flags=0x%x\n", __func__,
		 fb, ppos ? *ppos : 0, len, flags);

	inode_lock(inode);
	fuse_file_start_write(out, ppos ? *ppos : 0, len);
	ret = file_remove_privs(out);
	if (ret)
		goto out_unlock;

	old_cred = override_creds(fb->cred);
	file_start_write(fb->file);

	ret = iter_file_splice_write(pipe, fb->file, ppos, len, flags);

	file_end_write(fb->file);
	revert_creds(old_cred);
	fuse_file_end_write(out, ppos ? *ppos : 0, ret);

out_unlock:
	inode_unlock(inode);

	return ret;
}

ssize_t fuse_passthrough_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct fuse_file *ff = file->private_data;
	struct fuse_backing *fb = fuse_file_passthrough(ff);
	const struct cred *old_cred;
	int ret;

	pr_debug("%s: fb=0x%p, start=%lu, end=%lu\n", __func__,
		 fb, vma->vm_start, vma->vm_end);

	if (!fb->file->f_op->mmap)
		return -ENODEV;

	if (WARN_ON(file != vma->vm_file))
		return -EIO;

	vma->vm_file = get_file(fb->file);

	old_cred = override_creds(fb->cred);
	ret = call_mmap(vma->vm_file, vma);
	revert_creds(old_cred);
	fuse_file_accessed(file);

	if (ret)
		fput(fb->file);
	else
		fput(file);

	return ret;
}

int fuse_passthrough_readdir(struct file *file, struct dir_context *ctx)
{
	struct fuse_file *ff = file->private_data;
	struct inode *inode = file_inode(file);
	struct fuse_backing *fb = fuse_file_passthrough(ff);
	const struct cred *old_cred;
	bool locked;
	int ret;

	pr_debug("%s: fb=0x%p, pos=%lld\n", __func__, fb, ctx->pos);

	locked = fuse_lock_inode(inode);
	old_cred = override_creds(fb->cred);
	ret = iterate_dir(fb->file, ctx);
	revert_creds(old_cred);
	fuse_file_accessed(file);
	fuse_unlock_inode(inode, locked);

	return ret;
}

struct fuse_backing *fuse_backing_get(struct fuse_backing *fb)
{
	if (fb && refcount_inc_not_zero(&fb->count))
		return fb;
	return NULL;
}

static void fuse_backing_free(struct fuse_backing *fb)
{
	pr_debug("%s: fb=0x%p\n", __func__, fb);

	if (fb->file)
		fput(fb->file);
	if (fb->cred)
		put_cred(fb->cred);
	kfree_rcu(fb, rcu);
}

void fuse_backing_put(struct fuse_backing *fb)
{
	if (fb && refcount_dec_and_test(&fb->count))
		fuse_backing_free(fb);
}

void fuse_backing_files_init(struct fuse_conn *fc)
{
	idr_init(&fc->backing_files_map);
}

static int fuse_backing_id_alloc(struct fuse_conn *fc, struct fuse_backing *fb)
{
	int id;

	idr_preload(GFP_KERNEL);
	spin_lock(&fc->lock);
	id = idr_alloc_cyclic(&fc->backing_files_map, fb, 1, 0,
			       GFP_ATOMIC);
	spin_unlock(&fc->lock);
	idr_preload_end();

	WARN_ON_ONCE(id == 0);
	return id;
}

static struct fuse_backing *fuse_backing_id_remove(struct fuse_conn *fc,
						   int id)
{
	struct fuse_backing *fb;

	spin_lock(&fc->lock);
	fb = idr_remove(&fc->backing_files_map, id);
	spin_unlock(&fc->lock);

	return fb;
}

static int fuse_backing_id_free(int id, void *p, void *data)
{
	struct fuse_backing *fb = p;

	WARN_ON_ONCE(refcount_read(&fb->count) != 1);
	fuse_backing_free(fb);
	return 0;
}

void fuse_backing_files_free(struct fuse_conn *fc)
{
	idr_for_each(&fc->backing_files_map, fuse_backing_id_free, NULL);
	idr_destroy(&fc->backing_files_map);
}

int fuse_backing_open(struct fuse_conn *fc, struct fuse_backing_map *map)
{
	struct file *backing_file;
	struct super_block *backing_sb;
	struct fuse_backing *fb;
	int res;

	pr_debug("%s: fd=%d flags=0x%x\n", __func__, map->fd, map->flags);

	/* TODO: relax CAP_SYS_ADMIN once backing files are visible to lsof */
	if (!fc->passthrough || !capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (map->flags)
		return -EINVAL;

	backing_file = fget(map->fd);
	if (!backing_file)
		return -EBADF;

	res = -EOPNOTSUPP;
	if (!backing_file->f_op->iterate_shared &&
	    !(backing_file->f_op->read_iter &&
	      backing_file->f_op->write_iter))
		goto out_fput;

	backing_sb = file_inode(backing_file)->i_sb;
	res = -ELOOP;
	if (backing_sb->s_stack_depth >= fc->max_stack_depth)
		goto out_fput;

	fb = kmalloc(sizeof(struct fuse_backing), GFP_KERNEL);
	res = -ENOMEM;
	if (!fb)
		goto out_fput;

	fb->file = backing_file;
	fb->cred = prepare_creds();
	refcount_set(&fb->count, 1);

	res = fuse_backing_id_alloc(fc, fb);
	if (res < 0)
		fuse_backing_free(fb);
	else
		pr_debug("%s: backing_id=%d, fb=0x%p\n", __func__,
			 res, fb);

	return res;

out_fput:
	fput(backing_file);

	return res;
}

int fuse_backing_close(struct fuse_conn *fc, int backing_id)
{
	struct fuse_backing *fb;

	pr_debug("%s: backing_id=%u\n", __func__, backing_id);

	/* TODO: relax CAP_SYS_ADMIN once backing files are visible to lsof */
	if (!fc->passthrough || !capable(CAP_SYS_ADMIN))
		return -EPERM;

	fb = fuse_backing_id_remove(fc, backing_id);
	if (!fb)
		return -ENOENT;

	fuse_backing_put(fb);

	return 0;
}

/* Setup passthrough to a backing file */
void fuse_passthrough_setup(struct fuse_file *ff, int backing_id)
{
	struct fuse_conn *fc = ff->fm->fc;
	struct fuse_backing *fb = NULL;
	bool auto_close = ff->open_flags & FOPEN_CLOSE_BACKING_ID;

	if (backing_id <= 0)
		goto out;

	if (auto_close) {
		/* transfer reference and unmap backing id */
		fb = fuse_backing_id_remove(fc, backing_id);
	} else {
		rcu_read_lock();
		fb = idr_find(&fc->backing_files_map, backing_id);
		fb = fuse_backing_get(fb);
		rcu_read_unlock();
	}

	/* Noop if the backing file is not mapped */
	ff->passthrough = fb;

out:
	pr_debug("%s: backing_id=%d, auto_close=%d, fb=0x%p\n", __func__,
		 backing_id, auto_close, fb);
}
