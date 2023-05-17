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
	if (!passthrough_filp->f_op->read_iter ||
	    !passthrough_filp->f_op->write_iter)
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
