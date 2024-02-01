// SPDX-License-Identifier: GPL-2.0
/*
 * FUSE inode io modes.
 *
 * Copyright (c) 2024 CTERA Networks.
 */

#include "fuse_i.h"

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/file.h>
#include <linux/fs.h>

/*
 * Request an open in caching mode.
 * Return 0 if in caching mode.
 */
static int fuse_inode_get_io_cache(struct fuse_inode *fi)
{
	assert_spin_locked(&fi->lock);
	if (fi->iocachectr < 0)
		return -ETXTBSY;
	if (fi->iocachectr++ == 0)
		set_bit(FUSE_I_CACHE_IO_MODE, &fi->state);
	return 0;
}

/*
 * Release an open in caching mode.
 * Return 0 if in neutral (direct io) mode.
 */
static int fuse_inode_put_io_cache(struct fuse_inode *fi)
{
	assert_spin_locked(&fi->lock);
	if (WARN_ON(fi->iocachectr <= 0))
		return -EIO;
	if (--fi->iocachectr == 0)
		clear_bit(FUSE_I_CACHE_IO_MODE, &fi->state);
	return fi->iocachectr;
}

/*
 * Requets to deny new opens in caching mode.
 * Return 0 if denying new opens in caching mode.
 */
static int fuse_inode_deny_io_cache(struct fuse_inode *fi)
{
	assert_spin_locked(&fi->lock);
	if (fi->iocachectr > 0)
		return -ETXTBSY;
	fi->iocachectr--;
	return 0;
}

/*
 * Release a request to deny open in caching mode.
 * Return 0 if allowing new opens in caching mode.
 */
static int fuse_inode_allow_io_cache(struct fuse_inode *fi)
{
	assert_spin_locked(&fi->lock);
	if (WARN_ON(fi->iocachectr >= 0))
		return -EIO;
	fi->iocachectr++;
	return -fi->iocachectr;
}

/* Start cached io mode where parallel dio writes are not allowed */
int fuse_file_cached_io_start(struct inode *inode)
{
	struct fuse_inode *fi = get_fuse_inode(inode);
	int err;

	spin_lock(&fi->lock);
	err = fuse_inode_get_io_cache(fi);
	spin_unlock(&fi->lock);
	return err;
}

void fuse_file_cached_io_end(struct inode *inode)
{
	struct fuse_inode *fi = get_fuse_inode(inode);

	spin_lock(&fi->lock);
	fuse_inode_put_io_cache(get_fuse_inode(inode));
	spin_unlock(&fi->lock);
}

/* Start strictly uncached io mode where cache access is not allowed */
int fuse_file_uncached_io_start(struct inode *inode)
{
	struct fuse_inode *fi = get_fuse_inode(inode);
	int err;

	spin_lock(&fi->lock);
	err = fuse_inode_deny_io_cache(fi);
	spin_unlock(&fi->lock);
	return err;
}

void fuse_file_uncached_io_end(struct inode *inode)
{
	struct fuse_inode *fi = get_fuse_inode(inode);

	spin_lock(&fi->lock);
	fuse_inode_allow_io_cache(fi);
	spin_unlock(&fi->lock);
}

/* Open flags to determine regular file io mode */
#define FOPEN_IO_MODE_MASK (FOPEN_DIRECT_IO)

/* Request access to submit new io to inode via open file */
int fuse_file_io_open(struct file *file, struct inode *inode)
{
	struct fuse_file *ff = file->private_data;
	int iomode_flags = ff->open_flags & FOPEN_IO_MODE_MASK;
	int err;

	err = -EBADF;
	if (WARN_ON(!S_ISREG(inode->i_mode)))
		goto fail;

	err = -EBUSY;
	if (WARN_ON(ff->io_opened))
		goto fail;

	/*
	 * io modes are not relevant with DAX and with server that does not
	 * implement open.
	 */
	err = -EINVAL;
	if (FUSE_IS_DAX(inode) || !ff->release_args) {
		if (iomode_flags)
			goto fail;
		return 0;
	}

	/*
	 * FOPEN_PARALLEL_DIRECT_WRITES requires FOPEN_DIRECT_IO.
	 */
	if (!(ff->open_flags & FOPEN_DIRECT_IO))
		ff->open_flags &= ~FOPEN_PARALLEL_DIRECT_WRITES;

	/*
	 * First parallel dio open denies caching inode io mode.
	 * First caching file open enters caching inode io mode.
	 *
	 * Note that if user opens a file open with O_DIRECT, but server did
	 * not specify FOPEN_DIRECT_IO, a later fcntl() could remove O_DIRECT,
	 * so we put the inode in caching mode to prevent parallel dio.
	 */
	if (ff->open_flags & FOPEN_PARALLEL_DIRECT_WRITES)
		err = fuse_file_uncached_io_start(inode);
	else if (ff->open_flags & FOPEN_DIRECT_IO)
		return 0;
	else
		err = fuse_file_cached_io_start(inode);
	if (err)
		goto fail;

	/* io_opened means we hold a positive or nagative iocachectr refcount */
	ff->io_opened = true;
	return 0;

fail:
	pr_debug("failed to open file in requested io mode (open_flags=0x%x, err=%i).\n",
		 ff->open_flags, err);
	/*
	 * The file open mode determines the inode io mode.
	 * Using incorrect open mode is a server mistake, which results in
	 * user visible failure of open() with EIO error.
	 */
	return -EIO;
}

/* Request access to submit new io to inode via mmap */
int fuse_file_io_mmap(struct fuse_file *ff, struct inode *inode)
{
	struct fuse_inode *fi = get_fuse_inode(inode);
	int err = 0;

	/* There are no io modes if server does not implement open */
	if (!ff->release_args)
		return 0;

	spin_lock(&fi->lock);
	/* First mmap of direct_io file enters caching inode io mode */
	if (!ff->io_opened) {
		err = fuse_inode_get_io_cache(fi);
		if (!err)
			ff->io_opened = true;
	}
	spin_unlock(&fi->lock);

	return err;
}

/* No more pending io and no new io possible to inode via open/mmapped file */
void fuse_file_io_release(struct fuse_file *ff, struct inode *inode)
{
	if (!ff->io_opened)
		return;

	/*
	 * Last parallel dio close allows caching inode io mode.
	 * Last caching file close exits caching inode io mode.
	 */
	if (ff->open_flags & FOPEN_PARALLEL_DIRECT_WRITES)
		fuse_file_uncached_io_end(inode);
	else
		fuse_file_cached_io_end(inode);

	ff->io_opened = false;
}
