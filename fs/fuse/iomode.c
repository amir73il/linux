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
 * Return true if need to wait for new opens in caching mode.
 */
static inline bool fuse_is_io_cache_wait(struct fuse_inode *fi)
{
	return READ_ONCE(fi->iocachectr) < 0;
}

/*
 * Request an open in caching mode.
 * Blocks new parallel dio writes and waits for the in-progress parallel dio
 * writes to complete.
 * Return 0 if in caching mode.
 */
static int fuse_inode_get_io_cache(struct fuse_inode *fi)
{
	int err = 0;

	assert_spin_locked(&fi->lock);
	/*
	 * Setting the bit advises new direct-io writes to use an exclusive
	 * lock - without it the wait below might be forever.
	 */
	set_bit(FUSE_I_CACHE_IO_MODE, &fi->state);
	while (!err && fuse_is_io_cache_wait(fi)) {
		spin_unlock(&fi->lock);
		err = wait_event_killable(fi->direct_io_waitq,
					  !fuse_is_io_cache_wait(fi));
		spin_lock(&fi->lock);
	}
	/*
	 * Enter caching mode or clear the FUSE_I_CACHE_IO_MODE bit if we
	 * failed to enter caching mode and no other caching open exists.
	 */
	if (!err)
		fi->iocachectr++;
	else if (fi->iocachectr <= 0)
		clear_bit(FUSE_I_CACHE_IO_MODE, &fi->state);
	return err;
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
int fuse_file_uncached_io_start(struct inode *inode, struct fuse_backing *fb)
{
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct fuse_backing *oldfb;
	int err = -EBUSY;

	spin_lock(&fi->lock);
	/* deny conflicting backing files on same fuse inode */
	oldfb = fuse_inode_backing(fi);
	if (!oldfb || oldfb == fb)
		err = fuse_inode_deny_io_cache(fi);
	/* fuse inode holds a single refcount of backing file */
	if (!oldfb && !err) {
		oldfb = fuse_inode_backing_set(fi, fb);
		WARN_ON_ONCE(oldfb != NULL);
	} else if (!err) {
		fuse_backing_put(fb);
	}
	spin_unlock(&fi->lock);
	return err;
}

void fuse_file_uncached_io_end(struct inode *inode)
{
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct fuse_backing *oldfb = NULL;
	int uncached_io;

	spin_lock(&fi->lock);
	uncached_io = fuse_inode_allow_io_cache(fi);
	if (!uncached_io)
		oldfb = fuse_inode_backing_set(fi, NULL);
	spin_unlock(&fi->lock);
	if (!uncached_io)
		wake_up(&fi->direct_io_waitq);
	if (oldfb)
		fuse_backing_put(oldfb);
}

/*
 * Open flags that are allowed in combination with FOPEN_PASSTHROUGH.
 * A combination of FOPEN_PASSTHROUGH and FOPEN_DIRECT_IO means that read/write
 * operations go directly to the server, but mmap is done on the backing file.
 * FOPEN_PASSTHROUGH mode should not co-exist with any users of the fuse inode
 * page cache, so FOPEN_KEEP_CACHE is a strange and undesired combination.
 */
#define FOPEN_PASSTHROUGH_MASK \
	(FOPEN_PASSTHROUGH | FOPEN_DIRECT_IO | FOPEN_PARALLEL_DIRECT_WRITES | \
	 FOPEN_NOFLUSH)

static int fuse_file_passthrough_open(struct file *file, struct inode *inode)
{
	struct fuse_file *ff = file->private_data;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_backing *fb;
	int err;

	/* Check allowed conditions for file open in passthrough mode */
	if (!IS_ENABLED(CONFIG_FUSE_PASSTHROUGH) || !fc->passthrough ||
	    (ff->open_flags & ~FOPEN_PASSTHROUGH_MASK))
		return -EINVAL;

	fb = fuse_passthrough_open(file, inode,
				   ff->args->open_outarg.backing_id);
	if (IS_ERR(fb))
		return PTR_ERR(fb);

	/* First passthrough file open denies caching inode io mode */
	err = fuse_file_uncached_io_start(inode, fb);
	if (!err)
		return 0;

	fuse_passthrough_release(ff, fb);
	fuse_backing_put(fb);

	return err;
}

/* Open flags to determine regular file io mode */
#define FOPEN_IO_MODE_MASK \
	(FOPEN_DIRECT_IO | FOPEN_CACHE_IO | FOPEN_PASSTHROUGH)

/* Request access to submit new io to inode via open file */
int fuse_file_io_open(struct file *file, struct inode *inode)
{
	struct fuse_file *ff = file->private_data;
	struct fuse_inode *fi = get_fuse_inode(inode);
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
	if (FUSE_IS_DAX(inode) || !ff->args) {
		if (iomode_flags)
			goto fail;
		return 0;
	}

	/*
	 * Server is expected to use FOPEN_PASSTHROUGH for all opens of an inode
	 * which is already open for passthrough.
	 */
	if (fuse_inode_backing(fi) && !(ff->open_flags & FOPEN_PASSTHROUGH))
		goto fail;

	/*
	 * FOPEN_CACHE_IO is an internal flag that is set on file not open in
	 * direct io or passthrough mode and it cannot be set by the server.
	 * This includes a file open with O_DIRECT, but server did not specify
	 * FOPEN_DIRECT_IO. In this case, a later fcntl() could remove O_DIRECT,
	 * so we put the inode in caching mode to prevent parallel dio.
	 * FOPEN_PARALLEL_DIRECT_WRITES requires FOPEN_DIRECT_IO.
	 */
	if (ff->open_flags & FOPEN_CACHE_IO) {
		goto fail;
	} else if (!(ff->open_flags & FOPEN_IO_MODE_MASK)) {
		ff->open_flags |= FOPEN_CACHE_IO;
		ff->open_flags &= ~FOPEN_PARALLEL_DIRECT_WRITES;
	}

	/*
	 * First caching file open enters caching inode io mode.
	 */
	err = 0;
	if (ff->open_flags & FOPEN_CACHE_IO)
		err = fuse_file_cached_io_start(inode);
	else if (ff->open_flags & FOPEN_PASSTHROUGH)
		err = fuse_file_passthrough_open(file, inode);
	if (err)
		goto fail;

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

/* Request access to submit cached io to inode via mmap */
int fuse_file_io_mmap(struct fuse_file *ff, struct inode *inode)
{
	struct fuse_inode *fi = get_fuse_inode(inode);
	int err = 0;

	/* There are no io modes if server does not implement open */
	if (!ff->args)
		return 0;

	if (WARN_ON(ff->open_flags & FOPEN_PASSTHROUGH) ||
	    WARN_ON(!ff->io_opened))
		return -ENODEV;

	spin_lock(&fi->lock);
	/* First mmap of direct_io file enters caching inode io mode */
	if (!(ff->open_flags & FOPEN_CACHE_IO)) {
		err = fuse_inode_get_io_cache(fi);
		if (!err)
			ff->open_flags |= FOPEN_CACHE_IO;
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
	 * Last caching file close allows passthrough open of inode and
	 * Last passthrough file close allows caching open of inode.
	 */
	if (ff->open_flags & FOPEN_CACHE_IO)
		fuse_file_cached_io_end(inode);
	else if (ff->open_flags & FOPEN_PASSTHROUGH)
		fuse_file_uncached_io_end(inode);

	ff->io_opened = false;
}
