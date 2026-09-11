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
	return READ_ONCE(fi->iocachectr) < 0 && !fuse_inode_backing(fi);
}

/*
 * Called on cached file open() and on first mmap() of direct_io file.
 * Takes cached_io inode mode reference to be dropped on file release.
 *
 * Blocks new parallel dio writes and waits for the in-progress parallel dio
 * writes to complete.
 */
int fuse_file_cached_io_open(struct inode *inode, struct fuse_file *ff)
{
	struct fuse_inode *fi = get_fuse_inode(inode);

	/* There are no io modes if server does not implement open */
	if (!ff->args)
		return 0;

	spin_lock(&fi->lock);
	/*
	 * Setting the bit advises new direct-io writes to use an exclusive
	 * lock - without it the wait below might be forever.
	 */
	while (fuse_is_io_cache_wait(fi)) {
		set_bit(FUSE_I_CACHE_IO_MODE, &fi->state);
		spin_unlock(&fi->lock);
		wait_event(fi->direct_io_waitq, !fuse_is_io_cache_wait(fi));
		spin_lock(&fi->lock);
	}

	/*
	 * Check if inode entered passthrough io mode while waiting for parallel
	 * dio write completion.
	 */
	if (fuse_inode_backing(fi)) {
		clear_bit(FUSE_I_CACHE_IO_MODE, &fi->state);
		spin_unlock(&fi->lock);
		return -ETXTBSY;
	}

	WARN_ON(ff->iomode == IOM_UNCACHED);
	if (ff->iomode == IOM_NONE) {
		ff->iomode = IOM_CACHED;
		if (fi->iocachectr == 0)
			set_bit(FUSE_I_CACHE_IO_MODE, &fi->state);
		fi->iocachectr++;
	}
	spin_unlock(&fi->lock);
	return 0;
}

static void fuse_file_cached_io_release(struct fuse_file *ff,
					struct fuse_inode *fi)
{
	spin_lock(&fi->lock);
	WARN_ON(fi->iocachectr <= 0);
	WARN_ON(ff->iomode != IOM_CACHED);
	ff->iomode = IOM_NONE;
	fi->iocachectr--;
	if (fi->iocachectr == 0)
		clear_bit(FUSE_I_CACHE_IO_MODE, &fi->state);
	spin_unlock(&fi->lock);
}

/* Start strictly uncached io mode where cache access is not allowed */
int fuse_inode_uncached_io_start(struct inode *inode, struct fuse_file *ff,
				 struct fuse_backing *fb)
{
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_backing *oldfb;
	int err = 0;

	spin_lock(&fi->lock);
	/* deny conflicting backing files on same fuse inode */
	oldfb = fuse_inode_backing(fi);
	if (fb && oldfb && oldfb != fb) {
		err = -EBUSY;
		goto unlock;
	}
	/* FUSE_PASSTHROUGH_INO: backing_id is the fuse nodeid */
	if (fb && fc->passthrough_ino && fb->backing_id != get_node_id(inode)) {
		WARN_ON_ONCE(1);
		err = -EIO;
		goto unlock;
	}
	if (fi->iocachectr > 0) {
		err = -ETXTBSY;
		goto unlock;
	}
	/* every open file holds a single refcount of backing file... */
	if (ff)
		fi->iocachectr--;

	if (fb && !oldfb) {
		oldfb = fuse_inode_backing_set(fi, fb);
		WARN_ON_ONCE(oldfb != NULL);
		/* ...and an optional extra refcount for inode ops */
		if (!ff) {
			WARN_ON_ONCE(test_bit(FUSE_I_PASSTHROUGH, &fi->state));
			set_bit(FUSE_I_PASSTHROUGH, &fi->state);
			fi->iocachectr--;
		}
	} else {
		fuse_backing_put(fb);
	}
unlock:
	spin_unlock(&fi->lock);
	return err;
}

/* Takes uncached_io inode mode reference to be dropped on file release */
static int fuse_file_uncached_io_open(struct inode *inode,
				      struct fuse_file *ff,
				      struct fuse_backing *fb)
{
	int err;

	err = fuse_inode_uncached_io_start(inode, ff, fb);
	if (err)
		return fuse_err_EIO("failed to start uncached I/O", err);

	WARN_ON(ff->iomode != IOM_NONE);
	ff->iomode = IOM_UNCACHED;
	return 0;
}

void fuse_inode_uncached_io_end(struct inode *inode)
{
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct fuse_backing *oldfb = NULL;

	spin_lock(&fi->lock);
	WARN_ON(fi->iocachectr >= 0);
	fi->iocachectr++;
	if (!fi->iocachectr) {
		wake_up(&fi->direct_io_waitq);
		clear_bit(FUSE_I_PASSTHROUGH, &fi->state);
		oldfb = fuse_inode_backing_set(fi, NULL);
	}
	spin_unlock(&fi->lock);
	if (oldfb)
		fuse_backing_put(oldfb);
}

/* Drop uncached_io reference from passthrough open */
static void fuse_file_uncached_io_release(struct fuse_file *ff,
					  struct fuse_inode *fi)
{
	WARN_ON(ff->iomode != IOM_UNCACHED);
	ff->iomode = IOM_NONE;
	fuse_inode_uncached_io_end(&fi->inode);
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

static int fuse_file_passthrough_open(struct inode *inode, struct file *file)
{
	struct fuse_file *ff = file->private_data;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_backing *fb;
	u64 backing_id;
	bool is_64bit = ff->open_flags & FUSE_BACKING_ID_64;
	int err;

	ff->open_flags &= ~FUSE_BACKING_ID_64;

	/* Check allowed conditions for file open in passthrough mode */
	if (!IS_ENABLED(CONFIG_FUSE_PASSTHROUGH) || !fc->passthrough)
		return fuse_EIO("passthrough not enabled");

	if (ff->open_flags & ~FOPEN_PASSTHROUGH_MASK)
		return fuse_EIO("conflicting open flags");

	if (fc->passthrough_ino && !is_64bit)
		return fuse_EIO("PASSTHROUGH_INO requires 64bit backing id");

	if (!is_64bit)
		backing_id = ff->args->open_outarg.backing_id;
	else
		backing_id = ff->args->open_outarg.backing_id_64;

	if (fc->passthrough_ino && backing_id != get_node_id(inode)) {
		WARN_ON_ONCE(1);
		return fuse_EIO("backing_id must equal nodeid");
	}

	fb = fuse_passthrough_open(file, backing_id, is_64bit);
	if (IS_ERR(fb))
		return PTR_ERR(fb);

	/* First passthrough file open denies caching inode io mode */
	err = fuse_file_uncached_io_open(inode, ff, fb);
	if (!err)
		return 0;

	fuse_passthrough_release(ff, fb);
	fuse_backing_put(fb);

	return err;
}

/* Request access to submit new io to inode via open file */
int fuse_file_io_open(struct file *file, struct inode *inode)
{
	struct fuse_file *ff = file->private_data;
	struct fuse_inode *fi = get_fuse_inode(inode);
	int err;

	/*
	 * io modes are not relevant with virtiofs DAX and with server that does not
	 * implement open.
	 */
	if (FUSE_IS_VDAX(inode) || !ff->args)
		return 0;

	/*
	 * Server is expected to use FOPEN_PASSTHROUGH for all opens of an inode
	 * which is already open for passthrough.
	 */
	err = -EINVAL;
	if (fuse_inode_backing(fi) && !(ff->open_flags & FOPEN_PASSTHROUGH))
		return fuse_EIO("FOPEN_PASSTHROUGH expected");

	/*
	 * FOPEN_PARALLEL_DIRECT_WRITES requires FOPEN_DIRECT_IO.
	 */
	if (!(ff->open_flags & FOPEN_DIRECT_IO))
		ff->open_flags &= ~FOPEN_PARALLEL_DIRECT_WRITES;

	/*
	 * First passthrough file open denies caching inode io mode.
	 * First caching file open enters caching inode io mode.
	 *
	 * Note that if user opens a file open with O_DIRECT, but server did
	 * not specify FOPEN_DIRECT_IO, a later fcntl() could remove O_DIRECT,
	 * so we put the inode in caching mode to prevent parallel dio.
	 */
	if ((ff->open_flags & FOPEN_DIRECT_IO) &&
	    !(ff->open_flags & FOPEN_PASSTHROUGH))
		return 0;

	if (ff->open_flags & FOPEN_PASSTHROUGH)
		err = fuse_file_passthrough_open(inode, file);
	else
		err = fuse_file_cached_io_open(inode, ff);

	return err;
}

/* No more pending io and no new io possible to inode via open/mmapped file */
void fuse_file_io_release(struct fuse_file *ff, struct inode *inode)
{
	struct fuse_inode *fi = get_fuse_inode(inode);

	/*
	 * Last passthrough file close allows caching inode io mode.
	 * Last caching file close exits caching inode io mode.
	 */
	switch (ff->iomode) {
	case IOM_NONE:
		/* Nothing to do */
		break;
	case IOM_UNCACHED:
		fuse_file_uncached_io_release(ff, fi);
		break;
	case IOM_CACHED:
		fuse_file_cached_io_release(ff, fi);
		break;
	}
}
