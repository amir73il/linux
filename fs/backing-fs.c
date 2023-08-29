// SPDX-License-Identifier: GPL-2.0-only
/*
 * Common helpers for backing filesystem operations.
 * Forked from fs/overlayfs/file.c.
 *
 * Copyright (C) 2017 Red Hat, Inc.
 * Copyright (C) 2023 CTERA Networks.
 */

#include <linux/backing-fs.h>

struct backing_aio_req {
	struct kiocb iocb;
	refcount_t ref;
	struct kiocb *orig_iocb;
	void (*cleanup)(struct kiocb *, long);
};

static struct kmem_cache *backing_aio_req_cachep;

#define BACKING_IOCB_MASK \
	(IOCB_NOWAIT | IOCB_HIPRI | IOCB_DSYNC | IOCB_SYNC | IOCB_APPEND)

static rwf_t iocb_to_rw_flags(int flags)
{
	return (__force rwf_t)(flags & BACKING_IOCB_MASK);
}

static void backing_aio_put(struct backing_aio_req *aio_req)
{
	if (refcount_dec_and_test(&aio_req->ref)) {
		fput(aio_req->iocb.ki_filp);
		kmem_cache_free(backing_aio_req_cachep, aio_req);
	}
}

/* Completion for submitted/failed async rw io */
static void backing_aio_cleanup(struct backing_aio_req *aio_req, long res)
{
	struct kiocb *iocb = &aio_req->iocb;
	struct kiocb *orig_iocb = aio_req->orig_iocb;

	if (iocb->ki_flags & IOCB_WRITE)
		kiocb_end_write(iocb);

	orig_iocb->ki_pos = iocb->ki_pos;
	if (aio_req->cleanup)
		aio_req->cleanup(orig_iocb, res);

	backing_aio_put(aio_req);
}

/* Completion for submitted async rw io */
static void backing_aio_rw_complete(struct kiocb *iocb, long res)
{
	struct backing_aio_req *aio_req = container_of(iocb,
					       struct backing_aio_req, iocb);
	struct kiocb *orig_iocb = aio_req->orig_iocb;

	backing_aio_cleanup(aio_req, res);
	orig_iocb->ki_complete(orig_iocb, res);
}


ssize_t backing_file_read_iter(struct file *file, struct iov_iter *iter,
			       struct kiocb *iocb, int flags,
			       void (*cleanup)(struct kiocb *, long))
{
	struct backing_aio_req *aio_req = NULL;
	ssize_t ret;

	if (!iov_iter_count(iter))
		return 0;

	if (iocb->ki_flags & IOCB_DIRECT &&
	    !(file->f_mode & FMODE_CAN_ODIRECT))
		return -EINVAL;

	if (is_sync_kiocb(iocb)) {
		rwf_t rwf = iocb_to_rw_flags(flags);

		ret = vfs_iter_read(file, iter, &iocb->ki_pos, rwf);
		if (cleanup)
			cleanup(iocb, ret);
	} else {
		aio_req = kmem_cache_zalloc(backing_aio_req_cachep, GFP_KERNEL);
		if (!aio_req)
			return -ENOMEM;

		get_file(file);
		aio_req->orig_iocb = iocb;
		aio_req->cleanup = cleanup;
		kiocb_clone(&aio_req->iocb, iocb, file);
		aio_req->iocb.ki_complete = backing_aio_rw_complete;
		refcount_set(&aio_req->ref, 2);
		ret = vfs_iocb_iter_read(file, &aio_req->iocb, iter);
		backing_aio_put(aio_req);
		if (ret != -EIOCBQUEUED)
			backing_aio_cleanup(aio_req, ret);
	}

	return ret;
}
EXPORT_SYMBOL_GPL(backing_file_read_iter);

ssize_t backing_file_write_iter(struct file *file, struct iov_iter *iter,
				struct kiocb *iocb, int flags,
				void (*cleanup)(struct kiocb *, long))
{
	ssize_t ret;

	if (!iov_iter_count(iter))
		return 0;

	if (iocb->ki_flags & IOCB_DIRECT &&
	    !(file->f_mode & FMODE_CAN_ODIRECT))
		return -EINVAL;

	if (is_sync_kiocb(iocb)) {
		rwf_t rwf = iocb_to_rw_flags(flags);

		file_start_write(file);
		ret = vfs_iter_write(file, iter, &iocb->ki_pos, rwf);
		file_end_write(file);
		if (cleanup)
			cleanup(iocb, ret);
	} else {
		struct backing_aio_req *aio_req;

		aio_req = kmem_cache_zalloc(backing_aio_req_cachep, GFP_KERNEL);
		if (!aio_req)
			return -ENOMEM;

		get_file(file);
		aio_req->orig_iocb = iocb;
		aio_req->cleanup = cleanup;
		kiocb_clone(&aio_req->iocb, iocb, file);
		aio_req->iocb.ki_flags = flags;
		aio_req->iocb.ki_complete = backing_aio_rw_complete;
		refcount_set(&aio_req->ref, 2);
		kiocb_start_write(&aio_req->iocb);
		ret = vfs_iocb_iter_write(file, &aio_req->iocb, iter);
		backing_aio_put(aio_req);
		if (ret != -EIOCBQUEUED)
			backing_aio_cleanup(aio_req, ret);
	}

	return ret;
}
EXPORT_SYMBOL_GPL(backing_file_write_iter);

static int __init backing_fs_init(void)
{
	backing_aio_req_cachep = kmem_cache_create("backing_aio_req",
						   sizeof(struct backing_aio_req),
						   0, SLAB_HWCACHE_ALIGN, NULL);
	if (!backing_aio_req_cachep)
		return -ENOMEM;

	return 0;
}
fs_initcall(backing_fs_init);
