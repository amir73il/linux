/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Common helpers for stackable filesystems and backing files.
 *
 * Copyright (C) 2023 CTERA Networks.
 */

#ifndef _LINUX_BACKING_FILE_H
#define _LINUX_BACKING_FILE_H

#include <linux/file.h>
#include <linux/uio.h>
#include <linux/fs.h>

struct backing_file_ctx {
	const struct cred *cred;
	void (*accessed)(struct file *file);
	void (*end_write)(struct kiocb *iocb, ssize_t);
};

struct file *backing_file_open(const struct file *user_file, int flags,
			       const struct path *real_path,
			       const struct cred *cred);
struct file *backing_tmpfile_open(const struct file *user_file, int flags,
				  const struct path *real_parentpath,
				  umode_t mode, const struct cred *cred);
ssize_t backing_file_read_iter(struct file *file, struct iov_iter *iter,
			       struct kiocb *iocb, int flags,
			       struct backing_file_ctx *ctx);
ssize_t backing_file_write_iter(struct file *file, struct iov_iter *iter,
				struct kiocb *iocb, int flags,
				struct backing_file_ctx *ctx);
ssize_t backing_file_splice_read(struct file *in, struct kiocb *iocb,
				 struct pipe_inode_info *pipe, size_t len,
				 unsigned int flags,
				 struct backing_file_ctx *ctx);
ssize_t backing_file_splice_write(struct pipe_inode_info *pipe,
				  struct file *out, struct kiocb *iocb,
				  size_t len, unsigned int flags,
				  struct backing_file_ctx *ctx);
int backing_file_mmap(struct file *file, struct vm_area_struct *vma,
		      struct backing_file_ctx *ctx);
struct file *backing_file_real(struct file *user_file);

/**
 * file_real - Return the real file hosting the data
 * @file: the file to query
 *
 * If @file is on a stacking filesystem (e.g. overlayfs) whose data is
 * accessed through a backing file, return that backing file.
 * Otherwise return @file itself.
 *
 * The returned file is owned by @file and is valid for as long as the
 * caller holds a reference to @file.
 *
 * The real file is only meant to be used for inspecting and writing
 * back the page cache of the data (e.g. sync_file_range(2), cachestat(2)).
 * It must not be used for operations that require the credentials or the
 * permission checks of the stacking filesystem; those need a dedicated
 * file operation (e.g. ->fadvise()).
 */
static inline struct file *file_real(struct file *file)
{
	if (!IS_ENABLED(CONFIG_FS_STACK) || likely(!file->f_op->f_real))
		return file;

	return backing_file_real(file);
}

#endif /* _LINUX_BACKING_FILE_H */
