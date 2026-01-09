/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Common helpers for stackable filesystems and backing files.
 *
 * Copyright (C) 2023 CTERA Networks.
 */

#ifndef _LINUX_BACKING_FILE_H
#define _LINUX_BACKING_FILE_H

#include <linux/file.h>
#include <linux/fs.h>

/*
 * When mmapping a file on a stackable filesystem (e.g., overlayfs), the file
 * stored in ->vm_file is a backing file whose f_inode is on the underlying
 * filesystem.
 *
 * LSM can use file_user_path_file() to store context related to the user path
 * that was opened and mmaped.
 */
struct file *backing_file_user_path_file(struct file *f);

static inline struct file *file_user_path_file(struct file *f)
{
	if (unlikely(f->f_mode & FMODE_BACKING))
		return backing_file_user_path_file(f);
	return f;
}

static inline const struct cred *file_user_cred(const struct file *f)
{
	return file_user_path_file((struct file *)f)->f_cred;
}

struct backing_file_ctx {
	const struct cred *cred;
	void (*accessed)(struct file *file);
	void (*end_write)(struct kiocb *iocb, ssize_t);
};

struct file *backing_file_open(const struct path *user_path,
			       const struct cred *user_cred, int flags,
			       const struct path *real_path,
			       const struct cred *cred);
struct file *backing_tmpfile_open(const struct path *user_path,
				  const struct cred *user_cred, int flags,
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

#endif /* _LINUX_BACKING_FILE_H */
