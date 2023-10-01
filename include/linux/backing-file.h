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

struct file *backing_file_open(const struct path *user_path, int flags,
			       const struct path *real_path,
			       const struct cred *cred);
ssize_t backing_file_read_iter(struct file *file, struct iov_iter *iter,
			       struct kiocb *iocb, int flags,
			       void (*accessed)(struct file *));
ssize_t backing_file_write_iter(struct file *file, struct iov_iter *iter,
				struct kiocb *iocb, int flags,
				void (*modified)(struct file *));

#endif /* _LINUX_BACKING_FILE_H */
