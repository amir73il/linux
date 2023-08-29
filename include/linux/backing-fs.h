// SPDX-License-Identifier: GPL-2.0-only
/*
 * Common helpers for backing filesystem operations.
 *
 * Copyright (C) 2023 CTERA Networks.
 */

#ifndef _LINUX_BACKING_FS_H
#define _LINUX_BACKING_FS_H

#include <linux/file.h>
#include <linux/uio.h>
#include <linux/fs.h>

ssize_t backing_file_read_iter(struct file *file, struct iov_iter *iter,
			       struct kiocb *iocb, int flags,
			       void (*cleanup)(struct kiocb *, long));
ssize_t backing_file_write_iter(struct file *file, struct iov_iter *iter,
				struct kiocb *iocb, int flags,
				void (*cleanup)(struct kiocb *, long));

#endif	/* _LINUX_BACKING_FS_H */
