// SPDX-License-Identifier: GPL-2.0
/*
 * FUSE passthrough support.
 *
 * Copyright (c) 2021 Google LLC.
 * Copyright (c) 2023 CTERA Networks.
 */

#include "fuse_i.h"

#include <linux/file.h>

/*
 * Returns passthrough_fh id that can be passed with FOPEN_PASSTHROUGH
 * open response and needs to be released with fuse_passthrough_close().
 */
int fuse_passthrough_open(struct fuse_conn *fc, int backing_fd)
{
	return -EINVAL;
}

int fuse_passthrough_close(struct fuse_conn *fc, int passthrough_fh)
{
	return -EINVAL;
}

int fuse_passthrough_setup(struct fuse_conn *fc, struct fuse_file *ff,
			   struct fuse_open_out *openarg)
{
	return -EINVAL;
}

void fuse_passthrough_put(struct fuse_passthrough *passthrough)
{
	if (passthrough && refcount_dec_and_test(&passthrough->count))
		fuse_passthrough_free(passthrough);
}

void fuse_passthrough_free(struct fuse_passthrough *passthrough)
{
	if (passthrough && passthrough->filp) {
		fput(passthrough->filp);
		passthrough->filp = NULL;
	}
	kfree(passthrough);
}
