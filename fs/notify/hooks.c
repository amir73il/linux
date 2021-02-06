// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 CTERA Networks, Amir Goldstein <amir73il@gmail.com>
 * All Rights Reserved.
 */

#include <linux/lsm_hooks.h>
#include "fsnotify.h"

static int fsnotify_file_open(struct file *file)
{
	return fsnotify_perm(file, MAY_OPEN);
}

static int fsnotify_file_permission(struct file *file, int mask)
{
	return fsnotify_perm(file, mask);
}

static struct security_hook_list fsnotify_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(file_open, fsnotify_file_open),
	LSM_HOOK_INIT(file_permission, fsnotify_file_permission),
};

__init void fsnotify_add_security_hooks(void)
{
	security_add_hooks(fsnotify_hooks, ARRAY_SIZE(fsnotify_hooks),
			   "fsnotify");
}
