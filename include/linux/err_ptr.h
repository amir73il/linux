/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_ERR_PTR_H
#define _LINUX_ERR_PTR_H

#include <linux/err.h>
#include <linux/bug.h>

/**
 * ERR_PTR_SAFE - Create an error pointer, with validation.
 * @error: An error code to encode as an error pointer.
 *
 * Like ERR_PTR(), but validates @error:
 * - For constant @error: fails the build if the value is not a valid errno
 * - For variable @error: warns and converts to -EFAULT if out of range
 *   (zero is allowed, producing NULL).
 *
 * Subsystems may opt in for all ERR_PTR() call sites by adding after includes:
 *   #undef ERR_PTR
 *   #define ERR_PTR(err) ERR_PTR_SAFE(err)
 */
#define ERR_PTR_SAFE(error) ({					\
	void *__e = (void *)(long)(error);			\
	BUILD_BUG_ON(statically_true(!IS_ERR_VALUE(__e)));	\
	if (WARN_ON(!IS_ERR_OR_NULL(__e)))			\
		__e = (void *)(long)-EFAULT;			\
	__e;							\
})

#endif /* _LINUX_ERR_PTR_H */
