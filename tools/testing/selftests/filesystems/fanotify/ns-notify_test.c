// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025

#define _GNU_SOURCE

// Needed for linux/fanotify.h
typedef struct {
	int	val[2];
} __kernel_fsid_t;
#define __kernel_fsid_t __kernel_fsid_t

#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/fanotify.h>
#include <sys/wait.h>
#include <unistd.h>

#include "kselftest_harness.h"
#include "../utils.h"

#include <linux/fanotify.h>

/*
 * Retrieve the ns_id of a namespace fd via name_to_handle_at().
 * nsfs encodes { ns_id(u64), ns_type(u32), ns_inum(u32) } in f_handle.
 */
static uint64_t get_ns_id(int fd)
{
	struct {
		struct file_handle fh;
		uint64_t ns_id;
		uint32_t ns_type;
		uint32_t ns_inum;
	} h = { .fh.handle_bytes = sizeof(uint64_t) + sizeof(uint32_t) * 2 };
	int mnt_id;

	if (name_to_handle_at(fd, "", &h.fh, &mnt_id, AT_EMPTY_PATH))
		return 0;
	return h.ns_id;
}

static void read_ns_event_fd(struct __test_metadata *const _metadata,
			     int fd, char *buf, size_t buf_size,
			     uint64_t expect_mask,
			     uint64_t *self_nsid_out, uint64_t *owner_nsid_out)
{
	struct fanotify_event_metadata *meta;
	struct fanotify_event_info_ns *info;
	ssize_t len;

	len = read(fd, buf, buf_size);
	ASSERT_GT(len, 0);

	meta = (struct fanotify_event_metadata *)buf;
	ASSERT_TRUE(FAN_EVENT_OK(meta, len));
	ASSERT_EQ(meta->mask, expect_mask);
	ASSERT_EQ(meta->fd, FAN_NOFD);
	ASSERT_EQ(meta->event_len,
		  sizeof(*meta) + sizeof(struct fanotify_event_info_ns));

	info = (struct fanotify_event_info_ns *)(meta + 1);
	ASSERT_EQ(info->hdr.info_type, FAN_EVENT_INFO_TYPE_NS);
	ASSERT_EQ(info->hdr.len, sizeof(*info));

	*self_nsid_out  = info->self_nsid;
	*owner_nsid_out = info->owner_nsid;
}

/* =========================================================================
 * Outer tests: watch init_user_ns from root context (no setup_userns).
 * ========================================================================= */

/*
 * Root-only: watch init_user_ns, fork a child that creates a user namespace
 * owned by init_user_ns, verify FAN_CREATE, let the child exit, verify
 * FAN_DELETE.  The watched namespace is created and destroyed entirely within
 * the test body so both events are observable.
 */
TEST(outer_create_delete_userns)
{
	int fan_fd, ns_fd;
	int pipefd[2];
	pid_t pid;
	uint64_t ns_nsid, create_self, create_owner;
	uint64_t delete_self, delete_owner;
	char buf[256];
	char c;

	if (geteuid() != 0)
		SKIP(return, "requires root");

	ns_fd = open("/proc/self/ns/user", O_RDONLY);
	ASSERT_GE(ns_fd, 0);

	ns_nsid = get_ns_id(ns_fd);
	ASSERT_NE(ns_nsid, 0);

	fan_fd = fanotify_init(FAN_REPORT_NSID, 0);
	ASSERT_GE(fan_fd, 0);

	errno = 0;
	ASSERT_EQ(fanotify_mark(fan_fd, FAN_MARK_ADD | FAN_MARK_USERNS,
				FAN_NS_CREATE | FAN_NS_DELETE, ns_fd, NULL), 0)
		TH_LOG("fanotify_mark errno=%d (%s)", errno, strerror(errno));

	ASSERT_EQ(pipe(pipefd), 0);

	pid = fork();
	ASSERT_GE(pid, 0);

	if (pid == 0) {
		close(pipefd[0]);
		if (unshare(CLONE_NEWUSER))
			_exit(1);
		if (write(pipefd[1], "r", 1) < 0)
			_exit(1);
		close(pipefd[1]);
		pause();
		_exit(0);
	}

	close(pipefd[1]);
	ASSERT_EQ(read(pipefd[0], &c, 1), 1);
	close(pipefd[0]);

	/* --- FAN_NS_CREATE: new user namespace owned by init_user_ns --- */
	read_ns_event_fd(_metadata, fan_fd, buf, sizeof(buf),
			 FAN_NS_CREATE, &create_self, &create_owner);
	ASSERT_NE(create_self, 0);
	ASSERT_EQ(create_owner, ns_nsid);

	/* Let child exit, deactivating its user namespace */
	kill(pid, SIGTERM);
	waitpid(pid, NULL, 0);

	/* --- FAN_NS_DELETE --- */
	read_ns_event_fd(_metadata, fan_fd, buf, sizeof(buf),
			 FAN_NS_DELETE, &delete_self, &delete_owner);
	ASSERT_EQ(delete_self, create_self);
	ASSERT_EQ(delete_owner, ns_nsid);

	close(fan_fd);
	close(ns_fd);
}

/* =========================================================================
 * Inner tests: watch a child userns from within it (via setup_userns).
 * ========================================================================= */

FIXTURE(userns_notify) {
	int fan_fd;
	int userns_fd;
	int outer_ns_fd;	/* init_user_ns fd, captured before setup_userns() */
	uint64_t userns_nsid;
	char buf[256];
};

FIXTURE_SETUP(userns_notify)
{
	int ret;

	/* Capture the outer user namespace fd before setup_userns() */
	self->outer_ns_fd = open("/proc/self/ns/user", O_RDONLY);
	ASSERT_GE(self->outer_ns_fd, 0);

	ret = setup_userns();
	ASSERT_EQ(ret, 0);

	self->userns_fd = open("/proc/self/ns/user", O_RDONLY);
	ASSERT_GE(self->userns_fd, 0);

	self->userns_nsid = get_ns_id(self->userns_fd);
	ASSERT_NE(self->userns_nsid, 0);

	self->fan_fd = fanotify_init(FAN_REPORT_NSID, 0);
	ASSERT_GE(self->fan_fd, 0);

	errno = 0;
	ret = fanotify_mark(self->fan_fd, FAN_MARK_ADD | FAN_MARK_USERNS,
			    FAN_NS_CREATE | FAN_NS_DELETE,
			    self->userns_fd, NULL);
	ASSERT_EQ(ret, 0)
		TH_LOG("fanotify_mark errno=%d (%s)", errno, strerror(errno));
}

FIXTURE_TEARDOWN(userns_notify)
{
	close(self->fan_fd);
	close(self->userns_fd);
	close(self->outer_ns_fd);
}

static void read_ns_event(struct __test_metadata *const _metadata,
			  FIXTURE_DATA(userns_notify) *self,
			  uint64_t expect_mask,
			  uint64_t *self_nsid_out, uint64_t *owner_nsid_out)
{
	read_ns_event_fd(_metadata, self->fan_fd, self->buf, sizeof(self->buf),
			 expect_mask, self_nsid_out, owner_nsid_out);
}

/*
 * Create a UTS namespace inside the watched user namespace, verify
 * FAN_CREATE, then let the child exit and verify FAN_DELETE.
 * Cross-check self_nsid against the actual ns_id obtained via
 * name_to_handle_at() on the child's /proc/pid/ns/uts.
 */
TEST_F(userns_notify, inner_create_delete_uts)
{
	int pipefd[2];
	pid_t pid;
	uint64_t create_self, create_owner;
	uint64_t delete_self, delete_owner;
	char c;

	ASSERT_EQ(pipe(pipefd), 0);

	pid = fork();
	ASSERT_GE(pid, 0);

	if (pid == 0) {
		close(pipefd[0]);
		if (unshare(CLONE_NEWUTS))
			_exit(1);
		if (write(pipefd[1], "r", 1) < 0)
			_exit(1);
		close(pipefd[1]);
		pause();
		_exit(0);
	}

	close(pipefd[1]);
	ASSERT_EQ(read(pipefd[0], &c, 1), 1);
	close(pipefd[0]);

	/* --- FAN_NS_CREATE --- */
	read_ns_event(_metadata, self, FAN_NS_CREATE, &create_self, &create_owner);
	ASSERT_NE(create_self, 0);
	ASSERT_EQ(create_owner, self->userns_nsid);

	/* Cross-check self_nsid against the child's actual UTS ns_id */
	char path[64];
	int ns_fd;
	uint64_t uts_nsid;

	snprintf(path, sizeof(path), "/proc/%d/ns/uts", pid);
	ns_fd = open(path, O_RDONLY);
	ASSERT_GE(ns_fd, 0);
	uts_nsid = get_ns_id(ns_fd);
	close(ns_fd);
	ASSERT_EQ(uts_nsid, create_self);

	kill(pid, SIGTERM);
	waitpid(pid, NULL, 0);

	/* --- FAN_NS_DELETE --- */
	read_ns_event(_metadata, self, FAN_NS_DELETE, &delete_self, &delete_owner);
	ASSERT_EQ(delete_self, create_self);
	ASSERT_EQ(delete_owner, self->userns_nsid);
}

/*
 * Same as inner_create_delete_uts but the namespace fd is never opened, so
 * the stashed nsfs dentry/inode is never populated.  Verifies that FAN_CREATE
 * and FAN_DELETE are still delivered and carry a consistent self_nsid.
 */
TEST_F(userns_notify, inner_create_delete_uts_no_open)
{
	int pipefd[2];
	pid_t pid;
	uint64_t create_self, create_owner;
	uint64_t delete_self, delete_owner;
	char c;

	ASSERT_EQ(pipe(pipefd), 0);

	pid = fork();
	ASSERT_GE(pid, 0);

	if (pid == 0) {
		close(pipefd[0]);
		if (unshare(CLONE_NEWUTS))
			_exit(1);
		if (write(pipefd[1], "r", 1) < 0)
			_exit(1);
		close(pipefd[1]);
		pause();
		_exit(0);
	}

	close(pipefd[1]);
	ASSERT_EQ(read(pipefd[0], &c, 1), 1);
	close(pipefd[0]);

	/* --- FAN_NS_CREATE (no open of /proc/pid/ns/uts) --- */
	read_ns_event(_metadata, self, FAN_NS_CREATE, &create_self, &create_owner);
	ASSERT_NE(create_self, 0);
	ASSERT_EQ(create_owner, self->userns_nsid);

	kill(pid, SIGTERM);
	waitpid(pid, NULL, 0);

	/* --- FAN_NS_DELETE --- */
	read_ns_event(_metadata, self, FAN_NS_DELETE, &delete_self, &delete_owner);
	ASSERT_EQ(delete_self, create_self);
	ASSERT_EQ(delete_owner, self->userns_nsid);
}

/*
 * Attempt to set a FAN_MARK_USERNS watch on the initial user namespace.
 * Requires CAP_SYS_ADMIN in init_user_ns.  Since FIXTURE_SETUP calls
 * setup_userns(), the process lives in a child user namespace and cannot
 * hold capabilities in init_user_ns, so the call must fail with EPERM
 * regardless of the outer uid.
 */
TEST_F(userns_notify, inner_mark_init_userns_eperm)
{
	int ret;

	ret = fanotify_mark(self->fan_fd, FAN_MARK_ADD | FAN_MARK_USERNS,
			    FAN_NS_CREATE | FAN_NS_DELETE,
			    self->outer_ns_fd, NULL);
	EXPECT_EQ(ret, -1);
	EXPECT_EQ(errno, EPERM);
}

TEST_HARNESS_MAIN
