/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_FS_IOSTATS_H
#define _LINUX_FS_IOSTATS_H

#include <linux/fs.h>
#include <linux/percpu_counter.h>
#include <linux/slab.h>

/* Similar to task_io_accounting members */
enum {
	SB_IOSTATS_CHARS_RD,	/* bytes read via syscalls */
	SB_IOSTATS_CHARS_WR,	/* bytes written via syscalls */
	SB_IOSTATS_SYSCALLS_RD,	/* # of read syscalls */
	SB_IOSTATS_SYSCALLS_WR,	/* # of write syscalls */
	SB_IOSTATS_COUNTERS_NUM
};

struct sb_iostats {
	time64_t		start_time;
	struct percpu_counter	counter[SB_IOSTATS_COUNTERS_NUM];
};

#ifdef CONFIG_FS_IOSTATS
static inline struct sb_iostats *sb_iostats(struct super_block *sb)
{
	return sb->s_iostats;
}

static inline bool sb_has_iostats(struct super_block *sb)
{
	return !!sb->s_iostats;
}

/* Initialize per-sb I/O stats */
static inline int sb_iostats_init(struct super_block *sb)
{
	int err;

	if (sb->s_iostats)
		return 0;

	sb->s_iostats = kmalloc(sizeof(struct sb_iostats), GFP_KERNEL);
	if (!sb->s_iostats)
		return -ENOMEM;

	err = percpu_counters_init(sb->s_iostats->counter,
				   SB_IOSTATS_COUNTERS_NUM, 0, GFP_KERNEL);
	if (err) {
		kfree(sb->s_iostats);
		sb->s_iostats = NULL;
		return err;
	}

	sb->s_iostats->start_time = ktime_get_seconds();
	return 0;
}

static inline void sb_iostats_destroy(struct super_block *sb)
{
	if (!sb->s_iostats)
		return;

	percpu_counters_destroy(sb->s_iostats->counter,
				SB_IOSTATS_COUNTERS_NUM);
	kfree(sb->s_iostats);
	sb->s_iostats = NULL;
}

static inline void sb_iostats_counter_inc(struct super_block *sb, int id)
{
	if (!sb->s_iostats)
		return;

	percpu_counter_inc_relaxed(&sb->s_iostats->counter[id]);
}

static inline void sb_iostats_counter_add(struct super_block *sb, int id,
					  s64 amt)
{
	if (!sb->s_iostats)
		return;

	percpu_counter_add_relaxed(&sb->s_iostats->counter[id], amt);
}

static inline s64 sb_iostats_counter_read(struct super_block *sb, int id)
{
	if (!sb->s_iostats)
		return 0;

	return percpu_counter_sum_positive(&sb->s_iostats->counter[id]);
}

#else /* !CONFIG_FS_IOSTATS */

static inline struct sb_iostats *sb_iostats(struct super_block *sb)
{
	return NULL;
}

static inline bool sb_has_iostats(struct super_block *sb)
{
	return false;
}

static inline int sb_iostats_init(struct super_block *sb)
{
	return 0;
}

static inline void sb_iostats_destroy(struct super_block *sb)
{
}

static inline void sb_iostats_counter_inc(struct super_block *sb, int id)
{
}

static inline void sb_iostats_counter_add(struct super_block *sb, int id,
					  s64 amt)
{
}

static inline s64 sb_iostats_counter_read(struct super_block *sb, int id)
{
	return 0;
}
#endif

#endif /* _LINUX_FS_IOSTATS_H */
