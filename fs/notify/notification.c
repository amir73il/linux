// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *  Copyright (C) 2008 Red Hat, Inc., Eric Paris <eparis@redhat.com>
 */

/*
 * Basic idea behind the notification queue: An fsnotify group (like inotify)
 * sends the userspace notification about events asynchronously some time after
 * the event happened.  When inotify gets an event it will need to add that
 * event to the group notify queue.  Since a single event might need to be on
 * multiple group's notification queues we can't add the event directly to each
 * queue and instead add a small "event_holder" to each queue.  This event_holder
 * has a pointer back to the original event.  Since the majority of events are
 * going to end up on one, and only one, notification queue we embed one
 * event_holder into each event.  This means we have a single allocation instead
 * of always needing two.  If the embedded event_holder is already in use by
 * another group a new event_holder (from fsnotify_event_holder_cachep) will be
 * allocated and used.
 */

#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

#include <linux/atomic.h>

#include <linux/fsnotify_backend.h>
#include "fsnotify.h"

static atomic_t fsnotify_sync_cookie = ATOMIC_INIT(0);

/**
 * fsnotify_get_cookie - return a unique cookie for use in synchronizing events.
 * Called from fsnotify_move, which is inlined into filesystem modules.
 */
u32 fsnotify_get_cookie(void)
{
	return atomic_inc_return(&fsnotify_sync_cookie);
}
EXPORT_SYMBOL_GPL(fsnotify_get_cookie);

void fsnotify_destroy_event(struct fsnotify_group *group,
			    struct fsnotify_event *event)
{
	/* Overflow events are per-group and we don't want to free them */
	if (!event || event == group->overflow_event)
		return;
	/*
	 * If the event is still queued, we have a problem... Do an unreliable
	 * lockless check first to avoid locking in the common case. The
	 * locking may be necessary for permission events which got removed
	 * from the list by a different CPU than the one freeing the event.
	 */
	if (!list_empty(&event->list)) {
		spin_lock(&group->notification_lock);
		WARN_ON(!list_empty(&event->list));
		spin_unlock(&group->notification_lock);
	}
	group->ops->free_event(event);
}

/* Check and fix inconsistencies in hashed queue */
static void fsnotify_queue_check(struct fsnotify_group *group)
{
#ifdef FSNOTIFY_HASHED_QUEUE
	struct list_head *list;
	int i, nbuckets = 0;
	bool first_empty, last_empty;

	assert_spin_locked(&group->notification_lock);

	pr_debug("%s: group=%p events: num=%u max=%u buckets: first=%u last=%u max=%u\n",
		 __func__, group, group->num_events, group->max_events,
		 group->first_bucket, group->last_bucket, group->max_bucket);

	if (fsnotify_notify_queue_is_empty(group))
		return;

	first_empty = list_empty(&group->notification_list[group->first_bucket]);
	last_empty = list_empty(&group->notification_list[group->last_bucket]);

	list = &group->notification_list[0];
	for (i = 0; i <= group->max_bucket; i++, list++) {
		if (list_empty(list))
			continue;
		if (nbuckets++)
			continue;
		if (first_empty)
			group->first_bucket = i;
		if (last_empty)
			group->last_bucket = i;
	}

	pr_debug("%s: %u non-empty buckets\n", __func__, nbuckets);

	/* All buckets are empty, but non-zero num_events? */
	if (WARN_ON_ONCE(!nbuckets && group->num_events))
		group->num_events = 0;
#endif
}

/*
 * Add an event to the group notification queue (no merge and no failure).
 */
static void fsnotify_queue_event(struct fsnotify_group *group,
				struct fsnotify_event *event)
{
	/* Choose list to add event to */
	unsigned int b = fsnotify_event_bucket(group, event);
	struct list_head *list = &group->notification_list[b];

	assert_spin_locked(&group->notification_lock);

	pr_debug("%s: group=%p event=%p bucket=%u\n", __func__, group, event, b);

	/*
	 * TODO: set next_bucket of last event.
	 */
	group->last_bucket = b;
	if (!group->num_events)
		group->first_bucket = b;
	group->num_events++;
	list_add_tail(&event->list, list);
}

/*
 * Try to Add an event to the group notification queue.
 * The group can later pull this event off the queue to deal with.
 * The function returns 0 if the event was added to a queue,
 * 1 if the event was merged with some other queued event,
 * 2 if the event was not queued - either the queue of events has overflown
 * or the group is shutting down.
 */
int fsnotify_add_event(struct fsnotify_group *group,
		       struct fsnotify_event *event,
		       int (*merge)(struct list_head *,
				    struct fsnotify_event *))
{
	int ret = 0;
	struct list_head *list;

	pr_debug("%s: group=%p event=%p\n", __func__, group, event);

	spin_lock(&group->notification_lock);

	if (group->shutdown) {
		spin_unlock(&group->notification_lock);
		return 2;
	}

	if (event == group->overflow_event ||
	    group->num_events >= group->max_events) {
		ret = 2;
		/* Queue overflow event only if it isn't already queued */
		if (!list_empty(&group->overflow_event->list)) {
			spin_unlock(&group->notification_lock);
			return ret;
		}
		event = group->overflow_event;
		goto queue;
	}

	list = fsnotify_event_notification_list(group, event);
	if (!list_empty(list) && merge) {
		ret = merge(list, event);
		if (ret) {
			spin_unlock(&group->notification_lock);
			return ret;
		}
	}

queue:
	fsnotify_queue_event(group, event);
	spin_unlock(&group->notification_lock);

	wake_up(&group->notification_waitq);
	kill_fasync(&group->fsn_fa, SIGIO, POLL_IN);
	return ret;
}

void fsnotify_remove_queued_event(struct fsnotify_group *group,
				  struct fsnotify_event *event)
{
	assert_spin_locked(&group->notification_lock);
	/*
	 * We need to init list head for the case of overflow event so that
	 * check in fsnotify_add_event() works
	 */
	list_del_init(&event->list);
	group->num_events--;
}

/* Return the notification list of the first event */
struct list_head *fsnotify_first_notification_list(struct fsnotify_group *group)
{
	struct list_head *list;

	assert_spin_locked(&group->notification_lock);

	if (fsnotify_notify_queue_is_empty(group))
		return NULL;

	list = &group->notification_list[group->first_bucket];
	if (likely(!list_empty(list)))
		return list;

	/*
	 * Look for any non-empty bucket.
	 */
	fsnotify_queue_check(group);
	list = &group->notification_list[group->first_bucket];

	return list_empty(list) ? NULL : list;
}

/*
 * Remove and return the first event from the notification list.  It is the
 * responsibility of the caller to destroy the obtained event
 */
struct fsnotify_event *fsnotify_remove_first_event(struct fsnotify_group *group)
{
	struct fsnotify_event *event;
	struct list_head *list;

	assert_spin_locked(&group->notification_lock);

	list = fsnotify_first_notification_list(group);
	if (!list)
		return NULL;

	pr_debug("%s: group=%p bucket=%u\n", __func__, group, group->first_bucket);

	event = list_first_entry(list, struct fsnotify_event, list);
	fsnotify_remove_queued_event(group, event);
	/*
	 * TODO: update group->first_bucket to next_bucket in first event.
	 */
	return event;
}

/*
 * This will not remove the event, that must be done with
 * fsnotify_remove_first_event()
 */
struct fsnotify_event *fsnotify_peek_first_event(struct fsnotify_group *group)
{
	struct list_head *list;

	assert_spin_locked(&group->notification_lock);

	list = fsnotify_first_notification_list(group);
	if (!list)
		return NULL;

	return list_first_entry(list, struct fsnotify_event, list);
}

/*
 * Called when a group is being torn down to clean up any outstanding
 * event notifications.
 */
void fsnotify_flush_notify(struct fsnotify_group *group)
{
	struct fsnotify_event *event;

	spin_lock(&group->notification_lock);
	while (!fsnotify_notify_queue_is_empty(group)) {
		event = fsnotify_remove_first_event(group);
		spin_unlock(&group->notification_lock);
		fsnotify_destroy_event(group, event);
		spin_lock(&group->notification_lock);
	}
	spin_unlock(&group->notification_lock);
}
