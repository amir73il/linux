/*
 *  linux/fs/next3/buffer.c
 *
 *  from
 *
 *  linux/fs/buffer.c
 *
 *  Copyright (C) 1991, 1992, 2002  Linus Torvalds
 */

/*
 * Start bdflush() with kernel_thread not syscall - Paul Gortmaker, 12/95
 *
 * Removed a lot of unnecessary code and simplified things now that
 * the buffer cache isn't our primary cache - Andrew Tridgell 12/96
 *
 * Speed up hash, lru, and free list operations.  Use gfp() for allocating
 * hash table, use SLAB cache for buffer heads. SMP threading.  -DaveM
 *
 * Added 32k buffer block sizes - these are required older ARM systems. - RMK
 *
 * async buffer flushing, 1999 Andrea Arcangeli <andrea@suse.de>
 *
 * Tracked buffer read for Next3, Amir Goldstein <amir73il@users.sf.net>, 2008
 */

#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/percpu.h>
#include <linux/slab.h>
#include <linux/capability.h>
#include <linux/blkdev.h>
#include <linux/file.h>
#include <linux/quotaops.h>
#include <linux/highmem.h>
#include <linux/module.h>
#include <linux/writeback.h>
#include <linux/hash.h>
#include <linux/suspend.h>
#include <linux/buffer_head.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/bio.h>
#include <linux/notifier.h>
#include <linux/cpu.h>
#include <linux/bitops.h>
#include <linux/mpage.h>
#include <linux/bit_spinlock.h>
#include "snapshot.h"

static int quiet_error(struct buffer_head *bh)
{
	if (printk_ratelimit())
		return 0;
	return 1;
}


static void buffer_io_error(struct buffer_head *bh)
{
	char b[BDEVNAME_SIZE];
	printk(KERN_ERR "Buffer I/O error on device %s, logical block %Lu\n",
			bdevname(bh->b_bdev, b),
			(unsigned long long)bh->b_blocknr);
}

#ifdef CONFIG_NEXT3_FS_SNAPSHOT_RACE_READ
/*
 * Tracked read functions.
 * When reading through a next3 snapshot file hole to a block device block,
 * all writes to this block need to wait for completion of the async read.
 * next3_snapshot_readpage() always calls next3_read_full_page() to attach
 * a buffer head to the page and be aware of tracked reads.
 * next3_snapshot_get_block() calls start_buffer_tracked_read() to mark both
 * snapshot page buffer and block device page buffer.
 * next3_snapshot_get_block() calls cancel_buffer_tracked_read() if snapshot
 * doesn't need to read through to the block device.
 * next3_read_full_page() calls submit_buffer_tracked_read() to submit a
 * tracked async read.
 * end_buffer_async_read() calls end_buffer_tracked_read() to complete the
 * tracked read operation.
 * The only lock needed in all these functions is PageLock on the snapshot page,
 * which is guarantied in readpage() and verified in next3_read_full_page().
 * The block device page buffer doesn't need any lock because the operations
 * {get|put}_bh_tracked_reader() are atomic.
 */

#ifdef CONFIG_NEXT3_FS_DEBUG
/*
 * trace maximum value of b_count on all fs buffers to see if we are
 * overflowing to upper word (tracked readers count)
 */
void __next3_trace_bh_count(const char *fn, struct buffer_head *bh)
{
	static sector_t blocknr = 0;
	static int maxcount = 0;
	static int maxbit = 1;
	static int maxorder = 0;
	int count = atomic_read(&bh->b_count) & 0x0000ffff;

	BUG_ON(count < 0);
	if (count <= maxcount)
		return;
	maxcount = count;
	blocknr = bh->b_blocknr;

	if (count <= maxbit)
		return;
	while (count > maxbit) {
		maxbit <<= 1;
		maxorder++;
	}

	snapshot_debug(maxorder > 7 ? 1 : 2,
			"%s: buffer refcount maxorder = %d, "
			"maxcount = 0x%08x, block = [%lu/%lu].\n",
			fn, maxorder, maxcount,
			SNAPSHOT_BLOCK_TUPLE(blocknr));
}
#endif

/*
 * start buffer tracked read
 * called from inside get_block()
 * get tracked reader ref count on buffer cache entry
 * and set buffer tracked read flag
 */
int start_buffer_tracked_read(struct buffer_head *bh)
{
	struct buffer_head *bdev_bh;

	BUG_ON(buffer_tracked_read(bh));
	BUG_ON(!buffer_mapped(bh));

	/* grab the buffer cache entry */
	bdev_bh = __getblk(bh->b_bdev, bh->b_blocknr, bh->b_size);
	if (!bdev_bh)
		return -EIO;

	BUG_ON(bdev_bh == bh);
	next3_trace_bh_count(bdev_bh);
	set_buffer_tracked_read(bh);
	get_bh_tracked_reader(bdev_bh);
	put_bh(bdev_bh);
	return 0;
}

/*
 * cancel buffer tracked read
 * called for tracked read that was started but was not submitted
 * put tracked reader ref count on buffer cache entry
 * and clear buffer tracked read flag
 */
void cancel_buffer_tracked_read(struct buffer_head *bh)
{
	struct buffer_head *bdev_bh;

	BUG_ON(!buffer_tracked_read(bh));
	BUG_ON(!buffer_mapped(bh));

	/* try to grab the buffer cache entry */
	bdev_bh = __find_get_block(bh->b_bdev, bh->b_blocknr, bh->b_size);
	BUG_ON(!bdev_bh || bdev_bh == bh);
	next3_trace_bh_count(bdev_bh);
	clear_buffer_tracked_read(bh);
	clear_buffer_mapped(bh);
	put_bh_tracked_reader(bdev_bh);
	put_bh(bdev_bh);
}

/*
 * submit buffer tracked read
 * save a reference to buffer cache entry and submit I/O
 */
static int submit_buffer_tracked_read(struct buffer_head *bh)
{
	struct buffer_head *bdev_bh;
	BUG_ON(!buffer_tracked_read(bh));
	BUG_ON(!buffer_mapped(bh));
	/* tracked read doesn't work with multiple buffers per page */
	BUG_ON(bh->b_this_page != bh);

	/*
	 * Try to grab the buffer cache entry before submitting async read
	 * because we cannot call blocking function __find_get_block()
	 * in interrupt context inside end_buffer_tracked_read().
	 */
	bdev_bh = __find_get_block(bh->b_bdev, bh->b_blocknr, bh->b_size);
	BUG_ON(!bdev_bh || bdev_bh == bh);
	next3_trace_bh_count(bdev_bh);
	/* override page buffers list with reference to buffer cache entry */
	bh->b_this_page = bdev_bh;
	submit_bh(READ, bh);
	return 0;
}

/*
 * end buffer tracked read
 * complete submitted tracked read
 */
static void end_buffer_tracked_read(struct buffer_head *bh)
{
	struct buffer_head *bdev_bh = bh->b_this_page;

	BUG_ON(!buffer_tracked_read(bh));
	BUG_ON(!bdev_bh || bdev_bh == bh);
	bh->b_this_page = bh;
	/*
	 * clear the buffer mapping to make sure
	 * that get_block() will always be called
	 */
	clear_buffer_mapped(bh);
	clear_buffer_tracked_read(bh);
	put_bh_tracked_reader(bdev_bh);
	put_bh(bdev_bh);
}

#endif
/*
 * I/O completion handler for next3_read_full_page() - pages
 * which come unlocked at the end of I/O.
 */
static void end_buffer_async_read(struct buffer_head *bh, int uptodate)
{
	unsigned long flags;
	struct buffer_head *first;
	struct buffer_head *tmp;
	struct page *page;
	int page_uptodate = 1;

	BUG_ON(!buffer_async_read(bh));

#ifdef CONFIG_NEXT3_FS_SNAPSHOT_RACE_READ
	if (buffer_tracked_read(bh))
		end_buffer_tracked_read(bh);

#endif
	page = bh->b_page;
	if (uptodate) {
		set_buffer_uptodate(bh);
	} else {
		clear_buffer_uptodate(bh);
		if (!quiet_error(bh))
			buffer_io_error(bh);
		SetPageError(page);
	}

	/*
	 * Be _very_ careful from here on. Bad things can happen if
	 * two buffer heads end IO at almost the same time and both
	 * decide that the page is now completely done.
	 */
	first = page_buffers(page);
	local_irq_save(flags);
	bit_spin_lock(BH_Uptodate_Lock, &first->b_state);
	clear_buffer_async_read(bh);
	unlock_buffer(bh);
	tmp = bh;
	do {
		if (!buffer_uptodate(tmp))
			page_uptodate = 0;
		if (buffer_async_read(tmp)) {
			BUG_ON(!buffer_locked(tmp));
			goto still_busy;
		}
		tmp = tmp->b_this_page;
	} while (tmp != bh);
	bit_spin_unlock(BH_Uptodate_Lock, &first->b_state);
	local_irq_restore(flags);

	/*
	 * If none of the buffers had errors and they are all
	 * uptodate then we can set the page uptodate.
	 */
	if (page_uptodate && !PageError(page))
		SetPageUptodate(page);
	unlock_page(page);
	return;

still_busy:
	bit_spin_unlock(BH_Uptodate_Lock, &first->b_state);
	local_irq_restore(flags);
	return;
}

/*
 * If a page's buffers are under async readin (end_buffer_async_read
 * completion) then there is a possibility that another thread of
 * control could lock one of the buffers after it has completed
 * but while some of the other buffers have not completed.  This
 * locked buffer would confuse end_buffer_async_read() into not unlocking
 * the page.  So the absence of BH_Async_Read tells end_buffer_async_read()
 * that this buffer is not under async I/O.
 *
 * The page comes unlocked when it has no locked buffer_async buffers
 * left.
 *
 * PageLocked prevents anyone starting new async I/O reads any of
 * the buffers.
 *
 * PageWriteback is used to prevent simultaneous writeout of the same
 * page.
 *
 * PageLocked prevents anyone from starting writeback of a page which is
 * under read I/O (PageWriteback is only ever set against a locked page).
 */
static void mark_buffer_async_read(struct buffer_head *bh)
{
	bh->b_end_io = end_buffer_async_read;
	set_buffer_async_read(bh);
}

/*
 * Generic "read page" function for block devices that have the normal
 * get_block functionality. This is most of the block device filesystems.
 * Reads the page asynchronously --- the unlock_buffer() and
 * set/clear_buffer_uptodate() functions propagate buffer state into the
 * page struct once IO has completed.
 */
int next3_read_full_page(struct page *page, get_block_t *get_block)
{
	struct inode *inode = page->mapping->host;
	sector_t iblock, lblock;
	struct buffer_head *bh, *head, *arr[MAX_BUF_PER_PAGE];
	unsigned int blocksize;
	int nr, i;
	int fully_mapped = 1;

	BUG_ON(!PageLocked(page));
	blocksize = 1 << inode->i_blkbits;
	if (!page_has_buffers(page))
		create_empty_buffers(page, blocksize, 0);
	head = page_buffers(page);

	iblock = (sector_t)page->index << (PAGE_CACHE_SHIFT - inode->i_blkbits);
	lblock = (i_size_read(inode)+blocksize-1) >> inode->i_blkbits;
	bh = head;
	nr = 0;
	i = 0;

	do {
		if (buffer_uptodate(bh))
			continue;

		if (!buffer_mapped(bh)) {
			int err = 0;

			fully_mapped = 0;
			if (iblock < lblock) {
				WARN_ON(bh->b_size != blocksize);
				err = get_block(inode, iblock, bh, 0);
				if (err)
					SetPageError(page);
			}
			if (!buffer_mapped(bh)) {
				zero_user(page, i * blocksize, blocksize);
				if (!err)
					set_buffer_uptodate(bh);
				continue;
			}
			/*
			 * get_block() might have updated the buffer
			 * synchronously
			 */
			if (buffer_uptodate(bh))
				continue;
		}
		arr[nr++] = bh;
	} while (i++, iblock++, (bh = bh->b_this_page) != head);

	if (fully_mapped)
		SetPageMappedToDisk(page);

	if (!nr) {
		/*
		 * All buffers are uptodate - we can set the page uptodate
		 * as well. But not if get_block() returned an error.
		 */
		if (!PageError(page))
			SetPageUptodate(page);
		unlock_page(page);
		return 0;
	}

	/* Stage two: lock the buffers */
	for (i = 0; i < nr; i++) {
		bh = arr[i];
		lock_buffer(bh);
		mark_buffer_async_read(bh);
	}

	/*
	 * Stage 3: start the IO.  Check for uptodateness
	 * inside the buffer lock in case another process reading
	 * the underlying blockdev brought it uptodate (the sct fix).
	 */
	for (i = 0; i < nr; i++) {
		bh = arr[i];
#ifdef CONFIG_NEXT3_FS_SNAPSHOT_RACE_READ
		if (buffer_tracked_read(bh))
			return submit_buffer_tracked_read(bh);
#endif
		if (buffer_uptodate(bh))
			end_buffer_async_read(bh, 1);
		else
			submit_bh(READ, bh);
	}
	return 0;
}
