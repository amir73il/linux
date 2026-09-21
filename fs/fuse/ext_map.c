// SPDX-License-Identifier: GPL-2.0-only

#include "fuse_i.h"
#include <linux/rbtree.h>
#include <linux/pagemap.h>
#include <linux/iomap.h>
#include <linux/dax.h>

struct fuse_iext {
	struct rb_node rb;
	loff_t start;
	loff_t end; /* exclusive */
	struct fuse_backing *backing;
	loff_t backing_offset;
};

void fuse_ext_map_destroy(struct rb_root *extents)
{
	struct fuse_iext *fie, *tmp;

	rbtree_postorder_for_each_entry_safe(fie, tmp, extents, rb) {
		fuse_backing_put(fie->backing);
		kfree(fie);
	}
}

static struct fuse_iext *fuse_find_extent(struct rb_root *extents, loff_t offset)
{
	struct rb_node *node = extents->rb_node;

	while (node) {
		struct fuse_iext *fie = rb_entry(node, typeof(*fie), rb);

		if (offset < fie->start)
			node = node->rb_left;
		else if (offset >= fie->end)
			node = node->rb_right;
		else
			return fie;
	}

	return NULL;
}

static int fuse_add_extent(struct fuse_conn *fc, struct rb_root *extents,
			   struct fuse_extent *ext)
{
	struct fuse_iext *new_fie __free(kfree) = kzalloc_obj(*new_fie);
	struct rb_node *parent = NULL, **link = &extents->rb_node;

	if (!new_fie)
		return -ENOMEM;

	if (ext->reserved[0] || ext->reserved[1])
		return fuse_EIO("reserved fields set");

	if (!PAGE_ALIGNED(ext->length) || !PAGE_ALIGNED(ext->addr))
		return fuse_EIO("not page aligned");

	new_fie->start = ext->offset;
	new_fie->end = ext->offset + ext->length;
	new_fie->backing_offset = ext->addr;

	while (*link) {
		struct fuse_iext *fie = rb_entry(*link, typeof(*fie), rb);

		parent = *link;
		if (new_fie->end <= fie->start)
			link = &parent->rb_left;
		else if (new_fie->start >= fie->end)
			link = &parent->rb_right;
		else
			return fuse_EIO("overlap");
	}

	new_fie->backing = fuse_backing_lookup(fc, ext->backing_id, true);
	if (!new_fie->backing)
		return fuse_EIO("backing not found");

	rb_link_node(&new_fie->rb, parent, link);
	rb_insert_color(&no_free_ptr(new_fie)->rb, extents);

	return 0;
}

static int fuse_ext_map_iomap_begin(struct inode *inode, loff_t offset, loff_t length,
				    unsigned int flags, struct iomap *iomap, struct iomap *srcmap)
{
	struct fuse_backing *fb = fuse_inode_backing(get_fuse_inode(inode));
	struct fuse_iext *fie;
	uint64_t ncycle = 0;
	loff_t seq_off = 0;
	loff_t ext_len;

	if (!fb || fb->type != FUSE_BACKING_EXTMAP)
		return fuse_EIO("missing or wrong type backing");

	if (fb->cycle_length) {
		ncycle = offset / fb->cycle_length;
		seq_off = ncycle * fb->cycle_length;
	}

	fie = fuse_find_extent(&fb->extents, offset - seq_off);
	if (!fie)
		return fuse_EIO("missing mapping");

	if (WARN_ON(fie->backing->type != FUSE_BACKING_DAXDEV))
		return fuse_EIO("wrong type backing for extent");

	if (fie->backing->dax_error) {
		fuse_make_bad(inode);
		return fuse_EIO("dax error");
	}

	ext_len = fie->end - fie->start;

	iomap->offset = fie->start + seq_off;
	iomap->addr = fie->backing_offset + ncycle * ext_len;
	iomap->length = ext_len;
	iomap->dax_dev = fie->backing->dax_dev;
	iomap->type = IOMAP_MAPPED;
	iomap->flags = flags;

	return 0;
}

static const struct iomap_ops fuse_ext_map_iomap_ops = {
	.iomap_begin		= fuse_ext_map_iomap_begin,
};

static vm_fault_t fuse_ext_map_huge_fault(struct vm_fault *vmf, unsigned int order)
{
	struct inode *inode = file_inode(vmf->vma->vm_file);
	bool write_fault = (vmf->flags & FAULT_FLAG_WRITE) && (vmf->vma->vm_flags & VM_SHARED);
	vm_fault_t ret;
	unsigned long pfn;

	if (WARN_ON_ONCE(!IS_DAX(inode)))
		return VM_FAULT_SIGBUS;

	if (write_fault) {
		sb_start_pagefault(inode->i_sb);
		file_update_time(vmf->vma->vm_file);
	}

	ret = dax_iomap_fault(vmf, order, &pfn, NULL, &fuse_ext_map_iomap_ops);
	if (ret & VM_FAULT_NEEDDSYNC)
		ret = dax_finish_sync_fault(vmf, order, pfn);

	if (write_fault)
		sb_end_pagefault(inode->i_sb);

	return ret;
}

static vm_fault_t fuse_ext_map_fault(struct vm_fault *vmf)
{
	return fuse_ext_map_huge_fault(vmf, 0);
}

static const struct vm_operations_struct fuse_ext_map_vm_ops = {
	.fault		= fuse_ext_map_fault,
	.huge_fault	= fuse_ext_map_huge_fault,
	.page_mkwrite	= fuse_ext_map_fault,
	.pfn_mkwrite	= fuse_ext_map_fault,
};

static ssize_t fuse_rw_clamp(struct kiocb *iocb, struct iov_iter *ubuf)
{
	struct inode *inode = iocb->ki_filp->f_mapping->host;
	loff_t i_size = i_size_read(inode);
	loff_t max_count = iocb->ki_pos >= i_size ? 0 : i_size - iocb->ki_pos;

	if (iov_iter_count(ubuf) > max_count)
		iov_iter_truncate(ubuf, max_count);

	return 0;
}

ssize_t fuse_ext_map_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	ssize_t res;

	res = fuse_rw_clamp(iocb, to);
	if (res)
		return res;

	if (!iov_iter_count(to))
		return 0;

	res = dax_iomap_rw(iocb, to, &fuse_ext_map_iomap_ops);

	file_accessed(iocb->ki_filp);
	return res;
}

ssize_t fuse_ext_map_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	ssize_t res;

	res = fuse_rw_clamp(iocb, from);
	if (res)
		return res;

	if (!iov_iter_count(from))
		return 0;

	return dax_iomap_rw(iocb, from, &fuse_ext_map_iomap_ops);
}

int fuse_ext_map_mmap(struct file *file, struct vm_area_struct *vma)
{
	file_accessed(file);
	vma->vm_ops = &fuse_ext_map_vm_ops;
	vm_flags_set(vma, VM_HUGEPAGE);
	return 0;
}

bool fuse_ext_map_is_dax(struct fuse_backing *fb)
{
	struct fuse_iext *fie;

	if (WARN_ON(RB_EMPTY_ROOT(&fb->extents)))
		return false;

	fie = rb_entry(fb->extents.rb_node, typeof(*fie), rb);
	return fuse_backing_is_dax(fie->backing);
}

int fuse_ext_map_populate(struct fuse_conn *fc, struct fuse_notify_map_out *arg,
			  struct fuse_extent *ext)
{
	struct fuse_backing *fb;
	unsigned int i;
	int err;
	loff_t chunk_size = 0;

	if (fc->passthrough_ino)
		return -EINVAL;

	if (arg->flags & FUSE_MAP_BACKING_CREATE) {
		fb = kzalloc_obj(*fb);
		if (!fb)
			return -ENOMEM;

		refcount_set(&fb->count, 1);
		fb->type = FUSE_BACKING_EXTMAP;
		fb->backing_id = arg->backing_id;
	} else {
		/* Adding extents to an existing extmap backing is not yet supported */
		return -EINVAL;
	}

	if (arg->flags & FUSE_MAP_CYCLIC) {
		err = -EINVAL;
		if (!arg->num_extents)
			goto err_put;
		chunk_size = ext[0].length;
		fb->cycle_length = chunk_size * arg->num_extents;
	}

	for (i = 0; i < arg->num_extents; i++) {
		err = -EINVAL;
		if (chunk_size && (ext[i].offset != chunk_size * i || ext[i].length != chunk_size))
			goto err_put;

		err = fuse_add_extent(fc, &fb->extents, &ext[i]);
		if (err)
			goto err_put;
	}

	err = 0;
	if (arg->flags & FUSE_MAP_BACKING_CREATE) {
		err = fuse_backing_add_64(fc, fb);
		if (!err)
			return 0;
	}

err_put:
	fuse_backing_put(fb);
	return err;
}
