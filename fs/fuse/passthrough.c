// SPDX-License-Identifier: GPL-2.0
/*
 * FUSE passthrough to backing file.
 *
 * Copyright (c) 2023 CTERA Networks.
 */

#include "fuse_i.h"

#include <linux/file.h>

struct fuse_backing *fuse_backing_get(struct fuse_backing *fb)
{
	if (fb && refcount_inc_not_zero(&fb->count))
		return fb;
	return NULL;
}

static void fuse_backing_free(struct fuse_backing *fb)
{
	pr_debug("%s: fb=0x%p\n", __func__, fb);

	if (fb->file)
		fput(fb->file);
	if (fb->cred)
		put_cred(fb->cred);
	kfree_rcu(fb, rcu);
}

void fuse_backing_put(struct fuse_backing *fb)
{
	if (fb && refcount_dec_and_test(&fb->count))
		fuse_backing_free(fb);
}

/* Attach the inode bound backing file to inode */
static int fuse_backing_attach(struct fuse_conn *fc, u64 nodeid,
			       struct fuse_backing *fb)
{
	struct inode *inode;
	int err = -ENODEV;

	down_read(&fc->killsb);

	inode = fuse_ilookup(fc, nodeid, NULL);
	if (inode) {
		struct fuse_inode *fi = get_fuse_inode(inode);

		err = cmpxchg(&fi->fb, NULL, fb) ? -EEXIST : 0;
		iput(inode);
	}

	up_read(&fc->killsb);

	return err;
}

/* Detach the inode bound backing file from inode */
static struct fuse_backing *fuse_backing_detach(struct fuse_conn *fc,
						u64 nodeid)
{
	struct fuse_backing *fb;
	struct inode *inode;

	down_read(&fc->killsb);

	inode = fuse_ilookup(fc, nodeid, NULL);
	if (inode) {
		struct fuse_inode *fi = get_fuse_inode(inode);

		fb = xchg(&fi->fb, NULL);
		iput(inode);
	} else {
		fb = ERR_PTR(-ENODEV);
	}

	up_read(&fc->killsb);

	return fb;
}

/* fc->backing_files_map hold the backing files that are not inode bound */
void fuse_passthrough_init(struct fuse_conn *fc)
{
	idr_init(&fc->backing_files_map);
}

static int fuse_backing_id_alloc(struct fuse_conn *fc, struct fuse_backing *fb)
{
	int id;

	idr_preload(GFP_KERNEL);
	spin_lock(&fc->lock);
	id = idr_alloc_cyclic(&fc->backing_files_map, fb, 1, 0,
			       GFP_ATOMIC);
	spin_unlock(&fc->lock);
	idr_preload_end();

	WARN_ON_ONCE(id == 0);
	return id;
}

static struct fuse_backing *fuse_backing_id_remove(struct fuse_conn *fc,
						   int id)
{
	struct fuse_backing *fb;

	spin_lock(&fc->lock);
	fb = idr_remove(&fc->backing_files_map, id);
	spin_unlock(&fc->lock);

	return fb;
}

static int fuse_backing_id_free(int id, void *p, void *data)
{
	struct fuse_backing *fb = p;

	WARN_ON_ONCE(refcount_read(&fb->count) != 1);
	fuse_backing_free(fb);
	return 0;
}

void fuse_passthrough_free(struct fuse_conn *fc)
{
	idr_for_each(&fc->backing_files_map, fuse_backing_id_free, NULL);
	idr_destroy(&fc->backing_files_map);
}

int fuse_backing_open(struct fuse_conn *fc, struct fuse_backing_map *map)
{
	struct file *backing_file;
	struct super_block *backing_sb;
	struct fuse_backing *fb;
	int res;

	pr_debug("%s: fd=%d nodeid=%lld flags=0x%x\n", __func__,
		 map->fd, map->nodeid, map->flags);

	/* TODO: relax CAP_SYS_ADMIN once backing files are visible to lsof */
	if (!fc->passthrough || !capable(CAP_SYS_ADMIN))
		return -EPERM;

	switch (map->flags) {
	case FUSE_BACKING_MAP_INODE:
		if (!map->nodeid)
			return -EINVAL;
		break;

	case FUSE_BACKING_MAP_ID:
		if (map->nodeid)
			return -EINVAL;
		break;

	default:
		return -EINVAL;
	}

	backing_file = fget(map->fd);
	if (!backing_file)
		return -EBADF;

	res = -EOPNOTSUPP;
	if (!backing_file->f_op->read_iter ||
	    !backing_file->f_op->write_iter)
		goto out_fput;

	backing_sb = file_inode(backing_file)->i_sb;
	res = -ELOOP;
	if (backing_sb->s_stack_depth >= fc->max_stack_depth)
		goto out_fput;

	fb = kmalloc(sizeof(struct fuse_backing), GFP_KERNEL);
	res = -ENOMEM;
	if (!fb)
		goto out_fput;

	fb->file = backing_file;
	fb->cred = prepare_creds();
	refcount_set(&fb->count, 1);

	if (map->flags & FUSE_BACKING_MAP_ID)
		res = fuse_backing_id_alloc(fc, fb);
	else
		res = fuse_backing_attach(fc, map->nodeid, fb);
	if (res < 0) {
		fuse_backing_free(fb);
		return res;
	}

	map->backing_id = res;
	return 0;

out_fput:
	fput(backing_file);

	return res;
}

int fuse_backing_close(struct fuse_conn *fc, struct fuse_backing_map *map)
{
	struct fuse_backing *fb;

	pr_debug("%s: nodeid=%lld flags=0x%x\n", __func__,
		 map->nodeid, map->flags);

	/* TODO: relax CAP_SYS_ADMIN once backing files are visible to lsof */
	if (!fc->passthrough || !capable(CAP_SYS_ADMIN))
		return -EPERM;

	switch (map->flags) {
	case FUSE_BACKING_MAP_INODE:
		if (!map->nodeid)
			return -EINVAL;
		break;

	case FUSE_BACKING_MAP_ID:
		if (map->backing_id <= 0)
			return -EINVAL;
		break;

	default:
		return -EINVAL;
	}

	if (map->flags & FUSE_BACKING_MAP_ID)
		fb = fuse_backing_id_remove(fc, map->backing_id);
	else
		fb = fuse_backing_detach(fc, map->nodeid);
	if (IS_ERR_OR_NULL(fb))
		return fb ? PTR_ERR(fb) : -ENOENT;

	fuse_backing_put(fb);

	return 0;
}

/* Setup passthrough to an unbound backing file early */
void fuse_passthrough_start_open(struct fuse_file *ff, int backing_id)
{
	struct fuse_conn *fc = ff->fm->fc;
	struct fuse_backing *fb;

	rcu_read_lock();
	fb = idr_find(&fc->backing_files_map, backing_id);
	fb = fuse_backing_get(fb);
	rcu_read_unlock();

	/* Noop if the backing file is not mapped */
	ff->passthrough = fb;
	ff->open_flags &= ~FOPEN_PASSTHROUGH;

	pr_debug("%s: backing_id=%d, fb=0x%p\n", __func__, backing_id, fb);
}

/* Setup passthrough to an inode bound backing file */
void fuse_passthrough_finish_open(struct fuse_file *ff, struct fuse_inode *fi)
{
	struct fuse_backing *fb;

	rcu_read_lock();
	fb = fuse_backing_get(READ_ONCE(fi->fb));
	rcu_read_unlock();

	/* Noop if the backing file is not mapped */
	ff->passthrough = fb;

	pr_debug("%s: fb=0x%p\n", __func__, fb);
}
