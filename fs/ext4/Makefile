#
# Makefile for the linux ext4-filesystem routines.
#

ifndef CONFIG_EXT4_FS
# default configuration for standalone module
CONFIG_EXT4_FS?=m
CONFIG_EXT4_FS_XATTR?=y
CONFIG_EXT4_FS_POSIX_ACL?=$(CONFIG_FS_POSIX_ACL)
CONFIG_EXT4_FS_SECURITY?=y
CONFIG_EXT4_FS_DEBUG?=y
CONFIG_EXT4_FS_SNAPSHOT?=y
endif

obj-$(CONFIG_EXT4_FS) += ext4.o

ext4-y	:= balloc.o bitmap.o dir.o file.o fsync.o ialloc.o inode.o page-io.o \
		ioctl.o namei.o super.o symlink.o hash.o resize.o extents.o \
		ext4_jbd2.o migrate.o mballoc.o block_validity.o move_extent.o

ext4-$(CONFIG_EXT4_FS_XATTR)		+= xattr.o xattr_user.o xattr_trusted.o
ext4-$(CONFIG_EXT4_FS_POSIX_ACL)	+= acl.o
ext4-$(CONFIG_EXT4_FS_SECURITY)		+= xattr_security.o
ext4-$(CONFIG_EXT4_FS_SNAPSHOT)		+= snapshot.o snapshot_ctl.o
ext4-$(CONFIG_EXT4_FS_SNAPSHOT)		+= snapshot_inode.o buffer.o
ext4-$(CONFIG_EXT4_FS_DEBUG)		+= snapshot_debug.o
