/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2019 CTERA Networks.
 * All Rights Reserved.
 */
#ifndef __XFS_TIMESTAMP_H__
#define __XFS_TIMESTAMP_H__

//#define XFS_TIMESTAMP_DEBUG

#ifdef XFS_TIMESTAMP_DEBUG
#define XFS_TIMESTAMP_EXTENDED(sbp) 1
#else
#define XFS_TIMESTAMP_EXTENDED(sbp) xfs_sb_version_hasexttime(sbp)
#endif

/*
 * We use 2 unused msb of 32bit t_nsec to encode time ranges beyond y2038.
 *
 * We use an encoding that preserves the times for extra epoch "00":
 *
 * extra  msb of                         adjust for signed
 * epoch  32-bit                         32-bit tv_sec to
 * bits   time    decoded 64-bit tv_sec  64-bit tv_sec      valid time range
 * 0 0    1    -0x80000000..-0x00000001  0x000000000 1901-12-13..1969-12-31
 * 0 0    0    0x000000000..0x07fffffff  0x000000000 1970-01-01..2038-01-19
 * 0 1    1    0x080000000..0x0ffffffff  0x100000000 2038-01-19..2106-02-07
 * 0 1    0    0x100000000..0x17fffffff  0x100000000 2106-02-07..2174-02-25
 * 1 0    1    0x180000000..0x1ffffffff  0x200000000 2174-02-25..2242-03-16
 * 1 0    0    0x200000000..0x27fffffff  0x200000000 2242-03-16..2310-04-04
 * 1 1    1    0x280000000..0x2ffffffff  0x300000000 2310-04-04..2378-04-22
 * 1 1    0    0x300000000..0x37fffffff  0x300000000 2378-04-22..2446-05-10
 */

#define XFS_TIMESTAMP_NSEC_BITS		30
#define XFS_TIMESTAMP_NSEC_MASK		((1U << XFS_TIMESTAMP_NSEC_BITS) - 1)
#define XFS_TIMESTAMP_NSEC(nsec_epoch)	((nsec_epoch) & XFS_TIMESTAMP_NSEC_MASK)
#define XFS_TIMESTAMP_EPOCH_SHIFT	XFS_TIMESTAMP_NSEC_BITS
#define XFS_TIMESTAMP_EPOCH_BITS	(32 - XFS_TIMESTAMP_NSEC_BITS)
#define XFS_TIMESTAMP_EPOCH_MASK	(((1U << XFS_TIMESTAMP_EPOCH_BITS) \
					  - 1) << XFS_TIMESTAMP_EPOCH_SHIFT)
#define XFS_TIMESTAMP_SEC_BITS		(32 + XFS_TIMESTAMP_EPOCH_BITS)

#define XFS_TIMESTAMP_SEC_MIN		S32_MIN
#define XFS_TIMESTAMP_SEC32_MAX		S32_MAX
#define XFS_TIMESTAMP_SEC64_MAX		((1LL << XFS_TIMESTAMP_SEC_BITS) \
					 - 1  + S32_MIN)
#define XFS_TIMESTAMP_SEC_MAX(sbp) \
	(XFS_TIMESTAMP_EXTENDED(sbp) ? XFS_TIMESTAMP_SEC64_MAX : \
					XFS_TIMESTAMP_SEC32_MAX)


static inline int64_t xfs_timestamp_decode_sec64(int32_t sec32,
						 uint32_t nsec_epoch)
{
	int64_t sec64 = sec32;

	if (unlikely(nsec_epoch & XFS_TIMESTAMP_EPOCH_MASK)) {
		sec64 += ((int64_t)(nsec_epoch & XFS_TIMESTAMP_EPOCH_MASK)) <<
			XFS_TIMESTAMP_EPOCH_BITS;
#ifdef XFS_TIMESTAMP_DEBUG
		pr_info("%s: %lld.%d epoch=%x sec32=%d", __func__, sec64,
			XFS_TIMESTAMP_NSEC(nsec_epoch),
			(nsec_epoch & XFS_TIMESTAMP_EPOCH_MASK), sec32);
#endif
	}
	return sec64;
}

static inline int64_t xfs_timestamp_sec64(struct xfs_sb *sbp, int32_t sec32,
					  uint32_t nsec_epoch)
{
	return XFS_TIMESTAMP_EXTENDED(sbp) ?
		xfs_timestamp_decode_sec64(sec32, nsec_epoch) : sec32;
}

static inline bool xfs_timestamp_nsec_is_valid(struct xfs_sb *sbp,
					       uint32_t nsec_epoch)
{
	if (!XFS_TIMESTAMP_EXTENDED(sbp) &&
	    (nsec_epoch & XFS_TIMESTAMP_EPOCH_MASK))
		return false;

	return XFS_TIMESTAMP_NSEC(nsec_epoch) < NSEC_PER_SEC;
}

static inline bool xfs_timestamp_is_valid(struct xfs_sb *sbp,
					  xfs_timestamp_t *dtsp)
{
	return xfs_timestamp_nsec_is_valid(sbp,
				be32_to_cpu(dtsp->t_nsec_epoch));
}

static inline void xfs_timestamp_ic_decode(struct xfs_sb *sbp,
					   struct timespec64 *time,
					   xfs_ictimestamp_t *itsp)
{
	time->tv_sec = xfs_timestamp_sec64(sbp, itsp->t_sec,
					   itsp->t_nsec_epoch);
	time->tv_nsec = XFS_TIMESTAMP_NSEC(itsp->t_nsec_epoch);
}

static inline void xfs_timestamp_di_decode(struct xfs_sb *sbp,
					   struct timespec64 *time,
					   xfs_timestamp_t *dtsp)
{
	time->tv_sec = xfs_timestamp_sec64(sbp, be32_to_cpu(dtsp->t_sec),
					   be32_to_cpu(dtsp->t_nsec_epoch));
	time->tv_nsec = XFS_TIMESTAMP_NSEC(be32_to_cpu(dtsp->t_nsec_epoch));
}

static inline int32_t xfs_timestamp_encode_nsec_epoch(int64_t sec64,
						      int32_t nsec)
{
	int32_t epoch = ((sec64 - (int32_t)sec64) >> XFS_TIMESTAMP_EPOCH_BITS) &
			XFS_TIMESTAMP_EPOCH_MASK;

#ifdef XFS_TIMESTAMP_DEBUG
	if (epoch)
		pr_info("%s: %lld.%d epoch=%x sec32=%d", __func__, sec64, nsec,
			epoch, (int32_t)sec64);
#endif
	return (nsec & XFS_TIMESTAMP_NSEC_MASK) | epoch;
}

static inline int32_t xfs_timestamp_nsec_epoch(struct xfs_sb *sbp,
					       int64_t sec64, int32_t nsec)
{
	return XFS_TIMESTAMP_EXTENDED(sbp) ?
		xfs_timestamp_encode_nsec_epoch(sec64, nsec) : nsec;
}

static inline void xfs_timestamp_ic_encode(struct xfs_sb *sbp,
					   struct timespec64 *time,
					   xfs_ictimestamp_t *itsp)
{
	itsp->t_sec = (int32_t)time->tv_sec;
	itsp->t_nsec_epoch = xfs_timestamp_nsec_epoch(sbp, time->tv_sec,
						      time->tv_nsec);
}

static inline void xfs_timestamp_di_encode(struct xfs_sb *sbp,
					   struct timespec64 *time,
					   xfs_timestamp_t *dtsp)
{
	dtsp->t_sec = cpu_to_be32(time->tv_sec);
	dtsp->t_nsec_epoch = cpu_to_be32(xfs_timestamp_nsec_epoch(sbp,
						time->tv_sec, time->tv_nsec));
}

#endif /* __XFS_TIMESTAMP_H__ */
