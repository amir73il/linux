/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Support for Intel Camera Imaging ISP subsystem.
 * Copyright (c) 2015, Intel Corporation.
 */

#ifndef _IA_CSS_FRAC_H
#define _IA_CSS_FRAC_H

/* @file
 * This file contains typedefs used for fractional numbers
 */

#include <type_support.h>

/* Fixed point types.
 * NOTE: the 16 bit fixed point types actually occupy 32 bits
 * to save on extension operations in the ISP code.
 */
/* Unsigned fixed point value, 0 integer bits, 16 fractional bits */
typedef u32 ia_css_u0_16;
/* Unsigned fixed point value, 5 integer bits, 11 fractional bits */
typedef u32 ia_css_u5_11;
/* Unsigned fixed point value, 8 integer bits, 8 fractional bits */
typedef u32 ia_css_u8_8;
/* Signed fixed point value, 0 integer bits, 15 fractional bits */
typedef s32 ia_css_s0_15;

#endif /* _IA_CSS_FRAC_H */
