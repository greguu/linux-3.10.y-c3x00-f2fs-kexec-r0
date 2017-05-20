/*
 * Header file for NAND accessing via logical address (SHARP FTL)
 *
 * Copyright (C) 2017 Andrea Adami <andrea.adami@gmail.com>
 *
 * Based on 2.4 sources: linux/include/asm-arm/sharp_nand_logical.h
 * Copyright (C) 2002  SHARP
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#ifndef __SHARPSL_NAND_LOGICAL_H__
#define __SHARPSL_NAND_LOGICAL_H__

#include <linux/types.h>
#include <linux/mtd/mtd.h>

int sharpsl_nand_init_logical(struct mtd_info *mtd, u32 partition_size);

void sharpsl_nand_cleanup_logical(void);

int sharpsl_nand_read_laddr(struct mtd_info *mtd, loff_t from, size_t len,
			    u_char *buf);

#endif
