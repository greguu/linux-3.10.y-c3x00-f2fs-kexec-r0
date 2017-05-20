/*
 * MTD method for NAND accessing via logical address (SHARP FTL)
 *
 * Copyright (C) 2017 Andrea Adami <andrea.adami@gmail.com>
 *
 * Based on 2.4 sources: drivers/mtd/nand/sharp_sl_logical.c
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

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/mtd/mtd.h>
#include <linux/mtd/partitions.h>
#include "sharpsl_ftl.h"

/* oob structure */
#define NAND_NOOB_LOGADDR_00		8
#define NAND_NOOB_LOGADDR_01		9
#define NAND_NOOB_LOGADDR_10		10
#define NAND_NOOB_LOGADDR_11		11
#define NAND_NOOB_LOGADDR_20		12
#define NAND_NOOB_LOGADDR_21		13

/* Logical Table */
struct mtd_logical {
	u32 size;		/* size of the handled partition */
	int index;		/* mtd->index */
	u_int phymax;		/* physical blocks */
	u_int logmax;		/* logical blocks */
	u_int *log2phy;		/* the logical-to-physical table */
};

static struct mtd_logical *sharpsl_mtd_logical;

/* wrapper */
static int sharpsl_nand_read_oob(struct mtd_info *mtd, loff_t offs, size_t len,
				 uint8_t *buf)
{
	loff_t mask = mtd->writesize - 1;
	struct mtd_oob_ops ops;
	int ret;

	ops.mode = MTD_OPS_PLACE_OOB;
	ops.ooboffs = offs & mask;
	ops.ooblen = len;
	ops.oobbuf = buf;
	ops.datbuf = NULL;

	ret = mtd_read_oob(mtd, offs & ~mask, &ops);
	if (ret != 0 || len != ops.oobretlen)
		return -1;

	return 0;
}

/* utility */
static u_int sharpsl_nand_get_logical_num(u_char *oob)
{
	u16 us;
	int good0, good1;

	if (oob[NAND_NOOB_LOGADDR_00] == oob[NAND_NOOB_LOGADDR_10] &&
	    oob[NAND_NOOB_LOGADDR_01] == oob[NAND_NOOB_LOGADDR_11]) {
		good0 = NAND_NOOB_LOGADDR_00;
		good1 = NAND_NOOB_LOGADDR_01;
	} else if (oob[NAND_NOOB_LOGADDR_10] == oob[NAND_NOOB_LOGADDR_20] &&
		   oob[NAND_NOOB_LOGADDR_11] == oob[NAND_NOOB_LOGADDR_21]) {
		good0 = NAND_NOOB_LOGADDR_10;
		good1 = NAND_NOOB_LOGADDR_11;
	} else if (oob[NAND_NOOB_LOGADDR_20] == oob[NAND_NOOB_LOGADDR_00] &&
		   oob[NAND_NOOB_LOGADDR_21] == oob[NAND_NOOB_LOGADDR_01]) {
		good0 = NAND_NOOB_LOGADDR_20;
		good1 = NAND_NOOB_LOGADDR_21;
	} else {
		return UINT_MAX;
	}

	us = oob[good0] | oob[good1] << 8;

	/* parity check */
	if (hweight16(us) & 1)
		return (UINT_MAX - 1);

	/* reserved */
	if (us == 0xffff)
		return 0xffff;
	else
		return (us & 0x07fe) >> 1;
}

int sharpsl_nand_init_logical(struct mtd_info *mtd, u32 partition_size)
{
	struct mtd_logical *logical = NULL;
	u_int block_num, log_num;
	loff_t block_adr;
	u_char *oob = NULL;
	int i, readretry;

	logical = kzalloc(sizeof(*logical), GFP_KERNEL);
	if (!logical)
		return -ENOMEM;

	oob = kzalloc(mtd->oobsize, GFP_KERNEL);
	if (!oob) {
		kfree(logical);
		return -ENOMEM;
	}

	/* initialize management structure */
	logical->size = partition_size;
	logical->index = mtd->index;
	logical->phymax = (partition_size / mtd->erasesize);

	/* FTL reserves 5% of the blocks + 1 spare  */
	logical->logmax = ((logical->phymax * 95) / 100) - 1;

	logical->log2phy = NULL;
	logical->log2phy = kcalloc(logical->logmax, sizeof(u_int), GFP_KERNEL);
	if (!logical->log2phy) {
		kfree(logical);
		kfree(oob);
		return -ENOMEM;
	}

	/* initialize logical->log2phy */
	for (i = 0; i < logical->logmax; i++)
		logical->log2phy[i] = UINT_MAX;

	/* create physical-logical table */
	for (block_num = 0; block_num < logical->phymax; block_num++) {
		block_adr = block_num * mtd->erasesize;

		if (mtd_block_isbad(mtd, block_adr))
			continue;

		readretry = 3;
read_retry:
		if (sharpsl_nand_read_oob(mtd, block_adr, mtd->oobsize, oob))
			continue;

		/* get logical block */
		log_num = sharpsl_nand_get_logical_num(oob);

		/* skip out of range and not unique values */
		if ((int)log_num >= 0  && (log_num < logical->logmax)) {
			if (logical->log2phy[log_num] == UINT_MAX)
				logical->log2phy[log_num] = block_num;
		} else {
			readretry--;
			if (readretry)
				goto read_retry;
		}
	}
	kfree(oob);
	sharpsl_mtd_logical = logical;

	pr_info("Sharp SL FTL: %d blocks used (%d logical, %d reserved)\n",
		logical->phymax, logical->logmax,
		logical->phymax - logical->logmax);

	return 0;
}

void sharpsl_nand_cleanup_logical(void)
{
	struct mtd_logical *logical = sharpsl_mtd_logical;

	sharpsl_mtd_logical = NULL;

	kfree(logical->log2phy);
	logical->log2phy = NULL;
	kfree(logical);
	logical = NULL;
}

/* MTD METHOD */
int sharpsl_nand_read_laddr(struct mtd_info *mtd,
			    loff_t from,
			    size_t len,
			    u_char *buf)
{
	struct mtd_logical *logical;
	u_int log_num, log_new;
	u_int block_num;
	loff_t block_adr;
	loff_t block_ofs;
	size_t retlen;
	int ret;

	logical = sharpsl_mtd_logical;
	log_num = (u32)from / mtd->erasesize;
	log_new = ((u32)from + len - 1) / mtd->erasesize;

	if (len <= 0 || log_num >= logical->logmax || log_new > log_num)
		return -EINVAL;

	block_num = logical->log2phy[log_num];
	block_adr = block_num * mtd->erasesize;
	block_ofs = (u32)from % mtd->erasesize;

	ret = mtd_read(mtd, block_adr + block_ofs, len, &retlen, buf);
	if (ret != 0 || len != retlen)
		return -EINVAL;

	return 0;
}
