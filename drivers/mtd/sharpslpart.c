/*
 * MTD partition parser for NAND flash on Sharp SL Series
 *
 * Copyright (C) 2017 Andrea Adami <andrea.adami@gmail.com>
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
#include <linux/mtd/mtd.h>
#include <linux/mtd/partitions.h>
#include "sharpsl_ftl.h"

/* factory defaults */
#define SHARPSL_NAND_PARTS		3
#define SHARPSL_FTL_PARTITION_SIZE	(7 * 1024 * 1024)
#define PARAM_BLOCK_PARTITIONINFO1	0x00060000
#define PARAM_BLOCK_PARTITIONINFO2	0x00064000

#define BOOT_MAGIC			be32_to_cpu(0x424f4f54)   /* BOOT */
#define FSRO_MAGIC			be32_to_cpu(0x4653524f)   /* FSRO */
#define FSRW_MAGIC			be32_to_cpu(0x46535257)   /* FSRW */

/*
 * Sample values read from SL-C860
 *
 * # cat /proc/mtd
 * dev:    size   erasesize  name
 * mtd0: 006d0000 00020000 "Filesystem"
 * mtd1: 00700000 00004000 "smf"
 * mtd2: 03500000 00004000 "root"
 * mtd3: 04400000 00004000 "home"
 *
 * PARTITIONINFO1
 * 0x00060000: 00 00 00 00 00 00 70 00 42 4f 4f 54 00 00 00 00  ......p.BOOT....
 * 0x00060010: 00 00 70 00 00 00 c0 03 46 53 52 4f 00 00 00 00  ..p.....FSRO....
 * 0x00060020: 00 00 c0 03 00 00 00 04 46 53 52 57 00 00 00 00  ........FSRW....
 * 0x00060030: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff  ................
 *
 */

struct sharpsl_nand_partitioninfo {
	u32 start;
	u32 end;
	u32 magic;
	u32 reserved;
};

static int sharpsl_parse_mtd_partitions(struct mtd_info *master,
					struct mtd_partition **pparts,
					struct mtd_part_parser_data *data)
{
	struct sharpsl_nand_partitioninfo buf1[SHARPSL_NAND_PARTS];
	struct sharpsl_nand_partitioninfo buf2[SHARPSL_NAND_PARTS];
	struct mtd_partition *sharpsl_nand_parts;

	/* init logical mgmt (FTL) */
	if (sharpsl_nand_init_logical(master, SHARPSL_FTL_PARTITION_SIZE))
		return -EINVAL;

	/* read the two partition tables */
	if (sharpsl_nand_read_laddr(master,
				    PARAM_BLOCK_PARTITIONINFO1,
				    sizeof(buf1), (u_char *)&buf1) ||
	    sharpsl_nand_read_laddr(master,
				    PARAM_BLOCK_PARTITIONINFO2,
				    sizeof(buf2), (u_char *)&buf2))
		return -EINVAL;

	/* cleanup logical mgmt (FTL) */
	sharpsl_nand_cleanup_logical();

	/* compare the two buffers */
	if (memcmp(&buf1, &buf2, sizeof(buf1))) {
		pr_err("sharpslpart: PARTITIONINFO 1,2 differ. Quit parser.\n");
		return -EINVAL;
	}

	/* check for magics (just in the first) */
	if (buf1[0].magic != BOOT_MAGIC ||
	    buf1[1].magic != FSRO_MAGIC ||
	    buf1[2].magic != FSRW_MAGIC) {
		pr_err("sharpslpart: magic values mismatch. Quit parser.\n");
		return -EINVAL;
	}

	sharpsl_nand_parts = kzalloc(sizeof(*sharpsl_nand_parts) *
				     SHARPSL_NAND_PARTS, GFP_KERNEL);
	if (!sharpsl_nand_parts)
		return -ENOMEM;

	/* original names */
	sharpsl_nand_parts[0].name = "smf";
	sharpsl_nand_parts[0].offset = buf1[0].start;
	sharpsl_nand_parts[0].size = buf1[0].end - buf1[0].start;
	sharpsl_nand_parts[0].mask_flags = 0;

	sharpsl_nand_parts[1].name = "root";
	sharpsl_nand_parts[1].offset = buf1[1].start;
	sharpsl_nand_parts[1].size = buf1[1].end - buf1[1].start;
	sharpsl_nand_parts[1].mask_flags = 0;

	sharpsl_nand_parts[2].name = "home";
	sharpsl_nand_parts[2].offset = buf1[2].start;
	/* discard buf1[2].end, was for older models with 64M flash */
	sharpsl_nand_parts[2].size = master->size - buf1[2].start;
	sharpsl_nand_parts[2].mask_flags = 0;

	*pparts = sharpsl_nand_parts;
	return SHARPSL_NAND_PARTS;
}

static struct mtd_part_parser sharpsl_mtd_parser = {
	.owner = THIS_MODULE,
	.parse_fn = sharpsl_parse_mtd_partitions,
	.name = "sharpslpart",
};

static int __init sharpsl_mtd_parser_init(void)
{
	register_mtd_parser(&sharpsl_mtd_parser);
	return 0;
}

static void __exit sharpsl_mtd_parser_exit(void)
{
	deregister_mtd_parser(&sharpsl_mtd_parser);
}

module_init(sharpsl_mtd_parser_init);
module_exit(sharpsl_mtd_parser_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andrea Adami <andrea.adami@gmail.com>");
MODULE_DESCRIPTION("MTD partitioning for NAND flash on Sharp SL Series");
