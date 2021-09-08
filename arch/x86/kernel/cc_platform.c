// SPDX-License-Identifier: GPL-2.0-only
/*
 * Confidential Computing Platform Capability checks
 *
 * Copyright (C) 2021 Advanced Micro Devices, Inc.
 *
 * Author: Tom Lendacky <thomas.lendacky@amd.com>
 */

#include <linux/export.h>
#include <linux/cc_platform.h>
#include <linux/mem_encrypt.h>

bool cc_platform_has(enum cc_attr attr)
{
	if (sme_me_mask)
		return amd_cc_platform_has(attr);

	return false;
}
EXPORT_SYMBOL_GPL(cc_platform_has);
