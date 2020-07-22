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
#include <linux/cc_device.h>
#include <linux/mem_encrypt.h>
#include <linux/processor.h>
#include <linux/device.h>

#include <asm/tdx.h>

bool cc_platform_has(enum cc_attr attr)
{
	if (sme_me_mask)
		return amd_cc_platform_has(attr);
	else if (boot_cpu_data.x86_vendor == X86_VENDOR_INTEL)
		return intel_cc_platform_has(attr);

	return false;
}
EXPORT_SYMBOL_GPL(cc_platform_has);

bool cc_guest_authorized(struct device *dev)
{
	if (cpu_feature_enabled(X86_FEATURE_TDX_GUEST))
		return tdx_guest_authorized(dev);

	return dev->authorized;
}
EXPORT_SYMBOL_GPL(cc_guest_authorized);
