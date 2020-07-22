/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Confidential Computing Device Authorization Header
 *
 * Copyright (C) 2021 Intel Corporation, Inc.
 *
 * Author: Kuppuswamy Sathyanarayanan <sathyanarayanan.kuppuswamy@linux.intel.com>
 */

#ifndef _CC_DEVICE_AUTHORIZED_H
#define _CC_DEVICE_AUTHORIZED_H

# ifndef __ASSEMBLY__

# include <linux/device.h>
# include <linux/cc_platform.h>

/*
 * cc_guest_authorized() - Used to get ARCH specific authorized status
 *			   of the given device.
 * @dev			 - device structure
 *
 * Return True to allow the device or False to deny it.
 *
 */

#  ifdef CONFIG_ARCH_HAS_CC_PLATFORM

bool cc_guest_authorized(struct device *dev);

#  else	/* !CONFIG_ARCH_HAS_CC_PLATFORM */

static inline bool cc_guest_authorized(struct device *dev)
{
	return dev->authorized;
}

#  endif /* CONFIG_ARCH_HAS_CC_PLATFORM */

# endif /* __ASSEMBLY__ */

#endif /* _CC_PLATFORM_H */
