// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2020 Intel Corporation
 */
#define pr_fmt(fmt) "TDX: " fmt

#include <linux/acpi.h>
#include <linux/pci.h>
#include <linux/device.h>
#include <linux/cc_platform.h>
#include <linux/export.h>

#include <asm/tdx.h>
#include <asm/cmdline.h>

/*
 * To support regex formats like (ALL:ALL), device allow
 * list uses char* type. Alternative choices like device_id
 * model will only add additional complexity. Using char*
 * will make it easier to add command line overrides.
 */
struct authorize_node {
	const char *bus;
	const char *dev_list;
};

/* Temporary string for storing device name */
static char dev_str[16];

/*
 * Allow list for PCI bus
 *
 * NOTE: Device ID is duplicated here. But for small list
 * of devices, it is easier to maintain the duplicated list
 * here verses exporting the device ID table from the driver
 * and use it.
 */
static const char pci_allow_list[] =
"0x1af4:0x1000," /* Virtio NET */
"0x1af4:0x1001," /* Virtio block */
"0x1af4:0x1003," /* Virtio console */
"0x1af4:0x1009," /* Virtio FS */
"0x1af4:0x1041," /* Virtio 1.0 NET */
"0x1af4:0x1042," /* Virtio 1.0 block */
"0x1af4:0x1043," /* Virtio 1.0 console */
"0x1af4:0x1049"; /* Virtio 1.0 FS */

static struct authorize_node allow_list[] = {
	/* Enable all devices in "virtio" bus */
	{ "virtio", "ALL" },
	/* Allow devices in pci_allow_list in "pci" bus */
	{ "pci", pci_allow_list },
};

static bool authorized_node_match(struct authorize_node *node,
				  const char *bus_name, const char *dev_list)
{
	const char *n;
	int len;

	/* If bus and dev_list matches "ALL", return true */
	if (!strcmp(node->bus, "ALL") && !strcmp(node->dev_list, "ALL"))
		return true;

	/*
	 * Since next step involves bus specific comparison, make
	 * sure the bus name matches with filter node. If not
	 * return false.
	 */
	if (strcmp(node->bus, bus_name))
		return false;

	/* If device name is "ALL", allow all */
	if (!strcmp(node->dev_list, "ALL"))
		return true;

	for (n = node->dev_list; *n; n += len) {
		if (*n == ',')
			n++;
		len = strcspn(n, ",");
		if (!strncmp(dev_list, n, len))
			return true;
	}

	return false;
}

char *get_dev_name(struct device *dev)
{
	struct pci_dev *pdev;

	/* For PCI, use format vendor:device */
	if (!strncmp(dev->bus->name, "pci", 3)) {
		pdev = to_pci_dev(dev);
		sprintf(dev_str, "0x%x:0x%x", pdev->vendor, pdev->device);

		return dev_str;
	}

	/* For other bus, just use device name */
	return (char *)dev_name(dev);
}

bool tdx_guest_authorized(struct device *dev)
{
	int i;

	if (!dev->bus)
		return dev->authorized;

	/* Lookup arch allow list */
	for (i = 0;  i < ARRAY_SIZE(allow_list); i++) {
		if (authorized_node_match(&allow_list[i], dev->bus->name,
					  get_dev_name(dev)))
			return true;
	}

	return dev_default_authorization;
}
EXPORT_SYMBOL_GPL(tdx_guest_authorized);

void __init tdx_filter_init(void)
{
	if (!cc_platform_has(CC_ATTR_GUEST_DEVICE_FILTER))
		return;

	/* Set default authorization as disabled */
	dev_default_authorization = false;

	pr_info("Enabled TDX guest device filter\n");
}
