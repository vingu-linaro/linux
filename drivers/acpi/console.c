/*
 * Copyright (c) 2012, Intel Corporation
 * Copyright (c) 2015, Red Hat, Inc.
 * Copyright (c) 2015, Linaro Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#define DEBUG
#define pr_fmt(fmt) "ACPI: " KBUILD_MODNAME ": " fmt

#include <linux/acpi.h>
#include <linux/console.h>
#include <linux/kernel.h>
#include <linux/serial_core.h>
#include <linux/tty.h>

#define NUM_ELEMS(x) (sizeof(x) / sizeof(*x))

static u64 acpi_serial_addr;
static struct acpi_device *acpi_serial_device;
static char *acpi_serial_options;

#ifdef CONFIG_SERIAL_EARLYCON
static int use_earlycon __initdata;
static int __init setup_acpi_earlycon(char *buf)
{
	if (!buf)
		use_earlycon = 1;

	return 0;
}
early_param("earlycon", setup_acpi_earlycon);

extern struct earlycon_id __earlycon_table[];

static __initdata struct {
	int id;
	const char *name;
} subtypes[] = {
	{0, "uart8250"},
	{1, "uart8250"},
	{2, NULL},
	{3, "pl011"},
};

static int __init acpi_setup_earlycon(unsigned long addr, const char *driver)
{
	const struct earlycon_id *match;

	for (match = __earlycon_table; match->name[0]; match++)
		if (strcmp(driver, match->name) == 0)
			return setup_earlycon_driver(addr, match->setup);

	return -ENODEV;
}

static int __init acpi_parse_dbg2(struct acpi_table_header *table)
{
	struct acpi_table_dbg2 *dbg2;
	struct acpi_dbg2_device *entry;
	void *tbl_end;

	dbg2 = (struct acpi_table_dbg2 *)table;
	if (!dbg2) {
		pr_debug("DBG2 not present.\n");
		return -ENODEV;
	}

	tbl_end = (void *)table + table->length;

	entry = (struct acpi_dbg2_device *)((void *)dbg2 + dbg2->info_offset);

	while (((void *)entry) + sizeof(struct acpi_dbg2_device) < tbl_end) {
		struct acpi_generic_address *addr;

		if (entry->revision != 0) {
			pr_debug("DBG2 revision %d not supported.\n",
				 entry->revision);
			return -ENODEV;
		}

		addr = (void *)entry + entry->base_address_offset;

		pr_debug("DBG2 PROBE - console (%04x:%04x).\n",
			 entry->port_type, entry->port_subtype);

		if (use_earlycon &&
		    (entry->port_type == ACPI_DBG2_SERIAL_PORT) &&
		    (entry->port_subtype < NUM_ELEMS(subtypes)))
			acpi_setup_earlycon(addr->address,
					    subtypes[entry->port_subtype].name);

		entry = (struct acpi_dbg2_device *)
			((void *)entry + entry->length);
	}

	return 0;
}

int __init acpi_early_console_probe(void)
{
	acpi_table_parse(ACPI_SIG_DBG2, acpi_parse_dbg2);

	return 0;
}
#endif /* CONFIG_SERIAL_EARLYCON */

/*
 * Parse the SPCR table. If we are not working with version 2 or
 * higher, bail.
 * Otherwise, pull out the baud rate and address to the console device.
 */
static int __init acpi_parse_spcr(struct acpi_table_header *table)
{
	struct acpi_table_spcr *spcr = (struct acpi_table_spcr *)table;

	if (table->revision < 2)
		return -EOPNOTSUPP;

	/* Handle possible alignment issues */
	memcpy(&acpi_serial_addr,
	       &spcr->serial_port.address, sizeof(acpi_serial_addr));

	/*
	 * The baud rate the BIOS used for redirection. Valid values are....
	 *	3 = 9600
	 *	4 = 19200
	 *	6 = 57600
	 *	7 = 115200
	 *	0-2, 5, 8 - 255 = reserved
	*/
	switch (spcr->baud_rate) {
	case 3:
		acpi_serial_options = "9600";
		break;
	case 4:
		acpi_serial_options = "19200";
		break;
	case 6:
		acpi_serial_options = "57600";
		break;
	case 7:
		acpi_serial_options = "115200";
		break;
	default:
		acpi_serial_options = "";
		break;
	}

	pr_info("SPCR serial device: 0x%llx (options: %s)\n",
	       acpi_serial_addr, acpi_serial_options);

	return 0;
}

/*
 * Parse an ACPI "Device" to determine if it represents the
 * data found in the SPCR table. If the associated Device has
 * and Address entry, and, that Address matches the one found
 * in our SPCR table, it's the entry we are interested in.
 *
 */
static acpi_status acpi_spcr_device_scan(acpi_handle handle,
					 u32 level, void *context, void **retv)
{
	unsigned long long addr = 0;
	struct acpi_buffer name_buffer = { ACPI_ALLOCATE_BUFFER, NULL };
	acpi_status status = AE_OK;
	struct acpi_device *adev;
	struct list_head resource_list;
	struct resource_entry *rentry;

	status = acpi_get_name(handle, ACPI_FULL_PATHNAME, &name_buffer);
	if (ACPI_FAILURE(status))
		return status;

	adev = acpi_bus_get_acpi_device(handle);
	if (!adev) {
		pr_err("Err locating SPCR device from ACPI handle\n");
		return AE_OK; /* skip this one */
	}

	/*
	 * Read device address from _CRS.
	 */
	INIT_LIST_HEAD(&resource_list);
	if (acpi_dev_get_resources(adev, &resource_list, NULL, NULL) <= 0)
		return AE_OK;

	list_for_each_entry(rentry, &resource_list, node) {
		if (resource_type(rentry->res) == IORESOURCE_MEM)
			addr = rentry->res->start;
	}
	acpi_dev_free_resource_list(&resource_list);

	if (addr == acpi_serial_addr) {
		acpi_serial_device = adev;

		pr_info("SPCR serial console: %s (0x%llx)\n",
		       (char *)(name_buffer.pointer), addr);

		return AE_OK; /* harmless to continue */
	}

	/* continue */
	return AE_OK; /* continue */
}

static int __init acpi_setup_spcr(void)
{
	if (0 != acpi_table_parse(ACPI_SIG_SPCR, acpi_parse_spcr)) {
		pr_warn("SPCR table not found - auto console disabled\n");
		return -ENODEV;
	}

	acpi_walk_namespace(ACPI_TYPE_DEVICE, ACPI_ROOT_OBJECT,
			    ACPI_UINT32_MAX, acpi_spcr_device_scan,
			    NULL, NULL, NULL);

	return 0;
}

static int __init acpi_spcr_setup(void)
{
	/*
	 * If ACPI is enabled, scan the tables for
	 * automatic console configuration
	 */
	if (!acpi_disabled)
		acpi_setup_spcr();

	return 0;
}
subsys_initcall_sync(acpi_spcr_setup);

/**
 * acpi_console_check() - Check for and configure console from ACPI information
 * @adev - Pointer to device
 * @name - Name to use for preferred console without index. ex. "ttyS"
 * @index - Index to use for preferred console.
 *
 * Check if the given device matches the information provided in the SPCR table
 * If it does then register it as the preferred console and return TRUE.
 * Otherwise return FALSE.
 */
bool acpi_console_check(struct acpi_device *adev, char *name, int index)
{
	if (acpi_disabled || !adev || adev != acpi_serial_device
	    || console_set_on_cmdline)
		return false;

	pr_info("adding preferred console [%s]\n", name);

	return !add_preferred_console(name, index,
				      kstrdup(acpi_serial_options, GFP_KERNEL));
}
