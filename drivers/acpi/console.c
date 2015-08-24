/*
 * Copyright (c) 2012, Intel Corporation
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
#include <linux/kernel.h>
#include <linux/serial_core.h>

#define NUM_ELEMS(x) (sizeof(x) / sizeof(*x))

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
