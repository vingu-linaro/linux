/*
 * Copyright (c) 2012, Intel Corporation
 * Copyright (c) 2015, Red Hat, Inc.
 * Copyright (c) 2015, 2016 Linaro Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#define pr_fmt(fmt) "ACPI: SPCR: " fmt

#include <linux/acpi.h>
#include <linux/console.h>
#include <linux/kernel.h>

static struct acpi_table_spcr *spcr_table;

int console_acpi_match(struct console *c, char **options)
{
	int err;

	if (!c->acpi_match)
		return -ENODEV;

	if (!spcr_table)
		return -EAGAIN;

	err = c->acpi_match(c, spcr_table);
	if (err < 0)
		return err;

	if (options) {
		switch (spcr_table->baud_rate) {
		case 3:
			*options = "9600";
			break;
		case 4:
			*options = "19200";
			break;
		case 6:
			*options = "57600";
			break;
		case 7:
			*options = "115200";
			break;
		default:
			*options = "";
			break;
		}
	}

	return err;
}

static int __init spcr_table_detect(void)
{
	struct acpi_table_header *table;
	acpi_status status;

	if (acpi_disabled)
		return -ENODEV;

	status = acpi_get_table(ACPI_SIG_SPCR, 0, &table);
	if (ACPI_FAILURE(status)) {
		const char *msg = acpi_format_exception(status);

		pr_err("Failed to get table, %s\n", msg);
		return -EINVAL;
	}

	if (table->revision < 2)
		return -EOPNOTSUPP;

	spcr_table = (struct acpi_table_spcr *)table;

	pr_info("Console at 0x%016llx\n", spcr_table->serial_port.address);

	acpi_register_consoles_try_again();

	return 0;
}

arch_initcall(spcr_table_detect);
