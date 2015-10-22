/* PCI IRQ routing on the MN103E010 based ASB2305
 *
 * Copyright (C) 2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 *
 * This is simple: All PCI interrupts route through the CPU's XIRQ1 pin [IRQ 35]
 */
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <asm/io.h>
#include <asm/smp.h>
#include "pci-asb2305.h"

int pci_map_irq(struct pci_dev *, u8 slot, u8 pin)
{
	u8 line;

	dev->irq = XIRQ1;
	pci_write_config_byte(dev, PCI_INTERRUPT_LINE, dev->irq);
	pci_read_config_byte(dev, PCI_INTERRUPT_LINE, &line);
}
