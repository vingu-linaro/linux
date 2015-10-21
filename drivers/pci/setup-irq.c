/*
 *	drivers/pci/setup-irq.c
 *
 * Extruded from code written by
 *      Dave Rusling (david.rusling@reo.mts.dec.com)
 *      David Mosberger (davidm@cs.arizona.edu)
 *	David Miller (davem@redhat.com)
 *
 * Support routines for initializing a PCI subsystem.
 */


#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/errno.h>
#include <linux/ioport.h>
#include <linux/cache.h>
#include "pci.h"

void __weak pcibios_update_irq(struct pci_dev *dev, int irq)
{
	dev_dbg(&dev->dev, "assigning IRQ %02d\n", irq);
	pci_write_config_byte(dev, PCI_INTERRUPT_LINE, irq);
}

void pci_assign_irq(struct pci_dev *dev)
{
	u8 pin;
	u8 slot = -1;
	int irq = 0;
	struct pci_host_bridge *hbrg = pci_find_host_bridge(dev->bus);

	if (!(hbrg->map_irq)) {
		dev_dbg(&dev->dev, "runtime irq mapping not provided by arch\n");
		return;
	}

	/* If this device is not on the primary bus, we need to figure out
	   which interrupt pin it will come in on.   We know which slot it
	   will come in on 'cos that slot is where the bridge is.   Each
	   time the interrupt line passes through a PCI-PCI bridge we must
	   apply the swizzle function.  */

	pci_read_config_byte(dev, PCI_INTERRUPT_PIN, &pin);
	/* Cope with illegal. */
	if (pin > 4)
		pin = 1;

	if (pin) {
		/* Follow the chain of bridges, swizzling as we go.  */
		if(hbrg->swizzle_irq)
			slot = (*(hbrg->swizzle_irq))(dev, &pin);

		/* If a swizzling function is not used map_irq must ignore slot */
		irq = (*(hbrg->map_irq))(dev, slot, pin);
		if (irq == -1)
			irq = 0;
	}
	dev->irq = irq;

	dev_dbg(&dev->dev, "assign irq: got %d\n", dev->irq);

	/* Always tell the device, so the driver knows what is
	   the real IRQ to use; the device does not use it. */
	pcibios_update_irq(dev, irq);
}

void pci_fixup_irqs(u8 (*swizzle)(struct pci_dev *, u8 *),
		    int (*map_irq)(struct pci_dev *, u8, u8))
{
	/* This code should be removed shortly, but in the mean time
	   it can wrap the new codepath in order to allow arches
	   still using it to continue working */
	struct pci_dev *dev = NULL;
	struct pci_host_bridge *hbrg = NULL;

	for_each_pci_dev(dev)
		hbrg = pci_find_host_bridge(dev->bus);
		hbrg->swizzle_irq = swizzle;
		hbrg->map_irq = map_irq;
		pci_assign_irq(dev);
		hbrg->swizzle_irq = NULL;
		hbrg->map_irq = NULL;
}
EXPORT_SYMBOL_GPL(pci_fixup_irqs);
