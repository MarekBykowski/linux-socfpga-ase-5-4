// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2021 INTEL

#define DEBUG

#include <linux/module.h>
#include <linux/of.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/linkage.h>
#include <linux/uaccess.h>
#include <linux/arm-smccc.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/vmalloc.h>
#include <asm/cacheflush.h>
#include <linux/seq_file.h>
#include <linux/platform_device.h>
#include <linux/of_platform.h>
#include <linux/intel_extender.h>

#define EXTENDER_CTRL_CSR 0x2000

static void __iomem *great_virt_area __ro_after_init;

struct expdr_window {
	unsigned long addr;
	struct list_head list;
};

LIST_HEAD(extender_unmapped);
LIST_HEAD(extender_mapped);

#define extender_mapping(name)					\
static ssize_t name##_show(struct device *dev,			\
			   struct device_attribute *attr,	\
			   char *buf)				\
{								\
	struct expdr_window *p;					\
	int len = 0;						\
	list_for_each_entry(p, &extender_##name, list) {	\
		len += sprintf(buf + len, "%lx ", p->addr);	\
	}							\
	return len;						\
}								\
static DEVICE_ATTR_RO(name)

extender_mapping(mapped);
extender_mapping(unmapped);

int extender_map(struct intel_extender *extender,
		 unsigned long addr,
		 unsigned int esr,
		 struct pt_regs *regs)
{
	int err = 0;
	struct expdr_window *mapped, *p, *tmp;
	unsigned long offset;
	bool found = false;
	char buf0[300], buf1[300];
	int len0 = 0, len1 = 0;

	/*
	 * If the mapping address isn't within the great virt area,
	 * it means the MMU faulted not becasue of us, leave it out.
	 */
	if (addr < (unsigned long)extender->area_extender->addr ||
	    addr >=((size_t)extender->area_extender->addr +
	    extender->area_extender->size))
		return -EFAULT;

	dev_dbg(extender->dev,
		"unable to handle paging request at VA %016lx\n", addr);

	/* Page mask the mapping address */
	addr &= PAGE_MASK;

	/*
	 * Unmap the the mapped area
	 * If the mapping address led to the MMU fault it means
	 * it is unamapped. As there is only one area allowed to be mapped
	 * the requested area replaces the area already mapped. That
	 * results in the mapped moving to the unampped.
	 */
	list_for_each_entry_safe(p, tmp, &extender_mapped, list) {
		/*unmap_kernel_range_noflush(p->addr, PAGE_SIZE);*/
		unmap_kernel_range(p->addr, extender->windowed_size);
		list_move_tail(&p->list, &extender_unmapped);
	}

	/*
	 * Check if the requested area isn't already on the unmapped.
	 * If it is swap it around (from the unmapped to the mapped).
	 */
	list_for_each_entry_safe(p, tmp, &extender_unmapped, list) {
		if (p->addr == addr) {
			list_move_tail(&p->list, &extender_mapped);
			found = true;
		}
	}

	/*
	 * If the requested area isn't on the unmapped, create it and
	 * add it to the mapped.
	 */
	if (found == false) {
		mapped = kzalloc(sizeof(*mapped), GFP_KERNEL);
		mapped->addr = addr;
		list_add(&mapped->list, &extender_mapped);
	}

	/*
	 * Samity check! Don't even allow calling into
	 * ioremap_page_range() with the address and size page unaligned.
	 */
	BUG_ON(!PAGE_ALIGNED(extender->windowed_size) || !PAGE_ALIGNED(addr));

	dev_dbg(extender->dev, "ioremap_page_range %lx-%lx\n",
		addr, addr + extender->windowed_size);

	/* The heart of the mapping */
	err = ioremap_page_range(addr, addr + extender->windowed_size,
				 extender->area_extender->phys_addr,
				 __pgprot(PROT_DEVICE_nGnRE));
	if (err) {
		unmap_kernel_range_noflush(addr, extender->windowed_size);
		err = -ENOMEM;
		goto expdr_error;
	}

	/* We're interested into offset off the great virt area */
	offset = addr - (unsigned long)extender->area_extender->addr;
	dev_dbg(extender->dev, "offset off the great virt area %lx\n", offset);

	offset &= 0xffffffff00000000;

	/* Steer the Span Extender */
	dev_dbg(extender->dev, "steer Extender to %lx\n", offset);
	writeq(offset, extender->control + EXTENDER_CTRL_CSR);

#if 0
	/*
	 * Below we print the lists with the area mapped and unampped.
	 * This must be taken out of it and accessed through some
	 * management interface.
	 */
	list_for_each_entry(p, &extender_mapped, list) {
#ifdef DEBUG
		len0 += sprintf(buf0 + len0, "%lx ", p->addr);
#else
		;
#endif
	}
	list_for_each_entry(p, &extender_unmapped, list) {
#ifdef DEBUG
		len1 += sprintf(buf1 + len1, "%lx ", p->addr);
#else
		;
#endif
	}
	dev_dbg(extender->dev, "mapped: %s\n", buf0);
	dev_dbg(extender->dev, "unmapped: %s\n", buf1);
#endif

expdr_error:
	return err;
}

/* Pass on extra data to the child/ren */
static const struct of_dev_auxdata intel_extender_auxdata[] = {
	OF_DEV_AUXDATA("intel,extender-client", 0, NULL, &great_virt_area),
	/* put here all the extender clients */
	{ /* sentinel */ },
};

static int intel_extender_probe(struct platform_device *pdev)
{
	u64 fpga_address_space[2] = {0};
	phys_addr_t windowed_addr;
	unsigned long virt_size, offset;
	struct resource *res;
	struct intel_extender *extender;
	int ret = 0;

	extender = devm_kzalloc(&pdev->dev, sizeof(*extender), GFP_KERNEL);
	if (!extender) {
		dev_err(&pdev->dev, "memory allocation failed\n");
		return -ENOMEM;
	}

	extender->dev = &pdev->dev;
	platform_set_drvdata(pdev, extender);

	/* Get extender controls */
	res = platform_get_resource_byname(pdev, IORESOURCE_MEM, "control");
	extender->control = devm_ioremap(extender->dev, res->start,
		resource_size(res));
	if (IS_ERR(extender->control))
		return PTR_ERR(extender->control);

	/*
	 * Get windowed slave addr space.
	 * A subset of the great virt area space always maps to it.
	 */
	res = platform_get_resource_byname(pdev, IORESOURCE_MEM, "windowed_slave");
	if (!res) {
		dev_err(extender->dev, "fail to get windowed slave\n");
		return -ENOMEM;
	}
	extender->windowed_size = resource_size(res);
	extender->windowed_size = PAGE_ALIGN(extender->windowed_size);
	if (!devm_request_mem_region(extender->dev, res->start,
				     extender->windowed_size,
				     dev_name(extender->dev))) {
		dev_err(&pdev->dev, "cannot request I/O memory region");
		return -EBUSY;
	}
	windowed_addr = res->start;

	/* Get FPGA address space */
	if (of_property_read_u64_array(extender->dev->of_node,
				       "fpga_address_space",
				       fpga_address_space,
				       ARRAY_SIZE(fpga_address_space))) {
		dev_err(extender->dev, "failed to get fpga memory range\n");
		return -EINVAL;
	}

	/*
	 * We assume the sizes (and the mapping address) are PAGE aligned
	 * but if not we will force it (based on arch/arm64/mm/ioremap.c).
	 *
	 * The alignment is going around: say, you want to map a range
	 * from an address 0x1388 sized 0x1003, or in other words from
	 * 0x1388 through 0x1388 + 0x1003 = 0x238b. Assuming a PAGE SIZE is
	 * 0x1000 effectively we are looking for the size of two pages,
	 * 0x2000, spanning from 0x1000 through 0x3000, to satisfy the reqest.
	 *
	 * To calculate it we must calculate a PAGE offset off 0x1388,
	 * 0x1388 & 0xfff (~PAGE MASK) = 0x388, add it to the size reqested,
	 * 0x388 + 0x1003 = 0x138b, and PAGE ALIGN resulting in 0x2000.
	 */
	offset = fpga_address_space[0] & ~PAGE_MASK;
	virt_size = fpga_address_space[1] - fpga_address_space[0];
	virt_size = PAGE_ALIGN(virt_size + offset);

	dev_dbg(extender->dev, "fpga_address_space %llx-%llx (size 0x%lx)\n",
		fpga_address_space[0], fpga_address_space[1], virt_size);

	extender->area_extender = get_vm_area(virt_size,
					      VM_IOREMAP | VM_NO_GUARD);

	/* Register MMU fault handler */
	extender->map_op = extender_map;

	/* Get the virt addr of the great virt area */
	great_virt_area = extender->area_extender->addr;

	/* Page mask the windowed_addr */
	extender->area_extender->phys_addr = windowed_addr &= PAGE_MASK;

	dev_dbg(extender->dev, "reserve VA area %pS-0x%zx (size 0x%lx) from VMALLOC area 0x%lx-0x%lx\n",
		extender->area_extender->addr,
		(size_t)extender->area_extender->addr + extender->area_extender->size,
		extender->area_extender->size,
		VMALLOC_START, VMALLOC_END);

	dev_dbg(extender->dev, "VA is reserved for PA %pap-0x%zx\n",
		&extender->area_extender->phys_addr,
		(size_t)(extender->area_extender->phys_addr +
		extender->windowed_size));

	dev_dbg(extender->dev,
		"of_platform_populate(): populate great virt area %pS\n",
		great_virt_area);

	ret = of_platform_populate(extender->dev->of_node, NULL,
				   intel_extender_auxdata, extender->dev);
	if (ret) {
		dev_err(extender->dev,
			"failed to populate the great virt area\n");
		return ret;
	}

	device_create_file(extender->dev, &dev_attr_mapped);
	device_create_file(extender->dev, &dev_attr_unmapped);

#define TEST_EXTENDER_HERE_INSTEAD_OF_FROM_CLIENT 0

#if TEST_EXTENDER_HERE_INSTEAD_OF_FROM_CLIENT
	dev_dbg(extender->dev, "readl(%px)\n",
		extender->area_extender->addr);
	(void)readl(extender->area_extender->addr);

	dev_dbg(extender->dev, "readl(%px)\n",
		extender->area_extender->addr + 0x4000000000);
	(void)readl(extender->area_extender->addr + 0x4000000000);

	dev_dbg(extender->dev, "readl(%px)\n",
		extender->area_extender->addr + 0x8000000000);
	(void)readl(extender->area_extender->addr + 0x8000000000);
#endif

	return ret;
}

/* Compatible string */
static const struct of_device_id intel_extender_matches[] = {
	{ .compatible = "intel,extender", },
	{},
};
MODULE_DEVICE_TABLE(of, intel_extender_matches);

static struct platform_driver intel_extender_driver = {
	.driver = {
		   .name = "intel-extender",
		   .of_match_table = intel_extender_matches,
		   .owner = THIS_MODULE,
		  },
	.probe = intel_extender_probe,
};

static int __init extender_init(void)
{
	return platform_driver_register(&intel_extender_driver);
}

device_initcall(extender_init);
MODULE_AUTHOR("Marek Bykowski <marek.bykowski@gmail.com>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Memory Span Extender");
