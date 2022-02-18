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
#include <asm/extender_map.h>
#include <linux/intel_extender.h>

#if 0
#define CREATE_TRACE_POINTS
#include <trace/events/extender.h>
#endif

#define EXTENDER_CTRL_CSR 0x0

static void __iomem *great_virt_area __ro_after_init;
static const struct platform_device *intel_extender_device = NULL;

/*LIST_HEAD(extender_unmapped);
LIST_HEAD(extender_mapped);*/

#if 0
#define extender_mapping(name)					\
static ssize_t name##_show(struct device *dev,			\
			   struct device_attribute *attr,	\
			   char *buf)				\
{								\
	struct intel_extender *extender =			\
		platform_get_drvdata(intel_extender_device);	\
	struct intel_extender_pool *p;				\
	int len = 0;						\
								\
	list_for_each_entry(p, &(extender->##name), node)	\
		len += sprintf(buf + len, "%lx ", p->addr);	\
								\
	return len;						\
}								\
static DEVICE_ATTR_RO(name)

extender_mapping(allocated);
extender_mapping(free);
#endif

static ssize_t allocated_show(struct device *dev,
			   struct device_attribute *attr,
			   char *buf)
{
	struct intel_extender *extender =
		platform_get_drvdata(intel_extender_device);
	struct intel_extender_pool *p;
	int len = 0;

	list_for_each_entry(p, &(extender->allocated), node)
		len += sprintf(buf + len, "%lx ", p->addr);

	return len;
}

static ssize_t free_show(struct device *dev,
			 struct device_attribute *attr,
			 char *buf)
{
	struct intel_extender *extender =
		platform_get_drvdata(intel_extender_device);
	struct intel_extender_pool *p;
	int len = 0;

	list_for_each_entry(p, &(extender->free), node)
		len += sprintf(buf + len, "%lx ", p->addr);

	return len;
}
static DEVICE_ATTR_RO(allocated);
static DEVICE_ATTR_RO(free);

int extender_map(unsigned long addr,
		 unsigned int esr,
		 struct pt_regs *regs)
{
	int err = 0;
	struct intel_extender_pool *mapped, *p, *tmp;
	unsigned long offset;
	bool found = false;
	char buf0[300], buf1[300];
	int len0 = 0, len1 = 0;
	unsigned long flags;
	struct intel_extender *test, *extender =
		platform_get_drvdata(intel_extender_device);

	spin_lock_irqsave(&extender->lock, flags);

	/*
	 * If the mapping address isn't within the great virt area,
	 * it means the MMU faulted not becasue of us, leave it out.
	 */
	if (addr < (unsigned long)extender->area_extender->addr ||
	    addr >=((size_t)extender->area_extender->addr +
	    extender->area_extender->size))
		return -EFAULT;

	/*trace_extender_log(smp_processor_id(), __func__);*/

	dev_dbg(extender->dev,
		"unable to handle paging request at VA %016lx\n", addr);
	//trace_printk("in_irq? %s\n", (in_irq() != 0) ? "yes" : "no");
	trace_printk("unable to handle paging request at VA %016lx\n", addr);

	/* Page mask the mapping address */
	addr &= PAGE_MASK;

	/*
	 * Unmap the the mapped area.
	 * If the mapping address led to the MMU fault it means
	 * it is unamapped. As there is only one area allowed to be mapped
	 * the requesting area replaces the area already mapped resulting in
	 * the mapped moving to the unampped.
	 */
	list_for_each_entry_safe(p, tmp, &extender->allocated, node) {
		/*unmap_kernel_range_noflush(p->addr, PAGE_SIZE);*/
		unsigned long end = p->addr + extender->windowed_size;
		extender_unmap_page_range(p->addr, end);
		flush_tlb_kernel_range(addr, end);
		BUG_ON(false == display_mapping(p->addr, false));
		list_move_tail(&p->node, &extender->free);
		trace_printk(" l: %lx mapped -> unmapped\n", p->addr);
	}

	/*
	 * Check if the requesting area isn't already on the unmapped.
	 * If it is swap it around (from the unmapped to the mapped).
	 */
	list_for_each_entry_safe(p, tmp, &extender->free, node) {
		if (p->addr == addr) {
			list_move_tail(&p->node, &extender->allocated);
			found = true;
			trace_printk(" l: %lx unmapped -> mapped\n", p->addr);
		}
	}

	/*
	 * If the requesting area isn't on the unmapped, create it and
	 * add it to the mapped.
	 */
	if (found == false) {
		mapped = kzalloc(sizeof(*mapped), GFP_ATOMIC);
		mapped->addr = addr;
		list_add(&mapped->node, &extender->allocated);
		trace_printk(" l: add %lx -> mapped\n", mapped->addr);
	}

	/*
	 * Samity check! Don't even allow calling into
	 * ioremap_page_range() with the address and size page unaligned.
	 */
	BUG_ON(!PAGE_ALIGNED(extender->windowed_size) || !PAGE_ALIGNED(addr));

	dev_dbg(extender->dev, "extender_page_range %lx-%lx\n",
		addr, addr + extender->windowed_size);

	/* The heart of the mapping */
#if 1
	err = extender_page_range(addr, addr + extender->windowed_size,
				  extender->area_extender->phys_addr,
				  __pgprot(PROT_DEVICE_nGnRE),
				  extender->area_extender->caller);
#else
	err = ioremap_page_range(addr, addr + extender->windowed_size,
				 extender->area_extender->phys_addr,
				 __pgprot(PROT_DEVICE_nGnRE));
#endif
	if (err) {
		unmap_kernel_range_noflush(addr, extender->windowed_size);
		err = -ENOMEM;
		goto extender_error;
	}

	/* We're interested into offset off the great virt area */
	offset = addr - (unsigned long)extender->area_extender->addr;
	dev_dbg(extender->dev, "offset off the great virt area %lx\n", offset);

	/* We or with all ones but it may change, therefore leaving it here */
	offset &= ~0x0;

	/* Steer the Span Extender */
	dev_dbg(extender->dev, "steer Extender to %lx\n", offset);
#if 1
	writeq(offset, extender->control + EXTENDER_CTRL_CSR);
#else
	dev_dbg(extender->dev, "pretended but didn't write CSR\n");
	trace_printk("Pretended but didn't write CSR\n");
#endif
	#if 0
	trace_printk("map %lx steer ASE to %lx\n",
		     addr, /*addr + extender->windowed_size,*/
		     offset);
	#endif
	spin_unlock_irqrestore(&extender->lock, flags);
#if 0
	/*
	 * Below we print the lists with the area mapped and unampped.
	 * This must be taken out of it and accessed through some
	 * management interface.
	 */
	list_for_each_entry(p, &extender->pool_mapped, list) {
#ifdef DEBUG
		len0 += sprintf(buf0 + len0, "%lx ", p->addr);
#else
		;
#endif
	}
	list_for_each_entry(p, &extender->pool_unmapped, list) {
#ifdef DEBUG
		len1 += sprintf(buf1 + len1, "%lx ", p->addr);
#else
		;
#endif
	}
	dev_dbg(extender->dev, "mapped: %s\n", buf0);
	dev_dbg(extender->dev, "unmapped: %s\n", buf1);
#endif

extender_error:
	return err;
}

/* Pass on extra data to the child/ren */
static const struct of_dev_auxdata intel_extender_auxdata[] = {
	OF_DEV_AUXDATA("intel,extender-client", 0, NULL, &great_virt_area),
	OF_DEV_AUXDATA("intel,extender-memtest", 0, NULL, &great_virt_area),
	/* put here all the extender clients */
	{ /* sentinel */ },
};

extern struct list_head vmap_area_list;
static int intel_extender_probe(struct platform_device *pdev)
{
	u64 fpga_addr_size[2] = {0};
	phys_addr_t windowed_addr;
	unsigned long virt_size, offset;
	struct resource *res;
	struct intel_extender *extender;
	int ret = 0;

	intel_extender_device = pdev;

	extender = devm_kzalloc(&pdev->dev, sizeof(*extender), GFP_KERNEL);
	if (!extender) {
		dev_err(&pdev->dev, "memory allocation failed\n");
		return -ENOMEM;
	}

	spin_lock_init(&extender->lock);
	INIT_LIST_HEAD(&extender->allocated);
	INIT_LIST_HEAD(&extender->free);

	extender->dev = &pdev->dev;
	platform_set_drvdata(pdev, extender);

	dev_info(extender->dev, "pdev->num_resources %d\n",
		 pdev->num_resources);

	/* Get extender controls */
	res = platform_get_resource_byname(pdev, IORESOURCE_MEM, "control");
	if (res == NULL) {
		dev_err(&pdev->dev, "control resource failure\n");
		return -ENOMEM;
	}
	dev_dbg(extender->dev, "CSR start end %llx - %llx\n",
		 res->start, res->start + resource_size(res));

	extender->control = devm_ioremap(extender->dev, res->start,
		resource_size(res));
	if (IS_ERR(extender->control))
		return PTR_ERR(extender->control);

	dev_dbg(extender->dev, "CSR base %lx\n", (long unsigned int)extender->control);

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
	dev_dbg(extender->dev, "Window start end %llx - %llx\n",
		 res->start, res->start + resource_size(res));
	if (!devm_request_mem_region(extender->dev, res->start,
				     extender->windowed_size,
				     dev_name(extender->dev))) {
		dev_err(&pdev->dev, "cannot request I/O memory region");
		return -EBUSY;
	}
	windowed_addr = res->start;

	/* Get FPGA address space */
	if (of_property_read_u64_array(extender->dev->of_node,
				       "fpga_addr_size",
				       fpga_addr_size,
				       ARRAY_SIZE(fpga_addr_size))) {
		dev_err(extender->dev, "failed to get fpga memory range\n");
		return -EINVAL;
	}

	/*
	 * We assume a size and a mapping address are PAGE aligned but if not
	 * we will force it (based on arch/arm64/mm/ioremap.c).
	 *
	 * The alignment is going around: say, you want to map a range
	 * from an address 0x1388 sized 0x1003, or in other words from
	 * 0x1388 through 0x1388 + 0x1003 = 0x238b. Assuming a PAGE SIZE is
	 * 0x1000 effectively we are looking for a size of two pages,
	 * 0x2000, spanning from 0x1000 through 0x3000, to satisfy the reqest.
	 *
	 * To calculate it we must calculate a PAGE offset off 0x1388,
	 * 0x1388 & 0xfff (~PAGE MASK) = 0x388, add it to the size reqested,
	 * 0x388 + 0x1003 = 0x138b, and PAGE ALIGN resulting in 0x2000.
	 */
	offset = fpga_addr_size[0] & ~PAGE_MASK;
	virt_size = PAGE_ALIGN(fpga_addr_size[1] + offset);

	dev_dbg(extender->dev, "fpga start end %llx - %llx (size %lx)\n",
		fpga_addr_size[0], fpga_addr_size[0] + virt_size,
		virt_size);

	extender->area_extender = get_extender_area(virt_size);
	pr_info("extender->area_extender->caller %pF\n",
		extender->area_extender->caller);

	/* Get the virt addr of the great virt area */
	great_virt_area = (void *)extender->area_extender->addr;

	/* Page mask the windowed_addr */
	extender->area_extender->phys_addr = windowed_addr &= PAGE_MASK;

	dev_dbg(extender->dev, "reserve VA area %lx-%zx (size %lx) from extender area %lx-%lx (size %lx)\n",
		extender->area_extender->addr,
		(size_t)extender->area_extender->addr + extender->area_extender->size,
		extender->area_extender->size,
		EXTENDER_START, EXTENDER_END, EXTENDER_END - EXTENDER_START);

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

	device_create_file(extender->dev, &dev_attr_allocated);
	device_create_file(extender->dev, &dev_attr_free);

	pr_info("\n");
	pr_info("PGDIR_SIZE %lx PUD_SIZE %lx PMD_SIZE %lx PAGE_SIZE %lx\n",
		PGDIR_SIZE, PUD_SIZE, PMD_SIZE, PAGE_SIZE);
	pr_info("mb: PAGE_OFFSET %lx - PAGE_END %lx\n", PAGE_OFFSET, PAGE_END);
	pr_info("mb: KIMAGE_VADDR %lx MODULES_VADDR %lx MODULES_END %lx\n",
		KIMAGE_VADDR, MODULES_VADDR, MODULES_END);
	pr_info("mb: VMALLOC_START %lx VMALLOC_END %lx\n",
		VMALLOC_START, VMALLOC_END);
	pr_info("mb: EXTENDER_START %lx EXTENDER_END %lx\n",
		EXTENDER_START, EXTENDER_END);
	pr_info("mb: FIXADDR_START %lx FIXADDR_END %lx\n",
		FIXADDR_START, FIXADDR_TOP);
	pr_info("mb: PCI_IO_START %lx PCI_IO_END %lx PCI_IO_SIZE %x\n",
		PCI_IO_START, PCI_IO_END, (unsigned)PCI_IO_SIZE);
	pr_info("mb: VMEMMAP_START %lx VMEMMAP_END %lx VMEMMAP_SIZE %lx\n",
		VMEMMAP_START, VMEMMAP_START + VMEMMAP_SIZE, VMEMMAP_SIZE);
	pr_info("mb: STRUCT_PAGE_MAX_SHIFT %x sizeof(struct page) %lx\n",
		STRUCT_PAGE_MAX_SHIFT, sizeof(struct page));

#if 0 /* Some diagnostics */
{
	int i, index;
	unsigned long addr_48_bits, addr;
	pgd_t *pgdp;
	pr_info("mb: EXTENDER_START %lx (pgd %lx) EXTENDER_END %lx (pgd %lx)\n",
		EXTENDER_START, pgd_index(EXTENDER_START),
		EXTENDER_END, pgd_index(EXTENDER_END));

	for (i = 0; i < PTRS_PER_PGD; i++) {
		addr_48_bits = i * PGDIR_SIZE;
		addr = addr_48_bits | (0xfffful << 48);
		index = pgd_index(addr);
		pgdp = pgd_offset_k(addr);

		if (pgd_present(*pgdp) || __is_in_extender(addr))
			pr_info("pgd[%3d]: pgd_val %16llx spanning virt addr %16lx - %16lx: %s\n",
				index,
				pgd_val(READ_ONCE(*pgdp)),
				addr,
				addr + PGDIR_SIZE ? addr + PGDIR_SIZE : addr + PGDIR_SIZE - 1,
				__is_in_extender(addr) ? "EXTENDER_MAP" : "");
	}
}
{
	int k = 8;
	pr_info("mb: ALIGN_DOWN(7,4) %d ALIGN(7,4) %d ALIGN(5,4) %d\n",
		ALIGN_DOWN(7,4), ALIGN(7,4), ALIGN(5,4));
}

{
	struct vmap_area *va;
	struct vm_struct *vm;
	list_for_each_entry(va, &vmap_area_list, list) {
		pr_info("mb: vaddr %lx caller %pF\n",
			(unsigned long)va->vm->addr,
			va->vm->caller);
	}
}
#endif


#define TEST_EXTENDER_HERE_INSTEAD_OF_FROM_CLIENT 0

#if TEST_EXTENDER_HERE_INSTEAD_OF_FROM_CLIENT
{
	int i;
	for (i = 0; i < 5; i++) {
		dev_dbg(extender->dev, "readl(%lx)\n", 0xffffbdc000000000);
		(void)readl((void *)0xffffbdc000000000);
		dev_dbg(extender->dev, "readl(%lx)\n", 0xffffbda000000000);
		(void)readl((void *)0xffffbda000000000);
	}
}

#	if 0
	dev_dbg(extender->dev, "readl(%px)\n",
		extender->area_extender->addr + 0x4000000000);
	(void)readl(extender->area_extender->addr + 0x4000000000);

	dev_dbg(extender->dev, "readl(%px)\n",
		extender->area_extender->addr + 0x8000000000);
	(void)readl(extender->area_extender->addr + 0x8000000000);
#	endif
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
