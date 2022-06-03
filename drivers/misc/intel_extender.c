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
#include <linux/kallsyms.h> /* KSYM_NAME_LEN */
#include <linux/sched/mm.h> /*mmget*/
#include <linux/intel_extender.h>

#define CREATE_TRACE_POINTS
#include <trace/events/extender.h>

#define REMAP_PFN_RANGE
//#define INSERT_PFN
#define EXTENDER_CTRL_CSR 0x0

static void __iomem *great_virt_area __ro_after_init;
static const struct platform_device *intel_extender_device = NULL;
static u64 fpga_addr_size[2] = {0};

/*
 * arch/arm64/mm/fault.c provides is_ttbr0... and is_ttrb1..., but we don't
 * need both, the former sufficies as it is always either. The possibility
 * the addr falls in between got ruled out earlier in the way to this handler.
 */
static const char *stringify_el(unsigned long addr)
{
	return is_ttbr0_addr(addr) ? "el0" : "el1";
}

static struct window_struct *reclaim_windows_if_exhaused(struct device *dev,
					unsigned long addr,
					struct list_head *free_list,
					struct list_head *allocated_list)
{
	if (list_empty(free_list)) {
		struct window_struct *first_in;

		first_in = list_last_entry(allocated_list,
					   struct window_struct, list);
		list_move(&first_in->list, free_list);

		dev_dbg(dev, "  %s: l: (free exhausted): win%d allocated -> free: held %px\n",
			stringify_el(addr), first_in->win_num, first_in->faulting_addr);
		trace_extender_list_allocated_to_free(stringify_el(addr), first_in);

		return first_in;
	}
	return NULL;
}

static struct window_struct *get_window_from_free_list(struct device *dev,
						       struct list_head *free_list)
{
	return list_last_entry(free_list, struct window_struct, list);
}

static void indicate_consumption_of_window(struct device *dev,
					   unsigned long addr,
					   struct window_struct *first_in,
					   struct list_head *allocated_list)
{
	list_move(&first_in->list, allocated_list);
	dev_dbg(dev, " %s: l: win%d: free -> allocated: holds VA %px -> PA %llx\n",
		stringify_el(addr), first_in->win_num, first_in->faulting_addr,
		first_in->phys_addr);
	trace_extender_list_free_to_allocated(stringify_el(addr), first_in);
}

vm_fault_t intel_extender_el0_fault(struct vm_fault *vmf)
{
	/*
	 * From vmf to task (struct task_struct): vmf->vma->vm_mm->owner.
	 * Also this is true: vmf->vma->vm_mm->owner = current
	 *
	 * From task struct to all of the vma's of the task:
	 * task->mm->mmap (struct vm_area_struct) and iteration through:
	 *
	 * Eg.
	 *	mm = task->mm;
	 *	for (vma = mm->mmap; vma; vma = vma->vm_next)
	 *
	 * The mm (vm_mm from vmf) is referred to as a memory descriptor
	 * (struct mm_struct) all the vma's belong to. Note vma's belong to
	 * mm, and mm in turn is part of the task structure (referred to
	 * as process descriptor).
	 *
	 * In reclaiming a window we need to take into account that the window
	 * being reclaimed may be currently in possession of another task, or that
	 * another task exited leaving the window 'orphaned', aka it is not used
	 * despite being allocated (being on the allocated_list).
	 *
	 * What we do to address the above is: we store the mm vma allocating
	 * a window belongs to (vmf->vma->vm_mm). Later when reclaiming
	 * a window we find the vma holding the address based on mm and
	 * 'zap' the page entries. By it the vma remains but the mapping
	 * for it is torn down. Then if a task with the window reclaimed
	 * accesses it faults again and repeats the steps up to where was
	 * before, namely resolves the fault, allocates and steers for
	 * the window.
	 */

	struct vm_area_struct *vma = vmf->vma;
	vm_fault_t fault;
	pgprot_t prot;
	struct window_struct *first_in, *reclaimed_window;
	unsigned long window_mask;
	unsigned long fpga_expected_map_addr, fpga_expected_window_map_addr;
	unsigned long hps_offset_within_window, fpga_offset_within_window;
	unsigned long faulting_addr = vmf->address; /* Faulting addr */
	unsigned long phys_addr; /* Faulting addr would map to phys_addr */
	unsigned long offset_from_fpga, fpga_steer_to;
	struct extender *extender =
		platform_get_drvdata(intel_extender_device);

	dev_dbg(extender->dev,
		"\nel0: unable to handle paging request at VA %016lx\n",
		faulting_addr);
	trace_extender_fault_handler_entry(stringify_el(faulting_addr),
		"unable to handle paging request at VA", faulting_addr);

	mutex_lock(&extender->el0.lock);

	reclaimed_window = reclaim_windows_if_exhaused(extender->dev,
				    faulting_addr,
				    &extender->el0.free_list,
				    &extender->el0.allocated_list);

	if (reclaimed_window) {
		struct task_struct *temp;
		bool found = false;
		struct mm_struct *mm = reclaimed_window->mm;
		struct vm_area_struct *another_task_vma;
		unsigned long addr = (unsigned long)reclaimed_window->faulting_addr;

		/*
		 * Increment mm users preventing mm from being reaped
		 * while we are on it. If mm users zero ignore as it is
		 * terminated already or is being scheduled for.
		 */
		if (mmget_not_zero(mm)) {
			another_task_vma = find_vma_intersection(mm, addr, addr + 1);
			if (another_task_vma) {
				zap_vma_ptes(another_task_vma, addr, PAGE_SIZE);
				/*
				 * I had experimented with do_munmap() but it's overkill
				 * as it removes not only the mappings but also the VA
				 * area causing seg fault when accessed later.
				 */
				dev_dbg(extender->dev,
					"el0: zap_vma_ptes(addr %016lx)\n", addr);
			}
			mmput(mm);
		} else {
			dev_dbg(extender->dev,
				"el0: mm holding %016lx ceased\n", addr);
		}

	}

	first_in = get_window_from_free_list(extender->dev,
					     &extender->el0.free_list);

	/* Now play with data around the window allocated */
	first_in->caller = (void *)_RET_IP_;

	/*
	 * Mapping and faulting addresses are the same for el0 in contrast to
	 * el1 in which are not. Also the faulting addr here (el0) is already
	 * page aligned before this handler takes in. Maybe it is excessive
	 * here to show where it is but it can always be removed:
	 *
	 *   mm/memory.c:
	 *
	 *   static vm_fault_t __handle_mm_fault(struct vm_area_struct *vma,
         * 			unsigned long address, unsigned int flags)
	 *   {
         *   	struct vm_fault vmf = {
         *      .vma = vma,
	 *      .address = address & PAGE_MASK,
	 *
	 */
	first_in->mapping_addr = first_in->faulting_addr =
		(void __iomem *)faulting_addr;

	/*
	 * Store vma that maps to the window. Note, post task termination
	 * this should be invalid.
	 */
	first_in->mm = vmf->vma->vm_mm;

	/*
	 * It may be of use if we store a pid of the task. Even post-mortem
	 * we can cross check what task held the window.
	 */
	first_in->pid = vmf->vma->vm_mm->owner->pid;

#ifdef INSERT_PFN
#error "VMF_INSERT_PFN is untested and may not work"
	fault = vmf_insert_pfn_prot(vma, faulting_addr,
				    first_in->phys_addr >> PAGE_SHIFT,
				    vma->vm_page_prot);
	dev_dbg(extender->dev, "fault %x: %s\n",
		fault,
		fault == VM_FAULT_NOPAGE ? "VM_FAULT_NOPAGE" : "unknown fault");
#elif defined(REMAP_PFN_RANGE)
	/*
	 * Note, we resolve a pagefault but the ASE IP maps a window, they
	 * differ and need to be accounted for. Let us start with
	 * window_mask and ~window_mask (calcs down the code):
	 *
	 *  If window size is 0x100_0000 (16M), then:
	 *  window_mask   -> 0xffff_ffff_ff00_0000
	 *  ~windows_mask -> 0x0000_0000_00ff_ffff
	 *
	 * We came to here with the faulting addr (VA), and PFN we are to
	 * map the faulting addr at. The PFN is actually a PFN on the fpga
	 * address space and not on the HPS PA one.
	 *
	 * [I should not mention here but PA = PFN << PAGE_SHIFT]
	 *
	 * So, we need to calculate the in-between, namely a HPA PA (*), and
	 * fpga addr the window is to be steered at (**):
	 *
	 * (*) HPA PA is an offset within the HPA PA window. It is exactly
	 *     the offset the fpga addr is within the window steered, eg.
	 *
	 *     0x1000_8080 (fpga addr) & 0xff_ffff (~window_mask) =
	 *		0x00_8080 (offset within HPA PA window)
	 *
	 *     0x00_8080 (offset within HPA PA window) +
	 *		0x20_0000_0000 (HPA PA of a window, eg. window 0) =
	 *			0x20_0000_8080 (HPA PA)
	 *
	 * (**) fpga addr the window is to be steered at is fpga addr with
	 *      the least significant nibbles filtered, eg.
	 *
	 *	0x1000_8080 (fpga addr) & 0xff00_0000 (window_mask) =
	 *		0x1000_0000 (fpga addr window is steered at)
	 */

	window_mask = ~(first_in->size - 1);
	fpga_expected_map_addr = (unsigned long)(vma->vm_pgoff << PAGE_SHIFT);

	/* With upper nibble hack filter out that nibble */
	fpga_expected_map_addr &= EXTENDER_PHYS_MASK;
	fpga_expected_window_map_addr = fpga_expected_map_addr & window_mask;
	hps_offset_within_window = fpga_offset_within_window =
		fpga_expected_map_addr & ~window_mask;
	phys_addr = hps_offset_within_window + first_in->phys_addr;

	dev_dbg(extender->dev,
		"window_mask %lx fpga map addr %lx fpga window map addr %lx offset within the window %lx\n",
		window_mask, fpga_expected_map_addr,
		fpga_expected_window_map_addr, hps_offset_within_window);

	/*
	 * Whatever vma attributed the memory it represents override it to
	 * device memory as this is what we do if we map through the extender
	 * window. The device memory is slower but most reliable compared to
	 * normal memory.
	 */
	prot = pgprot_device(vma->vm_page_prot);
	if (io_remap_pfn_range(vma,
			       (unsigned long)faulting_addr,
			       phys_addr >> PAGE_SHIFT,
			       /*first_in->size*/PAGE_SIZE,
			       prot))
		return VM_FAULT_OOM;

	fault = VM_FAULT_NOPAGE;

	dev_dbg(extender->dev, "io_remap_pfn_range(VA %lx-%lx, PA %lx)\n",
		(unsigned long)faulting_addr,
		(unsigned long)faulting_addr + PAGE_SIZE,
		phys_addr);
#else
#error "define mapping routine for el0"
#endif
	/*
	 * Now steer the window. All the calcs are done above.
	 * Only add up the fpga base addr if other than 0.
	 */
	fpga_steer_to = fpga_expected_window_map_addr + fpga_addr_size[0];

	dev_dbg(extender->dev, "el0: steer: CSR val %lx @ first_in->control %px\n",
		fpga_steer_to, first_in->control);
	writeq(fpga_steer_to, first_in->control + EXTENDER_CTRL_CSR);

	/* Mark consumption of the window */
	indicate_consumption_of_window(extender->dev, faulting_addr, first_in,
				       &extender->el0.allocated_list);
	mutex_unlock(&extender->el0.lock);

	dev_dbg(extender->dev, "Resolution of faulting addr %s\n",
	        is_mapped(faulting_addr, false) ? "successful" : "failed");

	//show_pte(faulting_addr);
	//WARN_ON(1);
	//__asm volatile("1: b 1b\n");

#if 0
	{
		struct task_struct *task = current;
		struct vm_area_struct *vma;
		struct mm_struct *mm;
		int count = 0;

		mm = task->mm;
		for (vma = mm->mmap; vma; vma = vma->vm_next)
			dev_dbg(extender->dev, "vma number %d: start at %016lx ends at %016lx\n",
				++count, vma->vm_start, vma->vm_end);
	}
#endif

	trace_extender_fault_handler_exit(stringify_el(faulting_addr),
		"resolved paging request at VA", faulting_addr);
	return fault;
}
EXPORT_SYMBOL(intel_extender_el0_fault);

static ssize_t allocated_show(struct device *dev,
			   struct device_attribute *attr,
			   char *buf)
{
	struct extender *extender =
		platform_get_drvdata(intel_extender_device);
	struct window_struct *win;
	int len = 0;

	list_for_each_entry(win, &(extender->el1.allocated_list), list)
		len += sprintf(buf + len, "%llx ", win->phys_addr);

	return len;
}

static ssize_t free_show(struct device *dev,
			 struct device_attribute *attr,
			 char *buf)
{
	struct extender *extender =
		platform_get_drvdata(intel_extender_device);
	struct window_struct *win;
	int len = 0;

	list_for_each_entry(win, &(extender->el1.free_list), list)
		len += sprintf(buf + len, "%llx ", win->phys_addr);

	return len;
}

static DEVICE_ATTR_RO(allocated);
static DEVICE_ATTR_RO(free);

#if 0
#define extender_mapping(name)					\
static ssize_t name##_show(struct device *dev,			\
			   struct device_attribute *attr,	\
			   char *buf)				\
{								\
	struct extender *extender =			\
		platform_get_drvdata(intel_extender_device);	\
	struct window_struct *win;				\
	int len = 0;						\
								\
	list_for_each_entry(win, &(extender->##name), list)	\
		len += sprintf(buf + len, "%lx ", win->addr);	\
								\
	return len;						\
}								\
static DEVICE_ATTR_RO(name)

extender_mapping(allocated);
extender_mapping(free);
#endif

int intel_extender_el1_fault(unsigned long faulting_addr,
			     unsigned int esr,
			     struct pt_regs *regs)
{
	struct window_struct *win, *tmp;
	unsigned long offset_from_extender, fpga_steer_to;
	char buf0[300], buf1[300];
	int len0 = 0, len1 = 0;
	struct window_struct *first_in, *reclaimed_window;
	struct extender *extender =
		platform_get_drvdata(intel_extender_device);
	unsigned long flags, window_mask;
	unsigned long mapping_addr = faulting_addr;

	/*
	 * If the mapping address isn't within the extender start - end,
	 * it means the MMU faulted not becasue of us, return.
	 */
	if (faulting_addr < (unsigned long)extender->el1.extender_start ||
		faulting_addr >=((size_t)extender->el1.extender_start +
			extender->el1.extender_size))
		return -EFAULT;

	dev_dbg(extender->dev,
		"el1: unable to handle paging request at VA %016lx\n", faulting_addr);
	trace_extender_fault_handler_entry(stringify_el(faulting_addr),
		"unable to handle paging request at VA", faulting_addr);

	spin_lock_irqsave(&extender->el1.lock, flags);

	/*
	 * First, reclaim a window from the allocated list if
	 * the free list exhausted.
	 */
	reclaimed_window = reclaim_windows_if_exhaused(extender->dev,
				    faulting_addr,
				    &extender->el1.free_list,
				    &extender->el1.allocated_list);

	/* If reclaimed the window zap the mappings */
	if (reclaimed_window)
		extender_unmap_page_range(
			(unsigned long)reclaimed_window->mapping_addr,
			(unsigned long)reclaimed_window->mapping_addr +
			reclaimed_window->size);

	/*
	 * The reclaiming, above, ensured the free list is not empty.
	 * Pop the window from there.
	 */
	first_in = get_window_from_free_list(extender->dev,
					     &extender->el1.free_list);

	/*
	 * Now having a window (with its properties) find it is mask
	 * (window mask). Example with a 16M window size:
	 *
	 *   ~(0x100_0000 (window size) - 1) =
	 *	0xffff_ffff_ff00_0000 (window_mask)
	 */
	window_mask = ~(first_in->size - 1);

	first_in->caller = (void *)_RET_IP_;
	first_in->faulting_addr = (void __iomem *)faulting_addr;

	/*
	 * Filter out the least-significant nibbles from the faulting addr.
	 *
	 * Note, we are mapping not a page but a window (eg. 16M)
	 * the faulting address falls in. In other words this is not
	 * a pagefault handler but a windowfault handler if we were
	 * using the nomenclature from the el0 fault mechanism.
	 */
	mapping_addr &= window_mask;
	first_in->mapping_addr = (void __iomem *)mapping_addr;


	if (extender_page_range(mapping_addr, mapping_addr + first_in->size,
				 first_in->phys_addr,
				 __pgprot(PROT_DEVICE_nGnRE),
				 first_in->caller)) {
		unsigned long end = (unsigned long)mapping_addr + first_in->size;

		dev_err(extender->dev, "el1: extender_page_range() failed\n");;
		extender_unmap_page_range((unsigned long)mapping_addr, end);
		spin_unlock_irqrestore(&extender->el1.lock, flags);
		return -ENOMEM;
	}

	/*
	 * Now steer the window (ASE's IP). We are based on an assumption
	 * that the offset from the great virt area is the same as from
	 * the fpga start and it is where the window is to be steered at.
	 */
	offset_from_extender = faulting_addr - (unsigned long)extender->el1.extender_start;
	dev_dbg(extender->dev, "el1: offset_from_extender of the great virt area %lx\n",
		offset_from_extender);
	//trace_printk("el1: offset_from_extender of the great virt area %lx\n",
	//	offset_from_extender);

	/* Also filter out the least-significant nibbles from that offset. */
	//offset_from_extender &= window_mask;
	fpga_steer_to = offset_from_extender + fpga_addr_size[0];

	/* Steer the Span Extender */
	dev_dbg(extender->dev, "el1: steer: CSR val %lx @ first_in->control %px\n",
		fpga_steer_to, first_in->control);
	writeq(fpga_steer_to, first_in->control + EXTENDER_CTRL_CSR);
	//if (true == is_mapped(faulting_addr, true)) {
	//	dev_dbg(extender->dev, "VA %016lx mapped successfully!\n", faulting_addr);
	//}

	indicate_consumption_of_window(extender->dev,
				       faulting_addr,
				       first_in,
				       &extender->el1.allocated_list);
	spin_unlock_irqrestore(&extender->el1.lock, flags);

	trace_extender_fault_handler_exit(stringify_el(faulting_addr),
		"resolved paging request at VA", faulting_addr);

	return 0;
}

/* Pass on extra data to the child/ren */
static const struct of_dev_auxdata intel_extender_auxdata[] = {
	OF_DEV_AUXDATA("intel,extender-client", 0, NULL, &great_virt_area),
	OF_DEV_AUXDATA("intel,extender-memtest", 0, NULL, &great_virt_area),
	/* put here all the extender clients */
	{ /* sentinel */ },
};

static void run_some_diagnostics(void)
{
	struct window_struct *win;
	int i, index;
	unsigned long addr_48_bits, addr;
	pgd_t *pgdp;
	struct extender *extender =
		platform_get_drvdata(intel_extender_device);

	dev_dbg(extender->dev, "PGDIR_SIZE %lx PUD_SIZE %lx PMD_SIZE %lx PAGE_SIZE %lx\n",
		PGDIR_SIZE, PUD_SIZE, PMD_SIZE, PAGE_SIZE);
	dev_dbg(extender->dev, "PAGE_OFFSET %lx - PAGE_END %lx\n", PAGE_OFFSET, PAGE_END);
	dev_dbg(extender->dev, "KIMAGE_VADDR %lx MODULES_VADDR %lx MODULES_END %lx\n",
		KIMAGE_VADDR, MODULES_VADDR, MODULES_END);
	dev_dbg(extender->dev, "VMALLOC_START %lx VMALLOC_END %lx\n",
		VMALLOC_START, VMALLOC_END);
	dev_dbg(extender->dev, "EXTENDER_START %lx EXTENDER_END %lx\n",
		EXTENDER_START, EXTENDER_END);
	dev_dbg(extender->dev, "FIXADDR_START %lx FIXADDR_END %lx\n",
		FIXADDR_START, FIXADDR_TOP);
	dev_dbg(extender->dev, "PCI_IO_START %lx PCI_IO_END %lx PCI_IO_SIZE %x\n",
		PCI_IO_START, PCI_IO_END, (unsigned)PCI_IO_SIZE);
	dev_dbg(extender->dev, "VMEMMAP_START %lx VMEMMAP_END %lx VMEMMAP_SIZE %lx\n",
		VMEMMAP_START, VMEMMAP_START + VMEMMAP_SIZE, VMEMMAP_SIZE);
	dev_dbg(extender->dev, "STRUCT_PAGE_MAX_SHIFT %x sizeof(struct page) %lx\n",
		STRUCT_PAGE_MAX_SHIFT, sizeof(struct page));

	list_for_each_entry(win, &(extender->el1.free_list), list)
		dev_dbg(extender->dev, "el1: free_list[%d]: phys_addr %llx size %lx CSR %px",
			win->win_num, win->phys_addr, win->size, win->control);

	list_for_each_entry(win, &(extender->el0.free_list), list)
		dev_dbg(extender->dev, "el0: free_list[%d]: phys_addr %llx size %lx CSR %px",
			win->win_num, win->phys_addr, win->size, win->control);

	pr_info("EXTENDER_START %lx (pgd %lx) EXTENDER_END %lx (pgd %lx)\n",
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

static int intel_extender_probe(struct platform_device *pdev)
{
	unsigned long fpga_expected_size, offset;
	struct resource *res;
	struct extender *extender;
	struct window_struct *window;
	int ret = 0, order, i, curr_window = 0;
	int num_of_windows = pdev->num_resources / 2;

	intel_extender_device = pdev;

	extender = devm_kzalloc(&pdev->dev, sizeof(*extender), GFP_KERNEL);
	if (!extender) {
		dev_err(&pdev->dev, "memory allocation failed\n");
		return -ENOMEM;
	}

	extender->dev = &pdev->dev;
	platform_set_drvdata(pdev, extender);

	spin_lock_init(&extender->el1.lock);
	mutex_init(&extender->el0.lock);
	INIT_LIST_HEAD(&extender->el1.free_list);
	INIT_LIST_HEAD(&extender->el1.allocated_list);
	INIT_LIST_HEAD(&extender->el0.free_list);
	INIT_LIST_HEAD(&extender->el0.allocated_list);

	/*
	 * Manage EXTENDER area, get FPGA address (fpga_addr_size[0]), and
	 * size (fpga_addr_size[1]).
	 */
	if (of_property_read_u64_array(extender->dev->of_node,
				       "fpga_addr_size",
				       fpga_addr_size,
				       ARRAY_SIZE(fpga_addr_size))) {
		dev_err(extender->dev, "failed to get fpga memory range\n");
		return -EINVAL;
	}

	/*
	 * EXTENDER_START thr END is huge, but we only need to catch
	 * the accesses into a subspace from it equal to the fpga space.
	 *
	 * Calculate the fpga start and size and sanity check if it is
	 * page aligned (based on ioremap.c).
	 *
	 * The alignment is going around: say, stupidly the fpga start address
	 * is 0x1388, and a size 0x1003, or in other words a window is spanned
	 * from 0x1388 through 0x1388 + 0x1003 = 0x238b. Assuming a PAGE SIZE
	 * is 0x1000 effectively we are looking for a size of two pages
	 * (0x2000), spanning from 0x1000 through 0x3000.
	 *
	 * To calculate it we must calculate a PAGE offset from 0x1388,
	 * 0x1388 & 0xfff (~PAGE MASK) = 0x388, add it to the size requested,
	 * 0x388 + 0x1003 = 0x138b, and PAGE ALIGN that yields 0x2000.
	 *
	 * However again as with the windowed_size the fpga adrr. size is
	 * not in our control, so that if mismatch we can only sanity check
	 * it and complain.
	 */
	offset = fpga_addr_size[0] & ~PAGE_MASK;
	fpga_expected_size = PAGE_ALIGN(fpga_addr_size[1] + offset);

	dev_dbg(extender->dev, "dt: fpga start end %llx - %llx (size %llx)\n",
		fpga_addr_size[0], fpga_addr_size[0] + fpga_addr_size[1],
		fpga_addr_size[1]);

	BUG_ON(fpga_addr_size[1] != fpga_expected_size);

	extender->el1.extender_start = (void __iomem *)EXTENDER_START;
	extender->el1.extender_size = fpga_addr_size[1];

	/* Bug on if fpga space is greater than EXTENDER area */
	BUG_ON((unsigned long)extender->el1.extender_start + extender->el1.extender_size
			> EXTENDER_END);

	dev_dbg(extender->dev, "pdev->num_resources %d number of windows avail. %d\n",
		pdev->num_resources, num_of_windows);

	/*
	 * Each window is two resources, one is a windnow size, the other
	 * is CSR. Populated the windows to the list free_list.
	 */
	order = get_order(num_of_windows * sizeof(struct window_struct));
	window = (struct window_struct *)
			__get_free_pages(GFP_KERNEL | __GFP_ZERO, order);
	if (!window)
		return -ENOMEM;

	/* Populate all available windows from device-tree to free_list */
	for (i = 0; i < pdev->num_resources; i += 2) {
		unsigned long window_expected_size;
		struct window_struct *win =
			(struct window_struct *)&window[curr_window];

		/* Get windowed_slave addr and size. */
		res = platform_get_resource(pdev, IORESOURCE_MEM, i);
		if (!res) {
			dev_err(extender->dev, "fail to get windowed slave\n");
			return -ENOMEM;
		}

		win->phys_addr = res->start;
		win->size = resource_size(res);
		win->win_num = curr_window;

		dev_dbg(extender->dev, "window start end %llx - %llx (size %lx)\n",
			win->phys_addr, win->phys_addr + win->size,
			win->size);

		/*
		 * Window size (win->size) must be aligned. If not complain.
		 *
		 * Let us go step by step what we do below. We get the count order
		 * (fls - find last most-significant bit set) after rounding up to
		 * power of 2 and return if it is in the range [PAGE_SHIFT,
		 * get_count_order_long(EXTENDER_WINDOW_MAX_SIZE))]. If not we return
		 * either lower or upper boundary upon what the boundery is crossed, eg.
		 * if the size (as from order) is less than a page size
		 * (page size has page_shift order) than we take page_shift and
		 * not the order calculated.
		 *
		 * However as windowed_slave size is not in our control
		 * (Intel's extender IP) and we take it as-is we can only
		 * warn/bug on the misconfiguration found.
		 */
		window_expected_size = 1ul << clamp_t(int, get_count_order_long(win->size),
				       PAGE_SHIFT, get_count_order_long(EXTENDER_WINDOW_MAX_SIZE));

		dev_dbg(extender->dev, "window expected size %lx"
			" get_count_order_long(win->size %lx)"
			" %d fls(extender->win->size) %d\n",
			window_expected_size, win->size,
			get_count_order_long(win->size),
			fls(win->size));

		BUG_ON(window_expected_size != win->size);
		BUG_ON(!PAGE_ALIGNED(win->size));

		/* Get CSR */
		res = platform_get_resource(pdev, IORESOURCE_MEM, i + 1);
		if (res == NULL) {
			dev_err(&pdev->dev, "control resource failure\n");
			return -ENOMEM;
		}
		win->control = devm_ioremap_resource(extender->dev, res);
		if (IS_ERR(win->control))
			return PTR_ERR(win->control);

		dev_dbg(extender->dev, "CSR VA %px PA %llx - %llx\n",
			win->control, res->start, res->start + resource_size(res));

		/*
		 * Add a window to the free_list. Once the window gets
		 * allocated we will fill in some of the other fileds in
		 * pagefault handler specific to the caller, eg. caller's
		 * name, faulting addr, etc.
		 */
		if (curr_window >= num_of_windows - 2) { /* Add the last two widnows to el0. */
			dev_dbg(extender->dev, "add win%d to el0\n",
				win->win_num);
			list_add(&win->list, &extender->el0.free_list);
		} else if (curr_window >= 0) {
			dev_dbg(extender->dev, "add win%d to el1\n", win->win_num);
			list_add(&win->list, &extender->el1.free_list);
		}

		curr_window++;
	}


	dev_dbg(extender->dev, "reserve VA area %px-%lx (size %lx) from extender area %lx-%lx (size %lx)\n",
		extender->el1.extender_start,
		(unsigned long)extender->el1.extender_start + extender->el1.extender_size,
		extender->el1.extender_size,
		EXTENDER_START, EXTENDER_END, EXTENDER_END - EXTENDER_START);

	/*
	 * This is an alternative method of passing the great virt area to
	 * the clients of the ASE drivers. Populate the client platform
	 * devices with an address from here..
	 */
	great_virt_area = extender->el1.extender_start;
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

	/*
	 * Hmm, not sure if this is needed and not sure if adding it in
	 * the proper way. I guess it is not common the drivers do this
	 * so there is few to none to model on.
	 */
#ifdef DEBUG
	run_some_diagnostics();
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

arch_initcall(extender_init);
//subsys_initcall(extender_init);
//module_platform_driver(intel_extender_driver);
MODULE_AUTHOR("Marek Bykowski <marek.bykowski@gmail.com>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Memory Span Extender");
