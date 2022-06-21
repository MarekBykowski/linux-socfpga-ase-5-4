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

#if 0
#define CREATE_TRACE_POINTS
#include <trace/events/extender.h>
#endif

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

extern void unmap_region(struct mm_struct *mm,
			 struct vm_area_struct *vma,
			 struct vm_area_struct *prev,
			 unsigned long start, unsigned long end);

vm_fault_t intel_extender_el0_fault(struct vm_fault *vmf)
{
	/*
	 * From vmf to task (struct task_struct): vmf->vma->vm_mm->owner.
	 * Also the following is true: vmf->vma->vm_mm->owner = current
	 *
	 * From task struct to all the vma's of that task: task->mm->mmap (struct vm_area_struct).
	 * To iterate through: next vma of the mm is vma = task->mm->mmap->vm_next,
	 * from next vma to next to it is vma = vma->vm_next, etc. until vma NULL.
	 *
	 * Eg.
	 *	mm = task->mm;
	 *	for (vma = mm->mmap; vma; vma = vma->vm_next)
	 *
	 * The mm (and vm_mm) is referred to as a memory descriptor (struct mm_struct)
	 * all the vma's belong to. Note vma's belong to mm, and mm in turn is
	 * part of the task.
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
	//__maybe_unused unsigned long pfn = vmalloc_to_pfn((void *)vkern2);
	//get_cpu();
	//pr_info("mb: %s(): on CPU%d\n", __func__, smp_processor_id());
	//put_cpu();

	//dev_dbg(extender->dev, "%s: vma flags %lx FAULT_FLAG_xxx 0x%x (%#lx - %#lx) pgprot_val(vma->vm_page_prot) %s\n",
	//	current->comm,
	//	vma->vm_flags, vmf->flags,
	//	vmf->vma->vm_start, vmf->vma->vm_end,
	//	pgprot_val(vma->vm_page_prot) & PTE_UXN ? "UXN" : "other" );
	//dev_dbg(extender->dev, "mb: %s\n", vma->vm_mm->owner->comm);

	dev_dbg(extender->dev,
		"\nel0: unable to handle paging request at VA %016lx\n", faulting_addr);
	trace_extender_fault_handler_entry(stringify_el(faulting_addr), faulting_addr);
	//trace_printk("\nel0: unable to handle paging request at VA %016lx\n", faulting_addr);

	/* Allocate for a window to serve the request */
	mutex_lock(&extender->el0.lock);
	reclaimed_window = reclaim_windows_if_exhaused(extender->dev,
				    faulting_addr,
				    &extender->el0.free_list,
				    &extender->el0.allocated_list);

	/* If reclaimed window from allocated list do the unmapping of the VA to it */
	if (reclaimed_window) {
		struct task_struct *temp;
		bool found = false;
		struct mm_struct *mm = reclaimed_window->mm;
		struct vm_area_struct *another_task_vma;
		unsigned long addr = (unsigned long)reclaimed_window->faulting_addr;

		/*
		 * Increment mm users preventing mm from being torn down
		 * while we are on it. If mm users zero ignore as it is or
		 * being scheduled to be terminated.
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
				//do_munmap(mm, addr, PAGE_SIZE, NULL);
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
	first_in->faulting_addr = (void __iomem *)faulting_addr;
	/*
	 * Store vma that maps to the window.
	 * Note: post task termination this should be invalid.
	 */
	first_in->mm = vmf->vma->vm_mm;
	/*
	 * It may be of use if we store a pid of the task. Even post-mortem
	 * we can cross check what task it was.
	 */
	first_in->pid = vmf->vma->vm_mm->owner->pid;

#define REMAP_PFN_RANGE
//#define INSERT_PFN
#ifdef INSERT_PFN
#error "VMF_INSERT_PFN is untested and may not work"
	fault = vmf_insert_pfn_prot(vma, faulting_addr,
				    first_in->phys_addr >> PAGE_SHIFT,
				    vma->vm_page_prot);
	dev_dbg(extender->dev, "mb: fault %x: %s\n",
		fault,
		fault == VM_FAULT_NOPAGE ? "VM_FAULT_NOPAGE" : "unknown fault");
#elif defined(REMAP_PFN_RANGE)
	/*
	 * TODO:
	 * VM_PFNMAP in linux/mm.h
	 * Linux probably counts no of atomic_long_t pgtables_byte; PTE page table pages
	 *
	 * Note, we resolve page fault but the ASE IP maps a window size and
	 * not just a page size so they differ. Therefore for the mapping
	 * from VA through PA to fpga we need to map a page of the VA to
	 * a PFN of the PA calculated as the window start + page offset
	 * the faulting addr falls to.
	 */

#ifdef MAREKS_FIRST_EL0_TESTS
	window_offset = PAGE_ALIGN(addr - vmf->vma->vm_start);
#endif
	/*
	 * Find a window mask, eg. if size is 0x100_0000 (16M) then
	 * the window mask is 0xffff_ffff_ff00_0000.
	 *
	 * ~windows_mask is then 0x0000_0000_00ff_ffff.
	 */
	window_mask = ~(first_in->size - 1);
	fpga_expected_map_addr = (unsigned long)(vma->vm_pgoff << PAGE_SHIFT);

	/* While yet using the upper nibble hack filter out that nibble */
	fpga_expected_map_addr &= EXTENDER_PHYS_MASK;
	fpga_expected_window_map_addr = fpga_expected_map_addr & window_mask;

	/*
	 * We should map VA to the offset into the window same as
	 * fpga_expected_map_address offsets in the window. So calculate it...
	 */
	hps_offset_within_window = fpga_offset_within_window = fpga_expected_map_addr & ~window_mask;
	phys_addr = hps_offset_within_window + first_in->phys_addr;

	dev_dbg(extender->dev,
		"window_mask %lx fpga map addr %lx fpga window map addr %lx offset within the window %lx\n",
		window_mask, fpga_expected_map_addr,
		fpga_expected_window_map_addr, hps_offset_within_window);
	//trace_printk("window_mask %lx fpga map addr %lx fpga window map addr %lx offset within the window %lx\n",
	//	window_mask, fpga_expected_map_addr,
	//	fpga_expected_window_map_addr, hps_offset_within_window);

	/*
	 * Whatever mem attributes vma sets for itself (the area it
	 * represents) override to device memory if via extender.
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
	//trace_printk("io_remap_pfn_range(VA %lx-%lx, PA %lx)\n",
	//	(unsigned long)faulting_addr,
	//	(unsigned long)faulting_addr + PAGE_SIZE,
	//	phys_addr);
#else
#error "define mapping routine"
#endif
	/*
	 * Now steer the window.
	 *
	 * All the calcs are done above. Add to the window map address
	 * the fpga base address. With all the systems I have worked it
	 * was zero.
	 */
	fpga_steer_to = fpga_expected_window_map_addr + fpga_addr_size[0];

	/* Steer the window */
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

	trace_extender_fault_handler_exit(stringify_el(faulting_addr), faulting_addr);
	return fault;
}
EXPORT_SYMBOL(intel_extender_el0_fault);

const struct vm_operations_struct intel_extender_el0_ops = {
#ifdef CONFIG_HAVE_IOREMAP_PROT
	.access = generic_access_phys,
#endif
	/* pagefault handler */
	.fault = intel_extender_el0_fault,
};

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

	/*
	 * If the mapping address isn't within the extender start - end,
	 * it means the MMU faulted not becasue of us, return.
	 */
	if (faulting_addr < (unsigned long)extender->el1.extender_start ||
	    faulting_addr >=((size_t)extender->el1.extender_start + extender->el1.extender_size))
		return -EFAULT;

	dev_info(extender->dev,
		"el1: unable to handle paging request at VA %016lx\n", faulting_addr);
	trace_extender_fault_handler_entry(stringify_el(faulting_addr), faulting_addr);

	spin_lock_irqsave(&extender->el1.lock, flags);

#if 0 /* For a reason "Address Translation System Instructions" always return false "*/
	if (true == is_mapped(faulting_addr, false)) {
		dev_dbg(extender->dev, "el1: VA %016lx already mapped!\n", faulting_addr);
		spin_unlock_irqrestore(&extender->el1.lock, flags);
		return 0;
	}
#endif

#if 1
	reclaimed_window = reclaim_windows_if_exhaused(extender->dev,
				    faulting_addr,
				    &extender->el1.free_list,
				    &extender->el1.allocated_list);

	/* If reclaimed window from allocated list do the unmapping the VA to it */
	if (reclaimed_window)
		extender_unmap_page_range((unsigned long)reclaimed_window->faulting_addr,
				  (unsigned long)reclaimed_window->faulting_addr +
				  reclaimed_window->size);

	first_in = get_window_from_free_list(extender->dev,
					     &extender->el1.free_list);
#else
	/*
	 * If free_list empty pop first-in entry from allocated_list
	 * (that will be the last entry sitting on the allocated_list) and
	 * move to free_list.
	 */
	if (list_empty(&extender->el1.free_list)) {
		unsigned long end;

		first_in = list_last_entry(&extender->el1.allocated_list,
					   struct window_struct, list);
		end = (unsigned long)first_in->faulting_addr + first_in->size;
		/*
		 * Do it in order, that is unmap and only after then
		 * move around.
		 */
		extender_unmap_page_range((unsigned long)first_in->faulting_addr, end);
		list_move(&first_in->list, &extender->el1.free_list);
		dev_dbg(extender->dev, "  el1: l: (free exhausted): win%d allocated -> free: held %px\n",
			first_in->win_num, first_in->faulting_addr);
		trace_printk("  el1: l: (free exhausted): win%d allocated -> free: held %px\n",
			     first_in->win_num, first_in->faulting_addr);
#if 0
		/* Pop first-in entry. */
		list_for_each_entry_safe_reverse(win, tmp, &extender->el1.allocated_list, list) {
			/*
			 * In order, unmap and then switch around.
			 */
			unsigned long end = win->faulting_addr + win->size;
			extender_unmap_page_range(win->faulting_addr, end);
			flush_tlb_kernel_range(win->faulting_addr, end);
			list_move(&win->list, &extender->el1.free_list);
			break;
		}
#endif
	}

	/*
	 * We ensured above that the free_list has one item at minimum.
	 * Pop the first-in item from free_list (if there is just one item
	 * arranged for from above it will be that item then) and push to
	 * allocated_list.
	 */
	first_in = list_last_entry(&extender->el1.free_list,
				   struct window_struct, list);

#endif

	/* Now play with data around the window allocated */
	first_in->caller = (void *)_RET_IP_;

	/*
	 * Find a window mask, eg. if size is 0x100_0000 (16M) then
	 * the window mask is 0xffff_ffff_ff00_0000
	 */
	window_mask = ~(first_in->size - 1);

	/*
	 * and filter out the least-significant nibbles.
	 *
	 * Note, we are not mapping a page the faulting address falls in.
	 * We are mapping a window size (eg. 16M) where the faulting
	 * address falls in.
	 */
	faulting_addr &= window_mask;
	first_in->faulting_addr = (void __iomem *)faulting_addr;

	if (extender_page_range(faulting_addr, faulting_addr + first_in->size,
				 first_in->phys_addr,
				 __pgprot(PROT_DEVICE_nGnRE),
				 first_in->caller)) {
		unsigned long end = (unsigned long)first_in->faulting_addr + first_in->size;

		dev_err(extender->dev, "el1: extender_page_range() failed\n");;
		extender_unmap_page_range((unsigned long)first_in->faulting_addr, end);
		spin_unlock_irqrestore(&extender->el1.lock, flags);
		return -ENOMEM;
	}

	/*
	 * Now steer the window (ASE's IP).
	 * We are based on an assumption that the offset from the great
	 * virt area is the same as from the fpga start and it is where
	 * the ASE is to be steered to.
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
#if 0
	/*
	 * Below we print the lists with the area mapped and unampped.
	 * This must be taken out of it and accessed through some
	 * management interface.
	 */
	list_for_each_entry(win, &extender->pool_mapped, list) {
#ifdef DEBUG
		len0 += sprintf(buf0 + len0, "%lx ", win->faulting_addr);
#else
		;
#endif
	}
	list_for_each_entry(win, &extender->pool_unmapped, list) {
#ifdef DEBUG
		len1 += sprintf(buf1 + len1, "%lx ", win->faulting_addr);
#else
		;
#endif
	}
	dev_dbg(extender->dev, "mapped: %s\n", buf0);
	dev_dbg(extender->dev, "unmapped: %s\n", buf1);
#endif
	trace_extender_fault_handler_exit(stringify_el(faulting_addr), faulting_addr);
	return 0;
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
	{
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
	}

	dev_dbg(extender->dev, "pdev->num_resources %d number of windows avail. %d\n",
		pdev->num_resources, num_of_windows);

	/*
	 * Each window is two resources, one is a windnow size, the other
	 * is CSR. So that devide the resources by two and get the windows
	 * populated to the list free_list.
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
		{
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
		}

		/* Get CSR */
		{
			res = platform_get_resource(pdev, IORESOURCE_MEM, i + 1);
			if (res == NULL) {
				dev_err(&pdev->dev, "control resource failure\n");
				return -ENOMEM;
			}
			win->control = devm_ioremap_resource(extender->dev, res);
			if (IS_ERR(win->control))
				return PTR_ERR(win->control);

			//res = lookup_resource(&iomem_resource, res->start);
			//if (!res) {
			//	dev_err(&pdev->dev, "resource lookup failure\n");
			//	return -ENOMEM;
			//}

			dev_dbg(extender->dev, "CSR VA %px PA %llx - %llx\n",
				win->control, res->start, res->start + resource_size(res));
		}

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

	dev_info(extender->dev, "\n");
	dev_info(extender->dev, "PGDIR_SIZE %lx PUD_SIZE %lx PMD_SIZE %lx PAGE_SIZE %lx\n",
		PGDIR_SIZE, PUD_SIZE, PMD_SIZE, PAGE_SIZE);
	dev_info(extender->dev, "mb: PAGE_OFFSET %lx - PAGE_END %lx\n", PAGE_OFFSET, PAGE_END);
	dev_info(extender->dev, "mb: KIMAGE_VADDR %lx MODULES_VADDR %lx MODULES_END %lx\n",
		KIMAGE_VADDR, MODULES_VADDR, MODULES_END);
	dev_info(extender->dev, "mb: VMALLOC_START %lx VMALLOC_END %lx\n",
		VMALLOC_START, VMALLOC_END);
	dev_info(extender->dev, "mb: EXTENDER_START %lx EXTENDER_END %lx\n",
		EXTENDER_START, EXTENDER_END);
	dev_info(extender->dev, "mb: FIXADDR_START %lx FIXADDR_END %lx\n",
		FIXADDR_START, FIXADDR_TOP);
	dev_info(extender->dev, "mb: PCI_IO_START %lx PCI_IO_END %lx PCI_IO_SIZE %x\n",
		PCI_IO_START, PCI_IO_END, (unsigned)PCI_IO_SIZE);
	dev_info(extender->dev, "mb: VMEMMAP_START %lx VMEMMAP_END %lx VMEMMAP_SIZE %lx\n",
		VMEMMAP_START, VMEMMAP_START + VMEMMAP_SIZE, VMEMMAP_SIZE);
	dev_info(extender->dev, "mb: STRUCT_PAGE_MAX_SHIFT %x sizeof(struct page) %lx\n",
		STRUCT_PAGE_MAX_SHIFT, sizeof(struct page));

#if 0 /* Some diagnostics */
{
	struct window_struct *win;
	list_for_each_entry(win, &(extender->el1.free_list), list)
		dev_info(extender->dev, "el1: free_list[%d]: phys_addr %llx size %lx CSR %px",
			win->win_num, win->phys_addr, win->size, win->control);

	list_for_each_entry(win, &(extender->el0.free_list), list)
		dev_info(extender->dev, "el0: free_list[%d]: phys_addr %llx size %lx CSR %px",
			win->win_num, win->phys_addr, win->size, win->control);
}
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
		extender->area_extender->faulting_addr + 0x4000000000);
	(void)readl(extender->area_extender->faulting_addr + 0x4000000000);

	dev_dbg(extender->dev, "readl(%px)\n",
		extender->area_extender->faulting_addr + 0x8000000000);
	(void)readl(extender->area_extender->faulting_addr + 0x8000000000);
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

arch_initcall(extender_init);
//subsys_initcall(extender_init);
//module_platform_driver(intel_extender_driver);
MODULE_AUTHOR("Marek Bykowski <marek.bykowski@gmail.com>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Memory Span Extender");
