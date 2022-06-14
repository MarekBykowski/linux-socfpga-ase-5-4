// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2021 INTEL

#ifndef _INTEL_EXTENDER_H_
#define _INTEL_EXTENDER_H_

#if IS_ENABLED(CONFIG_INTEL_EXTENDER)

#ifdef DEBUG
#include <asm/stacktrace.h> /* For struct stackframe */
#define extender_trace_call(frames, fmt, ...)	\
	do {	\
		/*dump_backtrace(NULL, NULL);*/	\
		struct stackframe frame;	\
		struct task_struct *tsk = current;	\
		int i;	\
	\
		start_backtrace(&frame,	\
				(unsigned long)__builtin_frame_address(0),	\
				(unsigned long)_THIS_IP_);	\
	\
		pr_debug("extender trace call:\n");	\
		pr_debug("1: %pS args: " fmt, (void *)frame.pc, ##__VA_ARGS__);	\
		unwind_frame(tsk, &frame);	\
	\
		for (i = 2; i <= frames; i++) {	\
			pr_debug("%d: %pS\n", i, (void *)frame.pc);	\
			unwind_frame(tsk, &frame);	\
		}	\
	} while(0)
#else
#define extender_trace_call(frames, fmt, ...)	do {} while(0)
#endif

/*
 * This is a lousy attempt at ensuring only the extender mapper uses the
 * extender area. It takes advantage of the _RET_IP_ returning the address of
 * the calling function. From the addr we figure out symbolic name of the
 * function and if != function_names[] we WARN.
 *
 * Any failure in adding a function name to the function_names array will
 * result in a failure in properly handling it. Therefore we take the way we
 * secure the extender area is far from perfect.
 */
#ifdef LOUSY_GO_AT_SECURING_EXTENDER_AREA
#include <linux/kallsyms.h>

#undef pgd_offset_k
#define pgd_offset_k(addr)						\
({									\
	if (unlikely(__is_in_extender(addr))) {				\
		int i;							\
		bool found = false;					\
		char buf[KSYM_NAME_LEN] = {0};				\
		char *function_names[] = { "intel_extender", "extender_page" };	\
									\
		sprint_symbol_no_offset(buf, _RET_IP_);			\
		for (i = 0; i < ARRAY_SIZE(function_names); i++)	\
			if (strnstr(buf, function_names[i], strlen(function_names[i])))	\
				found = true;				\
									\
		WARN(found == false, "extender: illegal use of extender area. Offender: %ps\n",	\
		     (void *)_RET_IP_);						\
	}								\
	pgd_offset(&init_mm, addr);					\
})
#endif

struct window_struct {
	unsigned win_num;
	/* It is an actual virt addr accessed */
	void __iomem *faulting_addr;
	/*
	 * This one in contrast is an addr the mapping starts from.
	 * Example: if a faulting addr is ffff_bd80_0008_3060 (ttbr1)
	 * mapping one is the boundary start:
	 *
	 *  ffff_bd80_0008_3060 (faulting) &
	 *	ffff_ffff_ff00_0000 (window_mask) =
	 *		ffff_bd80_0000_0000 (mapping addr)
	 *
	 * All the above applies to el1.
	 *
	 * For el0 the fault system page masks the faulting addr before our
	 * handler is called and thus the mapping and faulting addresses
	 * are the same there.
	 */
	void __iomem *mapping_addr;
	struct mm_struct *mm;
	pid_t pid;
	unsigned long size;
	unsigned long flags;
	unsigned int nr_pages;
	phys_addr_t phys_addr;
	void const *caller;
	void __iomem *control;
	struct list_head list;
};

struct extender_el1 {
	void __iomem *extender_start;		/* el1 virt area start (EXTENDER_START)*/
	unsigned long extender_size;		/* el1 virt area size (EXTENDER_SIZE) */
	spinlock_t lock;		/* serialize el1 pagefaults */
	struct list_head free_list;	/* list head for free_list */
	struct list_head allocated_list;/* list head for allocated */
};

struct extender_el0 {
	struct mutex lock;		/* serialize el0 pagefaults */
	struct list_head free_list;	/* see comments above */
	struct list_head allocated_list;
};

struct extender {
	struct device *dev;
	struct window_struct *window;
	struct extender_el1 el1;
	struct extender_el0 el0;
};

extern int intel_extender_el1_fault(unsigned long addr,
			unsigned int esr,
			struct pt_regs *regs);
vm_fault_t intel_extender_el0_fault(struct vm_fault *vmf);
extern const struct file_operations intel_extender_el0_fops;
extern const struct vm_operations_struct intel_extender_el0_ops;
extern inline bool is_ttbr0_addr(unsigned long addr);
#else
static inline int intel_extender_el1_fault(unsigned long addr,
			       unsigned int esr,
			       struct pt_regs *regs)
{ return -ENODEV; }
static vm_fault_t __maybe_unused intel_extender_el0_fault(struct vm_fault *vmf)
{ return VM_FAULT_SIGBUS; }
#define extender_trace_call(frames, fmt, ...)	do {} while(0)
#endif

#endif /*_INTEL_EXTENDER_H_*/
