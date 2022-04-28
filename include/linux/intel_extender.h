// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2021 INTEL

#ifndef _INTEL_EXTENDER_H_
#define _INTEL_EXTENDER_H_

#ifdef CONFIG_INTEL_EXTENDER

struct window_struct {
	unsigned win_num;
	void __iomem *addr;
	unsigned long size;
	unsigned long flags;
	unsigned int nr_pages;
	phys_addr_t phys_addr;
	void const *caller;
	void __iomem *control;
	struct list_head list;
};

struct extender {
	struct device *dev;
	void __iomem *addr_el1;
	unsigned long size;
	spinlock_t lock_el1;		/* serialize el1 pagefaults */
	struct mutex lock_el0;		/* serialize el0 pagefaults */
	struct window_struct *window;
	struct list_head free_list;
	struct list_head allocated_list;
	struct list_head free_list_el0;
	struct list_head allocated_list_el0;
};

extern int extender_map(unsigned long addr,
			unsigned int esr,
			struct pt_regs *regs);

extern const struct file_operations intel_extender_el0_fops;
extern const struct vm_operations_struct intel_extender_el0_ops;
vm_fault_t intel_extender_el0_fault(struct vm_fault *vmf);

#else
struct intel_extender {};
static inline int extender_map(unsigned long addr,
			       unsigned int esr,
			       struct pt_regs *regs)
{ return -ENODEV; }
#endif

#endif /*_INTEL_EXTENDER_H_*/
