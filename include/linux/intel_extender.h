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

struct extender_el1 {
	void __iomem *addr;		/* el1 EXTENDER_START virt area */
	unsigned long size;		/* el1 EXTENDER_SIZE virt area */
	spinlock_t lock;		/* serialize el1 pagefaults */
	struct list_head free_list;
	struct list_head allocated_list;
};

struct extender_el0 {
	struct mutex lock;		/* serialize el0 pagefaults */
	struct list_head free_list;
	struct list_head allocated_list;
};

struct extender {
	struct device *dev;
	struct window_struct *window;
	struct extender_el1 el1;
	struct extender_el0 el0;
};

extern int extender_map(unsigned long addr,
			unsigned int esr,
			struct pt_regs *regs);

extern inline bool is_ttbr0_addr(unsigned long addr);
extern inline bool is_ttbr1_addr(unsigned long addr);
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
