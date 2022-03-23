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
	void __iomem *addr;
	unsigned long size;
	spinlock_t lock;
	struct list_head allocated_list;
	struct list_head free_list;
	struct window_struct *window;
};

extern int extender_map(unsigned long addr,
			unsigned int esr,
			struct pt_regs *regs);
#else
struct intel_extender {};
static inline int extender_map(unsigned long addr,
			       unsigned int esr,
			       struct pt_regs *regs)
{ return -ENODEV; }
#endif

#endif /*_INTEL_EXTENDER_H_*/
