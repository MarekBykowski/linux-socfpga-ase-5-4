// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2021 INTEL

#ifndef _INTEL_EXTENDER_H_
#define _INTEL_EXTENDER_H_

#ifdef CONFIG_INTEL_EXTENDER

struct intel_extender_pool {
	unsigned long addr;
	struct list_head node;
};

struct intel_extender {
	struct device *dev;
	struct extender_struct *area_extender;
	void __iomem *control, *windowed_slave;
	unsigned long windowed_size;
	spinlock_t lock;
	struct list_head allocated;
	struct list_head free;
	struct intel_extender_pool *window;
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
