// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2021 INTEL

#ifndef _INTEL_EXTENDER_H_
#define _INTEL_EXTENDER_H_

struct intel_extender {
	struct device *dev;
	struct vm_struct *area_extender;
	void __iomem *control, *windowed_slave;
	unsigned long windowed_size;
	int (*map_op)(struct intel_extender *, unsigned long,
		      unsigned int, struct pt_regs *);
};

#endif
