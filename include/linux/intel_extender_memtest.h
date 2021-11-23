// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2021 INTEL

#ifndef _INTEL_EXTENDER_MEMTEST_H_
#define _INTEL_EXTENDER_MEMTEST_H_

struct intel_extender_memtest {
	struct device *dev;
	u64 ramtest_base_address[4];
	u64 ramtest_len[4];
	u32 target_cpu[4];
//	struct vm_struct *area_extender;
//	void __iomem *control, *windowed_slave;
//	unsigned long windowed_size;
//	int (*map_op)(struct intel_extender *, unsigned long,
//		      unsigned int, struct pt_regs *);
};

#endif
