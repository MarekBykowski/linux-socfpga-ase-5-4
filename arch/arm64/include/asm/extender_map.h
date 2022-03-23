/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __ASM_EXTENDER_MAP_H
#define __ASM_EXTENDER_MAP_H

#include <linux/compiler.h>
#include <linux/types.h>
#include <asm/pgtable-hwdef.h>

/*
 *              |--pgdir_size--|--pgdir_size--|--pgdir_size--|
 *              |              |              |        ^     |
 *          pgd[x-2]         pgd[x-1]       pdg[x]     |  pgd[x+1]
 *					               |
 * If -(pud_size) -(vmemmap_size) -(guard gap) (*)     |
 *     gets us to address 'addr' here ------------------
 * then we must ALIGN_DOWN('addr', pgdir_size) that 'addr' getting us to
 * pgd[x] and then subtract N pgds so that [pgd[x-N], pgd[x]) is just ours
 * (note "[" and ")" brackets, in which the former indicates inclusion,
 * the later exclusion).
 *
 * (*) When converting negative to unsigned long (UNSIGNED_LONG_MAX + 1) gets
 * added to a negative number until ending up in a range of unsigned long.
 * Effectively -0x8000 is 0xffff_ffff_ffff_f8000, -1 is 0xffff_ffff_ffff_ffff and
 * so on. This is a clever way of computing offsets off the top boundary.
 */

#define EXTENDER_END	ALIGN_DOWN((- PUD_SIZE - VMEMMAP_SIZE - SZ_64K), \
				PGDIR_SIZE)
#define EXTENDER_START	(EXTENDER_END - 128 * PGDIR_SIZE)

#define __is_in_extender(addr)	(((u64)(addr) >= EXTENDER_START) && \
				(((u64)(addr)) < EXTENDER_END))

#define __is_in_extender_index(__pgd_index) \
	((__pgd_index >= pgd_index(EXTENDER_START)) && \
	 (__pgd_index < pgd_index(EXTENDER_END)))

/*
 * The macros below are used to intercept ioremap() family calls and return
 * early with an address from the extender map. The mapping proper is done
 * in the fault handler.
 */
#define EXTENDER_PHYS_FLAG_SHIFT	47
#define EXTENDER_PHYS_FLAG_RAISE	(_AC(1, UL) << EXTENDER_PHYS_FLAG_SHIFT)
#define EXTENDER_PHYS_MASK		(EXTENDER_PHYS_FLAG_RAISE - 1)

/* The min. window size is page_size, set for maximum. */
#define EXTENDER_WINDOW_MAX_SIZE	SZ_128M

#ifndef __ASSEMBLY__

int extender_page_range(unsigned long addr, unsigned long end,
			phys_addr_t phys_addr, pgprot_t prot,
			void const *caller);
void extender_unmap_page_range(unsigned long addr, unsigned long end);
struct extender_struct *get_extender_area(unsigned long virt_size);
__noclone __maybe_unused bool display_mapping(unsigned long address,
					      bool print);

#endif /* !__ASSEMBLY__ */

#endif /*__ASM_EXTENDER_MAP_H*/
