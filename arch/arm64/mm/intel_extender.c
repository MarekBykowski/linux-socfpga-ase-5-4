// SPDX-License-Identifier: GPL-2.0
/*
 * Page table mapping serving the address span extender.
 */

//#define DEBUG
//#define LOUSY_GO_AT_SECURING_EXTENDER_AREA

#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/io.h>
#include <linux/export.h>
#include <linux/spinlock.h>
#include <asm/cacheflush.h>
#include <asm/pgtable.h>
#include <asm/pgalloc.h>
#include <linux/kallsyms.h> /* KSYM_NAME_LEN */
#include <linux/intel_extender.h>

#ifdef DEBUG
static inline void race_test_for_pte(pte_t *ptep, phys_addr_t phys_addr,
				       pgprot_t prot)
{
	u64 pfn = phys_addr >> PAGE_SHIFT;

	if (pte_none(READ_ONCE(*ptep)))
		return;

	/*
	 * pte is present. Check if it is equal to one we write or
	 * different but not zero.
	 */
	if (pte_same(READ_ONCE(*ptep), READ_ONCE(pfn_pte(pfn, prot)))) {
		pr_debug("pte_same: pte %016llx@%px PA %pa",
			 pte_val(READ_ONCE(*ptep)), ptep, &phys_addr);
	} else {
		pr_debug("!pte_same but old wasn't zero: pte old=%016llx pte new%016llx@%px PA %pa\n",
			 pte_val(READ_ONCE(*ptep)),
			 pte_val(READ_ONCE(pfn_pte(pfn, prot))),
			 ptep, &phys_addr);
	}
}
#else
static inline void race_test_for_pte(pte_t *ptep, phys_addr_t phys_addr,
				       pgprot_t prot)
{ return; }
#endif

int extender_pte_range(pmd_t *pmd, unsigned long addr,
		       unsigned long end, phys_addr_t phys_addr,
		       pgprot_t prot)
{
	pte_t *ptep, *new;
	u64 pfn;

	pfn = phys_addr >> PAGE_SHIFT;

	/*
	 * From start >>> thr <<< end is a sleep-lock less counterpart for
	 * 'pte_alloc_kernel(pmd, address)'. We, in contrast to the 'regular'
	 * translation table allocation, cannot sleep as may be called
	 * from hard irq context.
	 *
	 * Extender's clients are the only users of these routines.
	 *
	 * Note: you may want to sync it up with the pte_alloc_kernel().
	 * pte_alloc_kernel() are upstream maintained, this may not.
	 */
	/* start >>> */
	if (likely(pmd_none(*pmd))) {
		/*
		 * No pte table - allocate for it. As with each entry is
		 * also the case for pte that the kernel allocates for it
		 * from the main memory and that the buddy allocator is used
		 * for it. As mentioned before we can not sleep so we pass
		 * GFP_ATOMIC ensuring the allocation won't sleep and will
		 * be as fast as possible.
		 */
		new = (pte_t *)__get_free_page(GFP_ATOMIC | __GFP_ZERO);
		if (!new)
			return -ENOMEM;

		smp_wmb(); /* See comment below */

		/*
		 * While we are on PMD we must shout out loudly
		 * we do not support PMD folded.
		 *
		 * PMD folded is supported on ARM only if PGTABLE_LEVELS is
		 * two. It is two only if either is met:
		 * - ARM64_16K_PAGES && ARM64_VA_BITS_36
		 * - ARM64_64K_PAGES && ARM64_VA_BITS_42
		 *
		 * In other words it is not supported under 'normal'
		 * conditions.
		 */
		BUILD_BUG_ON(__is_defined(__PAGETABLE_PMD_FOLDED));

		/*
		 * Load a pmd entry with the physical addr of
		 * the newly created pte table.
		 */
		pmd_populate_kernel(&init_mm, pmd, new);
		dsb(ishst);
		isb();
	}

	/* Pmd exists. Read it - it will tell you where the pte table is. */
	ptep = pte_offset_kernel(pmd, addr);
	/* <<< end */

	if (!ptep)
		return -ENOMEM;

	do {
		race_test_for_pte(ptep, phys_addr, prot);

		/*
		 * We have tested above if pte is zero and only notified if
		 * true. If the entry is the same break, no point in
		 * re-writing the same value.
		 */
		if (pte_same(READ_ONCE(*ptep), READ_ONCE(pfn_pte(pfn, prot))))
			break;

		BUG_ON(!pte_none(*ptep));
		/*
		 * From armv8 TRM: The proper sequence for writes to
		 * translation tables backed by inner shareable memory
		 * shall be:
		 * - populate pte
		 * - ensure write has completed (DSB ISHST)
		 * - flush_tlb
		 * - ensure completion of TLB flushing (DSB ISH)
		 * - ISB synchronize context and ensure that no instructions
		 *   are fetched using the old translation
		 */
		set_pte_at(&init_mm, addr, ptep, pfn_pte(pfn, prot));
		dsb(ishst);
		flush_tlb_kernel_range(addr, addr + PAGE_SIZE);
		dsb(ish);
		isb();
		pfn++;
	} while (ptep++, addr += PAGE_SIZE, addr != end);

	return 0;
}

int extender_pmd_range(pud_t *pud, unsigned long addr,
		unsigned long end, phys_addr_t phys_addr, pgprot_t prot)
{
	pmd_t *pmd;
	unsigned long next;

	/*
	 * From start >>> thr <<< end is a sleep-lock less counterpart for
	 * 'pmd_alloc(&init_mm, pud, addr)'.
	 *
	 * See comment above.
	 */
	/* start >>> */
	if (unlikely(pud_none(*pud))) {
		phys_addr_t phys_pmd;
		pud_t pud_val;

		pmd = (pmd_t *)__get_free_page(GFP_ATOMIC | __GFP_ZERO |
					       __GFP_ACCOUNT);
		if (!pmd)
			return -ENOMEM;

		/* Make sure all the stores are seen before going further */
		smp_wmb();

		phys_pmd = __pa(pmd);
		pud_val = __pud(__phys_to_pud_val(phys_pmd) | PMD_TYPE_TABLE);
		WRITE_ONCE(*pud, pud_val);
		dsb(ishst);
		isb();
	}

	pmd = pmd_offset(pud, addr);
	/* <<< end */

	if (!pmd)
		return -ENOMEM;
	do {
		next = pmd_addr_end(addr, end);

		if (extender_pte_range(pmd, addr, next, phys_addr, prot))
			return -ENOMEM;
	} while (pmd++, phys_addr += (next - addr), addr = next, addr != end);

	return 0;
}

int extender_pud_range(pgd_t *pgd, unsigned long addr,
		unsigned long end, phys_addr_t phys_addr, pgprot_t prot)
{
	pud_t *pud;
	unsigned long next;

	/*
	 * From start >>> thr <<< end is a sleep-lock less counterpart for
	 * 'pud_alloc(&init_mm, pgd, addr)'.
	 *
	 * See comment above.
	 */
	/* start >>> */
	if (unlikely(pgd_none(*pgd))) {
		phys_addr_t phys_pud;
		pgd_t pgd_val;

		pud = (pud_t *)__get_free_page(GFP_ATOMIC | __GFP_ZERO |
					       __GFP_ACCOUNT);
		if (!pud)
			return -ENOMEM;

		phys_pud = __pa(pud);
		pgd_val = __pgd(__phys_to_pgd_val(phys_pud) | PUD_TYPE_TABLE);
		if (in_swapper_pgdir(pgd)) {
			pgd_t *fixmap_pgdp;

			fixmap_pgdp = pgd_set_fixmap(__pa_symbol(pgd));
			WRITE_ONCE(*fixmap_pgdp, pgd_val);
			pgd_clear_fixmap();
		} else {
			WRITE_ONCE(*pgd, pgd_val);
			dsb(ishst);
			isb();
		}
	}

	pud = pud_offset(pgd, addr);
	/* <<< end */

	do {
		next = pud_addr_end(addr, end);
		if (extender_pmd_range(pud, addr, next, phys_addr, prot))
			return -ENOMEM;
	} while (pud++, phys_addr += (next - addr), addr = next, addr != end);

	return 0;
}


/*
 * extender_page_range() follows the break-before-make.
 *
 * From Marc Zyngier <marc.zyngier@arm.com> "The ARM architecture mandates
 * that when changing a page table entry from a valid entry to another valid
 * entry, an invalid entry is first written, TLB invalidated, and only then
 * the new entry being written."
 *
 * extender_unmap_page_range() does the first two items for us, namely
 * writes an invalid entry aka clears it and flushes/invalidates the page
 * entry/ies. Therefore we install it into the mapping routine before
 * the mapping proper takes in.
 *
 * Also as an complementary one may see the comments in virt/kvm/arm/mmu.c on
 * the break-before-make searching for "Skip updating the page table".
 */
int extender_page_range(unsigned long addr, unsigned long end,
			phys_addr_t phys_addr, pgprot_t prot,
			void const *caller)
{
	pgd_t *pgd;
	unsigned long start;
	unsigned long next;
	int err = 0;

	BUG_ON(addr >= end);
	extender_unmap_page_range(addr, end);
	start = addr;

	pgd = pgd_offset_k(addr);
	do {
		next = pgd_addr_end(addr, end);
		err = extender_pud_range(pgd, addr, next, phys_addr, prot);
		if (err)
			break;
	} while (pgd++, phys_addr += (next - addr), addr = next, addr != end);

#ifdef DEBUG
	show_pte(start);
	dsb(ishst);
	flush_tlb_kernel_range(start, end);
	dsb(ish);
	isb();
	pr_debug("%s(%lx, %lx): is_mapped? %s\n",
		__func__, start, end,
		is_mapped(start, 1, true) ? "yes" : "no");
#endif

	return err;
}

void extender_unmap_pte_range(pmd_t *pmd, unsigned long addr, unsigned long end)
{
	pte_t *ptep;

	ptep = pte_offset_kernel(pmd, addr);
	do {
		pte_t pte = ptep_get_and_clear(&init_mm, addr, ptep);

		WARN_ON(!pte_none(pte) && !pte_present(pte));
	} while (ptep++, addr += PAGE_SIZE, addr != end);
}

void extender_unmap_pmd_range(pud_t *pud, unsigned long addr, unsigned long end)
{
	pmd_t *pmd;
	unsigned long next;

	pmd = pmd_offset(pud, addr);
	do {
		next = pmd_addr_end(addr, end);
		if (pmd_clear_huge(pmd))
			continue;
		if (pmd_none_or_clear_bad(pmd))
			continue;
		extender_unmap_pte_range(pmd, addr, next);
	} while (pmd++, addr = next, addr != end);
}

void extender_unmap_pud_range(pgd_t *pgd, unsigned long addr, unsigned long end)
{
	pud_t *pud;
	unsigned long next;

	pud = pud_offset(pgd, addr);
	do {
		next = pud_addr_end(addr, end);
		if (pud_clear_huge(pud))
			continue;
		if (pud_none_or_clear_bad(pud))
			continue;
		extender_unmap_pmd_range(pud, addr, next);
	} while (pud++, addr = next, addr != end);
}

void extender_unmap_page_range(unsigned long addr, unsigned long end)
{
	pgd_t *pgd;
	unsigned long next, start = addr;

	BUG_ON(addr >= end);
	pgd = pgd_offset_k(addr);
	do {
		next = pgd_addr_end(addr, end);
		if (pgd_none_or_clear_bad(pgd))
			continue;
		extender_unmap_pud_range(pgd, addr, next);
	} while (pgd++, addr = next, addr != end);
	flush_tlb_kernel_range(start, end);
}

inline bool is_mapped(unsigned long addr, int exception, bool print)
{
	unsigned long par_el1;
	bool ret = false;

	if (print)
		pr_info("----- Translating VA 0x%lx\n", addr);

	if (exception == 0)
		__asm__ __volatile__ ("at s1e0r, %0" : : "r" (addr));
	else
		__asm__ __volatile__ ("at s1e1r, %0" : : "r" (addr));

	__asm__ __volatile__ ("mrs %0, PAR_EL1\n" : "=r" (par_el1));

	if (0 != (par_el1 & 1)) {
		if (print == true)
			pr_info("Address Translation Failed: 0x%lx\n"
			"    FSC: 0x%lx\n"
			"    PTW: 0x%lx\n"
			"      S: 0x%lx\n",
			addr,
			(par_el1 & 0x7e) >> 1,
			(par_el1 & 0x100) >> 8,
			(par_el1 & 0x200) >> 9);
		ret = false;
	} else {
		if (print == true)
			pr_info("Address Translation Succeeded: 0x%lx\n"
			"  SH: 0x%lx\n"
			"  NS: 0x%lx\n"
			"  PA: 0x%lx\n"
			"ATTR: 0x%lx\n",
			addr,
			(par_el1 & 0x180) >> 7,
			(par_el1 & 0x200) >> 9,
			par_el1 & 0xfffffffff000,
			(par_el1 & 0xff00000000000000) >> 56);
		ret = true;
	}

	return ret;
}
