// SPDX-License-Identifier: GPL-2.0
/*
 * Page table mapping serving the address span extender.
 */
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/io.h>
#include <linux/export.h>
#include <linux/spinlock.h>
#include <asm/cacheflush.h>
#include <asm/pgtable.h>
#include <asm/pgalloc.h>

extern void show_pte(unsigned long addr);
extern __noclone int display_mapping(unsigned long addr);

int extender_pte_range(pmd_t *pmd, unsigned long addr,
		unsigned long end, phys_addr_t phys_addr, pgprot_t prot)
{
	pte_t *ptep, *new;
	u64 pfn, pfn_count;

	pfn_count = pfn = phys_addr >> PAGE_SHIFT;
#if 0
	ptep = pte_alloc_kernel(pmd, addr);
#else
	if (unlikely(pmd_none(*(pmd)))) {
		unsigned long flags;

		new = (pte_t *)__get_free_page(GFP_ATOMIC | __GFP_ZERO);
		if (!new)
			return -ENOMEM;

		smp_wmb(); /* See comment below */

		spin_lock_irqsave(&init_mm.page_table_lock, flags);
		if (likely(pmd_none(*pmd))) {	/* Has another populated it ? */
			pmd_populate_kernel(&init_mm, pmd, new);
			new = NULL;
		}
		spin_unlock_irqrestore(&init_mm.page_table_lock, flags);
		if (new)
			pte_free_kernel(&init_mm, ptep);
	}

	ptep = pte_offset_kernel(pmd, addr);
#endif

	if (!ptep)
		return -ENOMEM;

	do {
		BUG_ON(!pte_none(*ptep));
		set_pte_at(&init_mm, addr, ptep, pfn_pte(pfn, prot));
		pfn++;
	} while (ptep++, addr += PAGE_SIZE, addr != end);

	return 0;
}

int extender_pmd_range(pud_t *pud, unsigned long addr,
		unsigned long end, phys_addr_t phys_addr, pgprot_t prot)
{
	pmd_t *pmd;
	unsigned long next;

#if 0
	pmd = pmd_alloc(&init_mm, pud, addr);
#else
	if (unlikely(pud_none(*pud))) {
		unsigned long flags;
		struct page *page = alloc_page(GFP_ATOMIC | __GFP_ZERO);

		if (!page)
			return -ENOMEM;
		if (!pgtable_pmd_page_ctor(page)) {
			__free_page(page);
			return -ENOMEM;
		}

		pmd = (pmd_t *)page_address(page);

		/* __asm volatile("ishst") - ISB for inner sharable, store-store */
		smp_wmb();

		spin_lock_irqsave(&init_mm.page_table_lock, flags);
		pud_populate(&init_mm, pud, pmd);
		spin_unlock_irqrestore(&init_mm.page_table_lock, flags);
	} else
		pmd = pmd_offset(pud, addr);
#endif

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

#if 0
	pud = pud_alloc(&init_mm, pgd, addr);
	if (!pud)
		return -ENOMEM;
#else
	if (unlikely(pgd_none(*pgd))) {
		unsigned long flags;
		/*
		 * No PUD - allocate for it. As with page tables the PUD takes
		 * main memory and we allocate for it using the buddy allocator.
		 * 'Normally' such allocation can sleep eg. for reclaiming,
		 * but we cannot as we may be called from irq (hard) context.
		 * Pass the allocator GFP_ATOMIC ensuring we won't sleep and
		 * are fast as we can.
		 *
		 * Note, there is no pgd_alloc (and friends) for ARM64.
		 * The reason is with translation tables with 4KB pages +
		 * 4 levels (48-bit) each level is up to 512 entries, each
		 * entry is 8 bytes giving it 4096 bytes (512*8), a single page.
		 * So that the pgd gets allocated only once and it surely far
		 * before us.
		 *
		 * And the last note, ARM refers to PUD as Level 1 of address lookup.
		 * PGD is Level 0, PMD - Level 2, PTE - Level 3.
		 */
		pud = (pud_t *)__get_free_page(GFP_ATOMIC | __GFP_ZERO | __GFP_ACCOUNT);
		if (!pud)
			return -ENOMEM;
		/*
		 * We must serialize populating for it. As it is possible we
		 * are mapping from hard (irq) context we must disable
		 * the interrupts for not being interrupted and re-acquiring
		 * the lock resulting in deadlock.
		 */
		spin_lock_irqsave(&init_mm.page_table_lock, flags);
		pgd_populate(&init_mm, pgd, pud);
		spin_unlock_irqrestore(&init_mm.page_table_lock, flags);
	} else
		/* PUD exists, find it */
		pud = pud_offset(pgd, addr);
#endif /*if 0*/

	do {
		next = pud_addr_end(addr, end);
		if (extender_pmd_range(pud, addr, next, phys_addr, prot))
			return -ENOMEM;
	} while (pud++, phys_addr += (next - addr), addr = next, addr != end);

	return 0;
}

int extender_page_range(unsigned long addr,
		       unsigned long end, phys_addr_t phys_addr, pgprot_t prot)
{
	pgd_t *pgd;
	unsigned long start;
	unsigned long next;
	int err;

	BUG_ON(addr >= end);

	start = addr;
	pgd = pgd_offset_k(addr);
	do {
		next = pgd_addr_end(addr, end);
		err = extender_pud_range(pgd, addr, next, phys_addr, prot);
		if (err)
			break;
	} while (pgd++, phys_addr += (next - addr), addr = next, addr != end);

	/*show_pte(addr);*/

	return err;
}

void extender_unmap_pte_range(pmd_t *pmd, unsigned long addr, unsigned long end)
{
	pte_t *pte;

	pte = pte_offset_kernel(pmd, addr);
	do {
		pte_t ptent = ptep_get_and_clear(&init_mm, addr, pte);
		WARN_ON(!pte_none(ptent) && !pte_present(ptent));
	} while (pte++, addr += PAGE_SIZE, addr != end);
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
	unsigned long next;

	BUG_ON(addr >= end);
	pgd = pgd_offset_k(addr);
	do {
		next = pgd_addr_end(addr, end);
		if (pgd_none_or_clear_bad(pgd))
			continue;
		extender_unmap_pud_range(pgd, addr, next);
	} while (pgd++, addr = next, addr != end);
}

int display_mapping(unsigned long addr)
{
	unsigned long par_el1;
	bool print = false;

	if (print)
		trace_printk("----- Translating VA 0x%lx\n", addr);

	__asm__ __volatile__ ("at s1e0r, %0" : : "r" (addr));
	__asm__ __volatile__ ("mrs %0, PAR_EL1\n" : "=r" (par_el1));

	if (0 != (par_el1 & 1)) {
		if (print == true)
			trace_printk("Address Translation Failed: 0x%lx\n"
			"    FSC: 0x%lx\n"
			"    PTW: 0x%lx\n"
			"      S: 0x%lx\n",
			addr,
			(par_el1 & 0x7e) >> 1,
			(par_el1 & 0x100) >> 8,
			(par_el1 & 0x200) >> 9);
		return -1;
	} else {
		if (print == true)
			trace_printk("Address Translation Succeeded: 0x%lx\n"
			"  SH: 0x%lx\n"
			"  NS: 0x%lx\n"
			"  PA: 0x%lx\n"
			"ATTR: 0x%lx\n",
			addr,
			(par_el1 & 0x180) >> 7,
			(par_el1 & 0x200) >> 9,
			par_el1 & 0xfffffffff000,
			(par_el1 & 0xff00000000000000) >> 56);
		return 0;
	}
	return 0;
}
