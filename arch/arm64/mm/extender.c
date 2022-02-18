// SPDX-License-Identifier: GPL-2.0
/*
 * Page table mapping serving the address span extender.
 */
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

extern void show_pte(unsigned long addr);

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
		new = (pte_t *)__get_free_page(GFP_ATOMIC | __GFP_ZERO);
		if (!new)
			return -ENOMEM;

		smp_wmb(); /* See comment below */

		/* We must serialize populating for it */
		if (likely(pmd_none(*pmd))) {	/* Has another populated it ? */
			pmd_populate_kernel(&init_mm, pmd, new);
			dsb(ishst);
			isb();
			new = NULL;
		}
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
		phys_addr_t phys_pmd;
		pud_t pud_val;

		pmd = (pmd_t *)__get_free_page(GFP_ATOMIC | __GFP_ZERO | __GFP_ACCOUNT);
		if (!pmd)
			return -ENOMEM;

		/* __asm volatile("ishst") - ISB for inner sharable, store-store */
		smp_wmb();

		/* We must serialize populating for it */
		phys_pmd = __pa(pmd);
		pud_val = __pud(__phys_to_pud_val(phys_pmd) | PMD_TYPE_TABLE);
		WRITE_ONCE(*pud, pud_val);
		dsb(ishst);
		isb();
	}
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
		phys_addr_t phys_pud;
		pgd_t pgd_val;
		/*
		 * No PUD - allocate for it. As with page tables the PUD takes
		 * main memory and we allocate for it using the buddy allocator.
		 * 'Normally' such allocation can sleep eg. for reclaiming,
		 * but we cannot as we may be called from irq (hard) context.
		 * Pass the allocator GFP_ATOMIC ensuring it won't sleep and
		 * is as fast as it can be.
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
	#if 0
		/* We must serialize populating for it. */
		pgd_populate(&init_mm, pgd, pud);
	#else
		/* pgd_populate but spinlock-less. */
		phys_pud =__pa(pud);
		pgd_val = __pgd(__phys_to_pgd_val(phys_pud) | PUD_TYPE_TABLE);
		if (in_swapper_pgdir(pgd)) {
			pgd_t *fixmap_pgdp;

			fixmap_pgdp = pgd_set_fixmap(__pa_symbol(pgd));
			WRITE_ONCE(*fixmap_pgdp, pgd_val);
			/*
			 * We need dsb(ishst) here to ensure the page-table-walker sees
			 * our new entry before set_p?d() returns. The fixmap's
			 * flush_tlb_kernel_range() via clear_fixmap() does this for us.
			 */
			pgd_clear_fixmap();
		} else {
			WRITE_ONCE(*pgd, pgd_val);
			dsb(ishst);
			isb();
		}
	#endif

	}

	/*
	 * mb: Note!!! Fix double maping: probably I put before a broken logic,
	 * namely post pgd alloc we should find an offset. If pgd_present we
	 * should also find offset. So that that code should execute
	 * unconditionally. Leave this comment for a while while testing,
	 * then remove.
	 */

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

#if 0
#include <linux/intel_extender.h>
#include <linux/kallsyms.h>

#undef pgd_offset_k
#define pgd_offset_k(addr)						\
({									\
	if (unlikely(__is_in_extender(addr))) {				\
		char buf[KSYM_NAME_LEN] = {0};				\
									\
		sprint_symbol_no_offset(buf, _RET_IP_);			\
		/* If extender virt. area used by anybody else but us	\
		 * warn on.*/							\
		WARN(strncmp(buf, "extender_map", strlen("extender_map")),	\
		     "extender: illigal use of the extender virt. area %pf\n",	\
		     (void *)_RET_IP_);						\
	}								\
	pgd_offset(&init_mm, addr);					\
})
#endif

int extender_page_range(unsigned long addr, unsigned long end,
			phys_addr_t phys_addr, pgprot_t prot,
			void const *caller)
{
	pgd_t *pgd;
	unsigned long start;
	unsigned long next;
	int err;
	char buf[KSYM_NAME_LEN] = {0};

	BUG_ON(addr >= end);

	sprint_symbol_no_offset(buf, (unsigned long)caller);
	WARN(0 != strncmp(buf, "intel_extender_probe", strlen("intel_extender_probe")),
	     "extender: illegal allocation to extender area: offending caller %pf\n",
	     (void *)_RET_IP_);

	if (0 == strncmp(buf, "intel_extender_probe", strlen("intel_extender_probe")))
		;//pr_info("intel_extender_probe called me -> ok\n");

	start = addr;
	pgd = pgd_offset_k(addr);
	do {
		next = pgd_addr_end(addr, end);
		err = extender_pud_range(pgd, addr, next, phys_addr, prot);
		if (err)
			break;
	} while (pgd++, phys_addr += (next - addr), addr = next, addr != end);

	/*
	 show_pte(start);
	 display_mapping(start, false);
	 */

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

struct extender_struct *get_extender_area(unsigned long virt_size)
{
	struct extender_struct *area;

	area = kzalloc(sizeof(*area), GFP_KERNEL);
	if (IS_ERR(area))
		return NULL;

	area->addr = EXTENDER_START;
	area->size = virt_size;

	pr_info("mb: area->addr %lx area->size %lx EXTENDER_END %lx\n",
		area->addr, area->size, EXTENDER_END);
	/* Bug on if we go over the extender area. */
	BUG_ON(area->addr + area->size >= EXTENDER_END);
	area->caller = (void *)_RET_IP_;
	/*
	 * The remaining fields are of no use for now but may be we will use
	 * it in the future when (and if) we being vm machinery in.
	 */
	return area;
}

/*
 * It may be called when removing the driver. Will this ever happen?!
 */
void release_extender_area(struct extender_struct *area)
{
	kfree(area);
	return;
}

bool display_mapping(unsigned long addr, bool print)
{
	unsigned long par_el1;

	if (print)
		pr_info("----- Translating VA 0x%lx\n", addr);

	__asm__ __volatile__ ("at s1e0r, %0" : : "r" (addr));
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
		return true;
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
		return false;
	}
	return false;
}
