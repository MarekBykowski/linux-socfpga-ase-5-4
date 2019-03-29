/*
 *
 * SMC testing module
 *
 * Copyright (C) 2019 Intel Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/of.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/linkage.h>
#include <linux/axxia-oem.h>
#include <linux/uaccess.h>
#include <linux/arm-smccc.h>
#include <asm/smp_plat.h>
#include <linux/seq_file.h>
#include <uapi/linux/psci.h>

#define SMC_DEBUG 0
#if SMC_DEBUG
#define smc_dbg(...) pr_info(__VA_ARGS__)
#define seq_printf(...)
#define seq_puts(...)
#else
#define smc_dbg(...)
#define seq_printf(arg0, ...) seq_printf(arg0, __VA_ARGS__)
#define seq_puts(arg0, ...) seq_puts(arg0, __VA_ARGS__)
#endif

struct _pt_regs {
	unsigned long elr;
	unsigned long regs[31];
};

typedef void (*smc_cb_t)(void *);

static bool all_cpus;
module_param(all_cpus, bool, 0644);
MODULE_PARM_DESC(all_cpus, "Run smc call on executing or all cpus (default: all");

void smc_call_v10(void *arg);
void smc_call_v11(void *arg);

smc_cb_t smc_call[] = {
	smc_call_v10,
	smc_call_v11
};

#define SMC_VARIANTS ARRAY_SIZE(smc_call)
#define SMC_VARIANT(n) n
#define for_each_smc(smc) \
	for ((smc) = 0; (smc) < SMC_VARIANTS; (smc)++)

unsigned long __percpu *time[SMC_VARIANTS];

/* SMCCC 1.0 */
void smc_call_v10(void *arg)
{
	struct pt_regs _regs = {0}, *regs = &_regs;
	int smc = *(unsigned int *)arg;
	struct arm_smccc_res res;
	ktime_t start, end;

	regs->regs[0] = PSCI_0_2_FN_PSCI_VERSION;

	start = ktime_get();
	arm_smccc_smc(regs->regs[0], regs->regs[1], regs->regs[2],
				  regs->regs[3], 0, 0, 0, 0, &res);
	end = ktime_get();

	this_cpu_write(*time[smc], ktime_to_ns(ktime_sub(end, start)));
	smc_dbg("cpu%d %lu ns (ret %#lx)\n",
				smc,
				this_cpu_read(*time[smc]),
				res.a0);
}

/*  SMCCC 1.1 */
void smc_call_v11(void *arg)
{
	int smc = *(unsigned int *)arg;
	ktime_t start, end;

	start = ktime_get();
	arm_smccc_1_1_smc(ARM_SMCCC_ARCH_WORKAROUND_1, NULL);
	end = ktime_get();

	this_cpu_write(*time[smc], ktime_to_ns(ktime_sub(end, start)));
	smc_dbg("cpu%d %lu ns (ret %s)\n",
				smc,
				this_cpu_read(*time[smc]),
				"RET0 in smc call");
}

void
zeroise_times(void)
{
	int cpu, smc;

	for_each_smc(smc) {
		for_each_online_cpu(cpu) {
			*per_cpu_ptr(time[smc], cpu) = 0;
		}
	}
}

static void run_test(void)
{
	int smc;

	/* init the smc call regs before the next call round */
	zeroise_times();

	switch (all_cpus) {
	case true:
		for_each_smc(smc) {
			int cpu;

			for_each_online_cpu(cpu) {
				int ret;

				ret = smp_call_function_single(cpu, smc_call[smc],
						 (void *)&smc, 1);
				if (ret)
					WARN_ON(ret);
			}
		}
		break;
	case false:
		for_each_smc(smc)
			smc_call[smc]((void *)&smc);
		break;
	}
}


static int proc_smc_show(struct seq_file *m, void *v)
{
	int smc;

	run_test();

	for_each_smc(smc) {
		int cpu;

		seq_printf(m, "SMC_VARIANT(%u): %pf\n", smc, smc_call[smc]);
		for_each_online_cpu(cpu)
			seq_printf(m, "CPU%-2d ", cpu);
		seq_puts(m, "\n");
		for_each_online_cpu(cpu)
			seq_printf(m, "%-5lu ",
				*per_cpu_ptr(time[SMC_VARIANT(smc)], cpu));
		seq_puts(m, "\n");
	}

	return 0;
}

static int proc_smc_open(struct inode *inode, struct file *file);
static const struct file_operations proc_smc_operations = {
	.open		= proc_smc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int proc_smc_open(struct inode *inode, struct file *file)
{
	return single_open(file, proc_smc_show, NULL);
}

static struct proc_dir_entry *procent;
static int __init proc_dma_init(void)
{
	procent = proc_create("axxia_smccall", 0444, NULL,
					&proc_smc_operations);
	return 0;
}


static int __init smctest_init(void)
{
	unsigned int smc;

	for_each_smc(smc)
		time[smc] = alloc_percpu(unsigned long);

	zeroise_times();
	proc_dma_init();

	return 0;
}
late_initcall(smctest_init);

static void __exit dmatest_exit(void)
{
	unsigned int smc;

	for_each_smc(smc)
		if (time[smc]) {
			free_percpu(time[smc]);
			time[smc] = NULL;
		}

	if (procent) {
		proc_remove(procent);
		procent = NULL;
	}
}

module_exit(dmatest_exit);

MODULE_AUTHOR("Marek Bykowski");
MODULE_LICENSE("GPL v2");
