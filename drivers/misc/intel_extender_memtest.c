// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2021 INTEL

#define DEBUG

#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/of_platform.h>
#include <linux/intel_extender.h>
#include <asm/io.h>
#include <linux/intel_extender_memtest.h>
 #include <linux/delay.h>




static void intel_extender_do_memtest(void *info)
{
	volatile int lp;
	struct intel_extender_memtest *extender_memtest;
	extender_memtest = info;

	if(extender_memtest->target_cpu == smp_processor_id())
	{
		dev_info(extender_memtest->dev, "thread bonded to CPU %d testing 0x%llx:(0x%llx)\n",
				extender_memtest->target_cpu,
				extender_memtest->ramtest_base_address,
				extender_memtest->ramtest_len);
	}

	for(lp=0; lp < 20;lp++){
		usleep_range(1000,1010);
		printk("%d %d\n",extender_memtest->target_cpu,smp_processor_id());
	}

}

static int intel_extender_memtest_probe(struct platform_device *pdev)
{
	void __iomem *base;
	struct intel_extender_memtest *extender_memtest;
	u64 ram_address_space[2] = {0};
	u32 target_cpu[1];


	dev_info(&pdev->dev, "Memory Test Client\n");
	dev_dbg(&pdev->dev, "Number of resources %d", pdev->num_resources);

	extender_memtest = devm_kzalloc(&pdev->dev, sizeof(*extender_memtest), GFP_KERNEL);
		if (!extender_memtest) {
			dev_err(extender_memtest->dev, "memory allocation failed\n");
			return -ENOMEM;
		}

	extender_memtest->dev = &pdev->dev;

	/*
	 * Each driver wanting using the 'extender' has to know the address
	 * the 'great virt area' starts. The idea exercised here is
	 * the 'extender' driver populates the client device/s setting
	 * the address in the platform_data field of device struct
	 * for the client device/s.
	 *
	 * Other options are available as well. Pass it throught the global
	 * static variable, examples of which may also be seen in the kernel.
	 */
	base = *(void __iomem **)(extender_memtest->dev)->platform_data;
	dev_dbg(extender_memtest->dev, "base is %lx\n", (unsigned long)base);


	/* Get FPGA address space */
	if (of_property_read_u64_array(extender_memtest->dev->of_node,
				       "ram_address_space",
				       ram_address_space,
				       ARRAY_SIZE(ram_address_space))) {
		dev_err(extender_memtest->dev, "failed to get ram memory range\n");
		return -EINVAL;
	}

	extender_memtest->ramtest_base_address = ram_address_space[0];
	extender_memtest->ramtest_len = ram_address_space[1];


	dev_dbg(extender_memtest->dev, "Testing ram space from 0x%llx (0x%llx bytes)\n",
			extender_memtest->ramtest_base_address, extender_memtest->ramtest_len);

	/* Get FPGA address space */
	if (of_property_read_u32_array(extender_memtest->dev->of_node,
				       "target_cpu",
				       target_cpu,
				       ARRAY_SIZE(target_cpu))) {
		dev_err(extender_memtest->dev, "failed to get target CPU\n");
		return -EINVAL;
	}

	extender_memtest->target_cpu = target_cpu[0];
	on_each_cpu(intel_extender_do_memtest, extender_memtest, 0);


	return 0;
}

static const struct of_device_id intel_extender_memtest_matches[] = {
	{ .compatible = "intel,extender-memtest", },
	{},
};
MODULE_DEVICE_TABLE(of, intel_extender_memtest_matches);

static struct platform_driver extender_client_memtest_driver = {
	.driver = {
		   .name = "intel-extender-memtest",
		   .of_match_table = intel_extender_memtest_matches,
		   .owner = THIS_MODULE,
		  },
	.probe = intel_extender_memtest_probe,
};

module_platform_driver(extender_client_memtest_driver);
MODULE_AUTHOR("Kris Chaplin <kris.chaplin@linux.intel.com>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Memory Span Extender Memory Test Client");
