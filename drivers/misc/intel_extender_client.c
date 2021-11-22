// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2021 INTEL

#define DEBUG

#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/of_platform.h>
#include <linux/intel_extender.h>
#include <asm/io.h>

static int probe(struct platform_device *pdev)
{
	void __iomem *base;
	unsigned int value = 0x11111111;
	int three_regions = 0;

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
	base = *(void __iomem **)(&pdev->dev)->platform_data;
	dev_dbg(&pdev->dev, "base is %lx\n", (unsigned long)base);

	for (; three_regions < 3;
			three_regions++,
			base+=0x4000000000,
			value++) {

		dev_dbg(&pdev->dev, "writel-readl sequence[%d]: value %x@%lx",
			three_regions,	value, (unsigned long)base);

		/* Write then read back and check */
		writel(value, base);
		if (value != readl(base))
			goto failed;
	}

	three_regions++;
	value++;
	base = *(void __iomem **)(&pdev->dev)->platform_data;
	base +=0x200000000000;
	dev_dbg(&pdev->dev, "writel-readl sequence[%d]: value %x@%lx",
				three_regions,	value, (unsigned long)base);
	writel(value, base);
	if (value != readl(base))
		goto failed;

	dev_info(&pdev->dev, "test succeeded\n");
	return 0;

failed:
	dev_err(&pdev->dev, "test failed\n");
	return 0;
}

static const struct of_device_id intel_extender_matches[] = {
	{ .compatible = "intel,extender-client", },
	{},
};
MODULE_DEVICE_TABLE(of, intel_extender_matches);

static struct platform_driver extender_client_driver = {
	.driver = {
		   .name = "intel-extender-client",
		   .of_match_table = intel_extender_matches,
		   .owner = THIS_MODULE,
		  },
	.probe = probe,
};

module_platform_driver(extender_client_driver);
MODULE_AUTHOR("Marek Bykowski <marek.bykowski@gmail.com>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Memory Span Extender Client");
