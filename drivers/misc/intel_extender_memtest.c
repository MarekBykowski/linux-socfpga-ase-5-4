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

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kdev_t.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include<linux/slab.h>                 //kmalloc()
#include<linux/uaccess.h>              //copy_to/from_user()
#include <linux/ioctl.h>

#define WR_VALUE _IOW('a','a',int32_t*)
#define RD_VALUE _IOR('a','b',int32_t*)

int32_t value = 0;
dev_t dev = 0;

static struct class *dev_class;
static struct cdev etx_cdev;
struct intel_extender_memtest *extender_memtest;

/*
** Function Prototypes
*/

static int      etx_open(struct inode *inode, struct file *file);
static int      etx_release(struct inode *inode, struct file *file);
static ssize_t  etx_read(struct file *filp, char __user *buf, size_t len,loff_t * off);
static ssize_t  etx_write(struct file *filp, const char *buf, size_t len, loff_t * off);
static long     etx_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

/*
** File operation sturcture
*/
static struct file_operations fops =
{
        .owner          = THIS_MODULE,
        .read           = etx_read,
        .write          = etx_write,
        .open           = etx_open,
        .unlocked_ioctl = etx_ioctl,
        .release        = etx_release,
};


static void intel_extender_do_memtest(void *info)
{
	u32 processor_id = smp_processor_id();
	void __iomem *base;

	unsigned int write_value,read_value;

	base = *(void __iomem **)(extender_memtest->dev)->platform_data;

	//pr_info("Target %d\n",extender_memtest->target_cpu);
		if (extender_memtest->target_cpu[processor_id] == 1)
	{
		pr_info("Memtest - Processor %d Base %lx Offset %llx Len %llx\n",
					processor_id, (unsigned long)base,
					extender_memtest->ramtest_base_address[processor_id],
					extender_memtest->ramtest_len[processor_id] );

		write_value = processor_id;
		base += extender_memtest->ramtest_base_address[processor_id];

		writel(write_value, base);
		read_value = readl(base);

		if (read_value != write_value){
			pr_info("Error - offset %llx should have %x but got %x\n",
					extender_memtest->ramtest_base_address[processor_id],
					write_value,read_value);
		} else {
			pr_info("Ok %d\n",processor_id);
		}
	}
}
/*
** This function will be called when we open the Device file
*/
static int etx_open(struct inode *inode, struct file *file)
{
//        pr_info("Device File Opened...!!!\n");
        return 0;
}

/*
** This function will be called when we close the Device file
*/
static int etx_release(struct inode *inode, struct file *file)
{
//        pr_info("Device File Closed...!!!\n");
        return 0;
}

/*
** This function will be called when we read the Device file
*/
static ssize_t etx_read(struct file *filp, char __user *buf, size_t len, loff_t *off)
{
//        pr_info("Read Function\n");
        return 0;
}

/*
** This function will be called when we write the Device file
*/
static ssize_t etx_write(struct file *filp, const char __user *buf, size_t len, loff_t *off)
{
		uint8_t write_buf[4];
		int lp;

		if (copy_from_user(write_buf,buf,4))
		{
			pr_err("Data Write : Err!\n");
			return len;
		}
		pr_info("Write: %c %c %c %c\n",write_buf[0], write_buf[1], write_buf[2], write_buf[3]);
		//extender_memtest->target_cpu = (u32)(write_buf[0]-48);

		for(lp=0;lp<4;lp++)
			extender_memtest->target_cpu[lp]=(write_buf[lp]== '1'? 1 : 0);

		on_each_cpu(intel_extender_do_memtest, NULL, 0);
        return len;
}

/*
** This function will be called when we write IOCTL on the Device file
*/
static long etx_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
         switch(cmd) {
                case WR_VALUE:
                        if( copy_from_user(&value ,(int32_t*) arg, sizeof(value)) )
                        {
                                pr_err("Data Write : Err!\n");
                        }
                        pr_info("Value = %d\n", value);
                        break;
                case RD_VALUE:
                        if( copy_to_user((int32_t*) arg, &value, sizeof(value)) )
                        {
                                pr_err("Data Read : Err!\n");
                        }
                        break;
                default:
                        pr_info("Default\n");
                        break;
        }
        return 0;
}




static int intel_extender_memtest_probe(struct platform_device *pdev)
{
	void __iomem *base;

	u64 ram_address_space[8] = {0};

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

	extender_memtest->ramtest_base_address[0] = ram_address_space[0];
	extender_memtest->ramtest_len[0] = ram_address_space[1];
	extender_memtest->ramtest_base_address[1] = ram_address_space[2];
	extender_memtest->ramtest_len[1] = ram_address_space[3];
	extender_memtest->ramtest_base_address[2] = ram_address_space[4];
	extender_memtest->ramtest_len[2] = ram_address_space[5];
	extender_memtest->ramtest_base_address[3] = ram_address_space[6];
	extender_memtest->ramtest_len[3] = ram_address_space[7];


//	on_each_cpu(intel_extender_do_memtest, extender_memtest, 0);

    /*Allocating Major number*/
    if((alloc_chrdev_region(&dev, 0, 1, "extender_memtest")) <0){
            pr_err("Cannot allocate major number\n");
            return -1;
    }
    pr_info("Major = %d Minor = %d \n",MAJOR(dev), MINOR(dev));

    /*Creating cdev structure*/
    cdev_init(&etx_cdev,&fops);

    /*Adding character device to the system*/
    if((cdev_add(&etx_cdev,dev,1)) < 0){
        pr_err("Cannot add the device to the system\n");
        goto r_class;
    }

    /*Creating struct class*/
    if((dev_class = class_create(THIS_MODULE,"extender_memtest_class")) == NULL){
        pr_err("Cannot create the struct class\n");
        goto r_class;
    }

    /*Creating device*/
    if((device_create(dev_class,NULL,dev,NULL,"extender_memtest_device")) == NULL){
        pr_err("Cannot create the Device\n");
        goto r_device;
    }
    pr_info("Device Driver Insert...Done!!!\n");

	return 0;

	r_device:
	        class_destroy(dev_class);
	r_class:
	        unregister_chrdev_region(dev,1);
	        return -1;
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
