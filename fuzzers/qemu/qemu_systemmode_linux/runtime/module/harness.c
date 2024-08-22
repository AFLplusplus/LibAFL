#include <linux/init.h>
#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include "/runtime/module/x509-parser.h"
#include "/runtime/module/libafl_qemu.h"
#define MAX_DEV 1

static int harness_open(struct inode *inode, struct file *file);
static int harness_release(struct inode *inode, struct file *file);

static const struct file_operations harness_fops = {
    .owner      = THIS_MODULE,
    .open       = harness_open,
    .release    = harness_release,
};

struct mychar_device_data {
    struct cdev cdev;
};

static int dev_major = 0;
static struct class *harness_class = NULL;
static struct mychar_device_data harness_data;

static int harness_uevent(const struct device *dev, struct kobj_uevent_env *env)
{
    add_uevent_var(env, "DEVMODE=%#o", 0666);
    return 0;
}

static int __init harness_init(void)
{
    int err;
    dev_t dev;

    err = alloc_chrdev_region(&dev, 0, 1, "harness");

    dev_major = MAJOR(dev);

    harness_class = class_create("harness");
    harness_class->dev_uevent = harness_uevent;

    cdev_init(&harness_data.cdev, &harness_fops);
    harness_data.cdev.owner = THIS_MODULE;

    cdev_add(&harness_data.cdev, MKDEV(dev_major, 0), 1);

    device_create(harness_class, NULL, MKDEV(dev_major, 0), NULL, "harness");

    return 0;
}

static void __exit harness_exit(void)
{
    device_destroy(harness_class, MKDEV(dev_major, 0));

    class_unregister(harness_class);
    class_destroy(harness_class);

    unregister_chrdev_region(MKDEV(dev_major, 0), MINORMASK);
}

#define BUF_SIZE 4096

static int harness_open(struct inode *inode, struct file *file)
{
    printk("harness: Device open\n");
    char *data = kmalloc(BUF_SIZE, GFP_KERNEL);
    for (uint64_t i = 0; i < 4096; i += 1) {
        data[i] = 0; // init
    }
    LIBAFL_QEMU_START_VIRT((uint64_t)data, BUF_SIZE);
    struct x509_certificate *ret = x509_cert_parse(data, BUF_SIZE);
    return 0;
}

static int harness_release(struct inode *inode, struct file *file)
{
    printk("harness: Device close\n");
    return 0;
}


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Slasti Mormanti");

module_init(harness_init);
module_exit(harness_exit);
