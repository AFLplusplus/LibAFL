#include <linux/init.h>
#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>

#include "x509-parser.h"
#include "libafl_qemu.h"

#define MAX_DEV 1

#define BUF_SIZE 4096

static int harness_open(struct inode *inode, struct file *file);
static int harness_release(struct inode *inode, struct file *file);

static const struct file_operations harness_fops = {
    .owner = THIS_MODULE,
    .open = harness_open,
    .release = harness_release,
};

struct mychar_device_data {
  struct cdev cdev;
};

static int                       dev_major = 0;
static struct class             *harness_class = NULL;
static struct mychar_device_data harness_data;

#define KPROBE_PRE_HANDLER(fname) \
  static int __kprobes fname(struct kprobe *p, struct pt_regs *regs)

long unsigned int kln_addr = 0;
unsigned long (*kln_pointer)(const char *name) = NULL;

static struct kprobe kp0, kp1;

KPROBE_PRE_HANDLER(handler_pre0) {
  kln_addr = (--regs->ip);

  return 0;
}

KPROBE_PRE_HANDLER(handler_pre1) {
  return 0;
}

static int do_register_kprobe(struct kprobe *kp, char *symbol_name,
                              void *handler) {
  int ret;

  kp->symbol_name = symbol_name;
  kp->pre_handler = handler;

  ret = register_kprobe(kp);
  if (ret < 0) {
    pr_err("register_probe() for symbol %s failed, returned %d\n", symbol_name,
           ret);
    return ret;
  }

  pr_info("Planted kprobe for symbol %s at %p\n", symbol_name, kp->addr);

  return ret;
}

// Find kallsyms_lookup_name
// taken from
// https://github.com/zizzu0/LinuxKernelModules/blob/main/FindKallsymsLookupName.c
static int harness_find_kallsyms_lookup(void) {
  int ret;

  ret = do_register_kprobe(&kp0, "kallsyms_lookup_name", handler_pre0);
  if (ret < 0) return ret;

  ret = do_register_kprobe(&kp1, "kallsyms_lookup_name", handler_pre1);
  if (ret < 0) {
    unregister_kprobe(&kp0);
    return ret;
  }

  unregister_kprobe(&kp0);
  unregister_kprobe(&kp1);

  lqprintf("kallsyms_lookup_name address = 0x%lx\n", kln_addr);

  kln_pointer = (unsigned long (*)(const char *name))kln_addr;

  return ret;
}

static int harness_uevent(const struct device    *dev,
                          struct kobj_uevent_env *env) {
  add_uevent_var(env, "DEVMODE=%#o", 0666);
  return 0;
}

static int __init harness_init(void) {
  int   err;
  dev_t dev;

  err = alloc_chrdev_region(&dev, 0, 1, "harness");

  dev_major = MAJOR(dev);

  harness_class = class_create("harness");
  harness_class->dev_uevent = harness_uevent;

  cdev_init(&harness_data.cdev, &harness_fops);
  harness_data.cdev.owner = THIS_MODULE;

  cdev_add(&harness_data.cdev, MKDEV(dev_major, 0), 1);

  device_create(harness_class, NULL, MKDEV(dev_major, 0), NULL, "harness");

  harness_find_kallsyms_lookup();

  return 0;
}

static void __exit harness_exit(void) {
  device_destroy(harness_class, MKDEV(dev_major, 0));

  class_unregister(harness_class);
  class_destroy(harness_class);

  unregister_chrdev_region(MKDEV(dev_major, 0), MINORMASK);
}

static int harness_open(struct inode *inode, struct file *file) {
  int ret;
  lqprintf("harness: Device open\n");

  char *data = kzalloc(BUF_SIZE, GFP_KERNEL);
  data[0] = 0xff;  // init page

  unsigned long x509_fn_addr = kln_pointer("x509_cert_parse");
  lqprintf("harness: x509 fn addr: 0x%lx\n", x509_fn_addr);

  // TODO: better filtering...
  libafl_qemu_trace_vaddr_size(x509_fn_addr, 0x1000);

  libafl_qemu_test();

  u64 buf_size = libafl_qemu_start_virt(data, BUF_SIZE);

  struct x509_certificate *cert_ret = x509_cert_parse(data, buf_size);

  libafl_qemu_end(LIBAFL_QEMU_END_OK);

  return 0;
}

static int harness_release(struct inode *inode, struct file *file) {
  lqprintf("harness: Device close\n");
  return 0;
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Slasti Mormanti");

module_init(harness_init);
module_exit(harness_exit);
