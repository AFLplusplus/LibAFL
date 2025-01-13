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

#if defined(USE_LQEMU)
  #include "libafl_qemu.h"
#elif defined(USE_NYX)
  #include "nyx_api.h"
#endif

#define PAYLOAD_MAX_SIZE 65536

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

// kallsyms_lookup_name function address
static long unsigned int kallsyms_lookup_name_addr = 0;

// kallsyms_lookup_name function
static unsigned long (*kall_syms_lookup_name_fn)(const char *name) = NULL;

static struct kprobe kp0, kp1;

KPROBE_PRE_HANDLER(handler_pre0) {
  kallsyms_lookup_name_addr = (--regs->ip);

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

#ifdef USE_NYX
  hprintf("kallsyms_lookup_name address = 0x%lx\n", kallsyms_lookup_name_addr);
#elif DEFINED(USE_LQEMU)
  lqprintf("kallsyms_lookup_name address = 0x%lx\n", kallsyms_lookup_name_addr);
#endif

  if (kallsyms_lookup_name_addr == 0) { return -1; }

  kall_syms_lookup_name_fn =
      (unsigned long (*)(const char *name))kallsyms_lookup_name_addr;

  return ret;
}

static int harness_uevent(const struct device    *dev,
                          struct kobj_uevent_env *env) {
  add_uevent_var(env, "DEVMODE=%#o", 0666);
  return 0;
}

#ifdef USE_NYX
/**
 * Allocate page-aligned memory
 */
static void *malloc_resident_pages(size_t num_pages) {
  size_t data_size = PAGE_SIZE * num_pages;
  void  *ptr = NULL;

  if ((ptr = kzalloc(data_size, GFP_KERNEL)) == NULL) {
    printk("Allocation failure\n");
    goto err_out;
  }

  // ensure pages are aligned and resident
  memset(ptr, 0x42, data_size);
  // if (mlock(ptr, data_size) == -1) {
  //   printk("Error locking scratch buffer\n");
  //   goto err_out;
  // }

  // assert(((uintptr_t)ptr % PAGE_SIZE) == 0);
  return ptr;
err_out:
  // free(ptr);
  return NULL;
}

static volatile __attribute__((aligned(PAGE_SIZE))) uint64_t range_args[3];

static void hrange_submit(unsigned id, unsigned long start, unsigned long end) {
  range_args[0] = start;
  range_args[1] = end;
  range_args[2] = id;

  kAFL_hypercall(HYPERCALL_KAFL_RANGE_SUBMIT, (unsigned long)range_args);
}

static int agent_init(int verbose) {
  host_config_t host_config;

  hprintf("Nyx agent init");

  // set ready state
  kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
  kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);

  kAFL_hypercall(HYPERCALL_KAFL_GET_HOST_CONFIG, (uintptr_t)&host_config);

  if (verbose) {
    printk("GET_HOST_CONFIG\n");
    printk("\thost magic:  0x%x, version: 0x%x\n", host_config.host_magic,
           host_config.host_version);
    printk("\tbitmap size: 0x%x, ijon:    0x%x\n", host_config.bitmap_size,
           host_config.ijon_bitmap_size);
    printk("\tpayload size: %u KB\n", host_config.payload_buffer_size / 1024);
    printk("\tworker id: %d\n", host_config.worker_id);
  }

  if (host_config.host_magic != NYX_HOST_MAGIC) {
    hprintf("HOST_MAGIC mismatch: %08x != %08x", host_config.host_magic,
            NYX_HOST_MAGIC);
    habort("HOST_MAGIC mismatch!");
    return -1;
  }

  if (host_config.host_version != NYX_HOST_VERSION) {
    hprintf("HOST_VERSION mismatch: %08x != %08x\n", host_config.host_version,
            NYX_HOST_VERSION);
    habort("HOST_VERSION mismatch!");
    return -1;
  }

  if (host_config.payload_buffer_size > PAYLOAD_MAX_SIZE) {
    hprintf("Fuzzer payload size too large: %lu > %lu\n",
            host_config.payload_buffer_size, PAYLOAD_MAX_SIZE);
    habort("Host payload size too large!");
    return -1;
  }

  agent_config_t agent_config = {0};
  agent_config.agent_magic = NYX_AGENT_MAGIC;
  agent_config.agent_version = NYX_AGENT_VERSION;
  // agent_config.agent_timeout_detection = 0; // timeout by host
  // agent_config.agent_tracing = 0; // trace by host
  // agent_config.agent_ijon_tracing = 0; // no IJON
  agent_config.agent_non_reload_mode = 0;  // no persistent mode
  // agent_config.trace_buffer_vaddr = 0xdeadbeef;
  // agent_config.ijon_trace_buffer_vaddr = 0xdeadbeef;
  agent_config.coverage_bitmap_size = host_config.bitmap_size;
  // agent_config.input_buffer_size;
  // agent_config.dump_payloads; // set by hypervisor (??)

  kAFL_hypercall(HYPERCALL_KAFL_SET_AGENT_CONFIG, (uintptr_t)&agent_config);

  return 0;
}
#endif

static int __init harness_init(void) {
  int   err;
  dev_t dev;

  err = alloc_chrdev_region(&dev, 0, 1, "harness");

  if (err < 0) { return err; }

  dev_major = MAJOR(dev);

  harness_class = class_create("harness");
  harness_class->dev_uevent = harness_uevent;

  cdev_init(&harness_data.cdev, &harness_fops);
  harness_data.cdev.owner = THIS_MODULE;

  cdev_add(&harness_data.cdev, MKDEV(dev_major, 0), 1);

  device_create(harness_class, NULL, MKDEV(dev_major, 0), NULL, "harness");

  err = harness_find_kallsyms_lookup();

  if (err < 0) {
    habort("error while trying to find kallsyms");
    return err;
  }

  return 0;
}

static void __exit harness_exit(void) {
  device_destroy(harness_class, MKDEV(dev_major, 0));

  class_unregister(harness_class);
  class_destroy(harness_class);

  unregister_chrdev_region(MKDEV(dev_major, 0), MINORMASK);
}

static int harness_open(struct inode *inode, struct file *file) {
  unsigned long x509_fn_addr = kall_syms_lookup_name_fn("x509_cert_parse");
  unsigned long asn1_ber_decoder_addr =
      kall_syms_lookup_name_fn("asn1_ber_decoder");
  unsigned long x509_get_sig_params_addr =
      kall_syms_lookup_name_fn("x509_get_sig_params");

  // hprintf("action 0: %p", x509_decoder.actions[0]);

#if defined(USE_LQEMU)
  lqprintf("harness: Device open\n");

  // TODO: better filtering...
  libafl_qemu_trace_vaddr_size(x509_fn_addr, 0x1000);

  libafl_qemu_test();

  char *input_buf = kzalloc(PAYLOAD_MAX_SIZE, GFP_KERNEL);
  input_buf[0] = 0xff;  // init page

#elif defined(USE_NYX)
  hprintf("harness: Device open.");
  hprintf("\tx509_cert_parse: %p", x509_fn_addr);
  hprintf("\tasn1_ber_decoder: %p", asn1_ber_decoder_addr);
  hprintf("\tx509_get_sig_params: %p", x509_get_sig_params_addr);

  if (!x509_fn_addr || !asn1_ber_decoder_addr) { habort("Invalid ranges"); }

  kAFL_payload *pbuf = malloc_resident_pages(PAYLOAD_MAX_SIZE / PAGE_SIZE);

  agent_init(1);

  // kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_CR3, 0);
  hrange_submit(0, x509_fn_addr, x509_fn_addr + 0x1000);
  hrange_submit(1, asn1_ber_decoder_addr, asn1_ber_decoder_addr + 0x1000);
  hrange_submit(2, x509_get_sig_params_addr, x509_get_sig_params_addr + 0x1000);

  kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (uintptr_t)pbuf);

  hprintf("payload size addr: %p", &pbuf->size);
  hprintf("payload addr: %p", &pbuf->data);

#else
  #error No API specified.
#endif

  // int ret;
  // uintptr_t start_addr = 0, end_addr = 0;

  // ret = lqemu_symfinder_widen_range("x509_cert_parse", &start_addr,
  // &end_addr); if (ret) {
  //   printk("error while handling range");
  //   return ret;
  // }

  while (true) {
#if defined(USE_LQEMU)
    uint8_t *data = input_buf;
    size_t   size = libafl_qemu_start_virt(data, PAYLOAD_MAX_SIZE);
#elif defined(USE_NYX)
    kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);
    kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);

    size_t                  size = pbuf->size;
    const volatile uint8_t *data = pbuf->data;
#endif

    __maybe_unused struct x509_certificate *cert_ret =
        x509_cert_parse((const void *)data, size);

#if defined(USE_LQEMU)
    libafl_qemu_end(LIBAFL_QEMU_END_OK);
#elif defined(USE_NYX)
    kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
#endif
  }

  return 0;
}

static int harness_release(struct inode *inode, struct file *file) {
#if defined(USE_LQEMU)
  lqprintf("harness: Device close\n");
#elif defined(USE_NYX)
  hprintf("harness: Device close");
#endif
  return 0;
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Slasti Mormanti");

module_init(harness_init);
module_exit(harness_exit);
