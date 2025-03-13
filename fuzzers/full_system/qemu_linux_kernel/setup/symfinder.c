#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/cred.h>
#include <linux/pid.h>
#include <linux/pid_namespace.h>
#include <linux/fs.h>

struct symfindex_ctx {
}
#include "symfinder.h"

static map_kallsyms(void) {
  const struct cred *current_creds = get_current_cred();

  struct cred *root_creds;

  current_creds = get_current_cred();
  root_creds = prepare_kernel_cred(
      pid_task(find_pid_ns(1, task_active_pid_ns(current)), PIDTYPE_PID));

  if (!root_creds) {
    printk("error while fetching root credentials from init process.\n");
    return -1;
  }

  commit_creds(root_creds);

  struct file *syms_f = filp_open("/proc/kallsyms", O_RDONLY, 0);
  if (!syms_f) {
    printk("error while opening kallsyms.\n");
    return -1;
  }

  commit_creds((struct cred *)current_creds);
  put_cred(root_creds);

  return 0;
}

int lqemu_symfinder_find_range(const char *symbol, uintptr_t *addr_start,
                               uintptr_t *addr_end) {
}

int lqemu_symfinder_widen_range(const char *symbol, uintptr_t *min_addr_start,
                                uintptr_t *max_addr_end) {
  int ret;

  uintptr_t tmp_addr_start = 0;
  uintptr_t tmp_addr_end = 0;

  ret = lqemu_symfinder_find_range(symbol, &tmp_addr_start, &tmp_addr_end);
  if (ret) {
    printk("symbol not found: %s", symbol);
    return ret;
  }

  *min_addr_start = *min_addr_start == 0 ? tmp_addr_start
                                         : min(*min_addr_start, tmp_addr_start);
  *max_addr_end =
      *max_addr_end == 0 ? tmp_addr_end : max(*max_addr_end, tmp_addr_end);

  return 0;
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Slasti Mormanti");
