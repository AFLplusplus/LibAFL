#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

typedef int64_t abi_long;
typedef uint64_t abi_ulong;

__attribute__((weak)) int libafl_qemu_write_reg(int reg, uint8_t* val) {
  (void)reg;
  (void)val;
  return 0;
}

__attribute__((weak)) int libafl_qemu_read_reg(int reg, uint8_t* val) {
  (void)reg;
  (void)val;
  return 0;
}

__attribute__((weak)) int libafl_qemu_num_regs(void) {
  return 0;
}

__attribute__((weak)) int libafl_qemu_set_breakpoint(uint64_t addr) {
  (void)addr;
  return 0;
}

__attribute__((weak)) int libafl_qemu_remove_breakpoint(uint64_t addr) {
  (void)addr;
  return 0;
}

__attribute__((weak)) int libafl_qemu_run() {
  return 0;
}

__attribute__((weak)) uint64_t libafl_load_addr() {
    return 0;
}

__attribute__((weak)) abi_long target_mmap(abi_ulong start, abi_ulong len,
                                           int target_prot, int flags, int fd,
                                           abi_ulong offset) {

  (void)start;
  (void)len;
  (void)target_prot;
  (void)flags;
  (void)fd;
  (void)offset;
  return 0;
}

__attribute__((weak)) int target_munmap(abi_ulong start, abi_ulong len) {
  (void)start;
  (void)len;
  return 0;
}

__attribute__((weak)) char* exec_path = NULL;
__attribute__((weak)) size_t guest_base = 0;

__attribute__((weak)) void (*libafl_exec_edge_hook)(uint32_t);
__attribute__((weak)) uint32_t (*libafl_gen_edge_hook)(uint64_t, uint64_t);
__attribute__((weak)) void (*libafl_exec_block_hook)(uint64_t);
__attribute__((weak)) uint32_t (*libafl_gen_block_hook)(uint64_t);

__attribute__((weak)) void (*libafl_exec_cmp_hook1)(uint32_t, uint8_t, uint8_t);
__attribute__((weak)) void (*libafl_exec_cmp_hook2)(uint32_t, uint16_t, uint16_t);
__attribute__((weak)) void (*libafl_exec_cmp_hook4)(uint32_t, uint32_t, uint32_t);
__attribute__((weak)) void (*libafl_exec_cmp_hook8)(uint32_t, uint64_t, uint64_t);
__attribute__((weak)) uint32_t (*libafl_gen_cmp_hook)(uint64_t, uint32_t);

struct syshook_ret {
    uint64_t retval;
    bool skip_syscall;
};
__attribute__((weak)) struct syshook_ret (*libafl_syscall_hook)(int, uint64_t,
                                          uint64_t, uint64_t, uint64_t, uint64_t,
                                          uint64_t, uint64_t, uint64_t);
