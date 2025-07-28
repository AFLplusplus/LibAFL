#include "lqemu.h"
#include "consts.h"

#ifdef STATIC_CHECKS
STATIC_CHECKS
#endif

#ifdef LQEMU_SUPPORT_STDIO
static char llqprintf_buffer[LQEMU_PRINTF_MAX_SIZE] = {0};
#endif

noinline lqword libafl_qemu_start_virt(void *buf_vaddr, lqword max_len) {
  return _lqemu_custom_insn_call2(LIBAFL_QEMU_COMMAND_START_VIRT,
                                  (lqword)buf_vaddr, max_len);
}

noinline lqword libafl_qemu_start_phys(void *buf_paddr, lqword max_len) {
  return _lqemu_custom_insn_call2(LIBAFL_QEMU_COMMAND_START_PHYS,
                                  (lqword)buf_paddr, max_len);
}

noinline void libafl_qemu_end(enum LibaflQemuEndStatus status) {
  _lqemu_custom_insn_call1(LIBAFL_QEMU_COMMAND_END, status);
}

noinline void libafl_qemu_save(void) {
  _lqemu_custom_insn_call0(LIBAFL_QEMU_COMMAND_SAVE);
}

noinline void libafl_qemu_load(void) {
  _lqemu_custom_insn_call0(LIBAFL_QEMU_COMMAND_LOAD);
}

noinline lqword libafl_qemu_version(void) {
  return _lqemu_custom_insn_call2(LIBAFL_QEMU_COMMAND_VERSION,
                                  LQEMU_VERSION_MAJOR, LQEMU_VERSION_MINOR);
}

noinline void libafl_qemu_internal_error(void) {
  _lqemu_custom_insn_call0(LIBAFL_QEMU_COMMAND_INTERNAL_ERROR);
}

#ifdef LQEMU_SUPPORT_STDIO
noinline void lqprintf(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  int res = vsnprintf(llqprintf_buffer, LQEMU_PRINTF_MAX_SIZE, fmt, args);
  va_end(args);

  if (res >= LQEMU_PRINTF_MAX_SIZE) {
    // buffer is not big enough, either recompile the target with more
    // space or print less things
    libafl_qemu_internal_error();
  }

  _lqemu_custom_insn_call2(LIBAFL_QEMU_COMMAND_LQPRINTF,
                           (lqword)llqprintf_buffer, res);
}
#endif

noinline void libafl_qemu_test(void) {
  _lqemu_custom_insn_call1(LIBAFL_QEMU_COMMAND_TEST, LIBAFL_QEMU_TEST_VALUE);
}

noinline void libafl_qemu_trace_vaddr_range(lqword start, lqword end) {
  _lqemu_custom_insn_call2(LIBAFL_QEMU_COMMAND_VADDR_FILTER_ALLOW, start, end);
}

noinline void libafl_qemu_trace_vaddr_size(lqword start, lqword size) {
  libafl_qemu_trace_vaddr_range(start, start + size);
}

noinline void libafl_qemu_set_covmap_virt(volatile char *vaddr, lqword len,
                                          bool is_physically_contiguous) {
  struct lqemu_map map = {
      .map_kind = LQEMU_MAP_COV,
      .addr_kind = LQEMU_ADDR_VIRT,
      .addr = (lqword)vaddr,
      .len = len,
      .is_physically_contiguous = is_physically_contiguous,
  };

  _lqemu_custom_insn_call1(LIBAFL_QEMU_COMMAND_SET_MAP, (lqword)&map);
}

noinline void libafl_qemu_set_covmap_phys(volatile char *paddr, lqword len) {
  struct lqemu_map map = {
      .map_kind = LQEMU_MAP_COV,
      .addr_kind = LQEMU_ADDR_PHYS,
      .addr = (lqword)paddr,
      .len = len,
      .is_physically_contiguous = true,
  };

  _lqemu_custom_insn_call1(LIBAFL_QEMU_COMMAND_SET_MAP, (lqword)&map);
}
