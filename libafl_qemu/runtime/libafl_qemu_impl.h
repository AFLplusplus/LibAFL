#ifndef LIBAFL_QEMU_IMPL
#define LIBAFL_QEMU_IMPL

#include "libafl_qemu.h"

static char _lqprintf_buffer[LIBAFL_QEMU_PRINTF_MAX_SIZE] = {0};

noinline libafl_word libafl_qemu_start_virt(void       *buf_vaddr,
                                            libafl_word max_len) {
  return _libafl_sync_exit_call2(LIBAFL_QEMU_COMMAND_START_VIRT,
                                 (libafl_word)buf_vaddr, max_len);
}

noinline libafl_word libafl_qemu_start_phys(void       *buf_paddr,
                                            libafl_word max_len) {
  return _libafl_sync_exit_call2(LIBAFL_QEMU_COMMAND_START_PHYS,
                                 (libafl_word)buf_paddr, max_len);
}

noinline libafl_word libafl_qemu_input_virt(void       *buf_vaddr,
                                            libafl_word max_len) {
  return _libafl_sync_exit_call2(LIBAFL_QEMU_COMMAND_INPUT_VIRT,
                                 (libafl_word)buf_vaddr, max_len);
}

noinline libafl_word libafl_qemu_input_phys(void       *buf_paddr,
                                            libafl_word max_len) {
  return _libafl_sync_exit_call2(LIBAFL_QEMU_COMMAND_INPUT_PHYS,
                                 (libafl_word)buf_paddr, max_len);
}

noinline void libafl_qemu_end(enum LibaflQemuEndStatus status) {
  _libafl_sync_exit_call1(LIBAFL_QEMU_COMMAND_END, status);
}

noinline void libafl_qemu_save(void) {
  _libafl_sync_exit_call0(LIBAFL_QEMU_COMMAND_SAVE);
}

noinline void libafl_qemu_load(void) {
  _libafl_sync_exit_call0(LIBAFL_QEMU_COMMAND_LOAD);
}

noinline libafl_word libafl_qemu_version(void) {
  return _libafl_sync_exit_call0(LIBAFL_QEMU_COMMAND_VERSION);
}

noinline void libafl_qemu_internal_error(void) {
  _libafl_sync_exit_call0(LIBAFL_QEMU_COMMAND_INTERNAL_ERROR);
}

#ifdef STDIO_SUPPORT
noinline void lqprintf(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  int res = vsnprintf(_lqprintf_buffer, LIBAFL_QEMU_PRINTF_MAX_SIZE, fmt, args);
  va_end(args);

  if (res >= LIBAFL_QEMU_PRINTF_MAX_SIZE) {
    // buffer is not big enough, either recompile the target with more
    // space or print less things
    libafl_qemu_internal_error();
  }

  _libafl_sync_exit_call2(LIBAFL_QEMU_COMMAND_LQPRINTF,
                          (libafl_word)_lqprintf_buffer, res);
}
#endif

noinline void libafl_qemu_test(void) {
  _libafl_sync_exit_call1(LIBAFL_QEMU_COMMAND_TEST, LIBAFL_QEMU_TEST_VALUE);
}

noinline void libafl_qemu_trace_vaddr_range(libafl_word start,
                                            libafl_word end) {
  _libafl_sync_exit_call2(LIBAFL_QEMU_COMMAND_VADDR_FILTER_ALLOW, start, end);
}

noinline void libafl_qemu_trace_vaddr_size(libafl_word start,
                                           libafl_word size) {
  libafl_qemu_trace_vaddr_range(start, start + size);
}

#endif