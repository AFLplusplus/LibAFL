#ifndef LIBAFL_QEMU_IMPL
#define LIBAFL_QEMU_IMPL

#include "libafl_qemu.h"

static char _lqprintf_buffer[LIBAFL_QEMU_PRINTF_MAX_SIZE] = {0};

libafl_word libafl_qemu_start_virt(void *buf_vaddr, libafl_word max_len) {
  return _libafl_sync_exit_call2(LIBAFL_QEMU_COMMAND_START_VIRT,
                                 (libafl_word)buf_vaddr, max_len);
}

libafl_word libafl_qemu_start_phys(void *buf_paddr, libafl_word max_len) {
  return _libafl_sync_exit_call2(LIBAFL_QEMU_COMMAND_START_PHYS,
                                 (libafl_word)buf_paddr, max_len);
}

libafl_word libafl_qemu_input_virt(void *buf_vaddr, libafl_word max_len) {
  return _libafl_sync_exit_call2(LIBAFL_QEMU_COMMAND_INPUT_VIRT,
                                 (libafl_word)buf_vaddr, max_len);
}

libafl_word libafl_qemu_input_phys(void *buf_paddr, libafl_word max_len) {
  return _libafl_sync_exit_call2(LIBAFL_QEMU_COMMAND_INPUT_PHYS,
                                 (libafl_word)buf_paddr, max_len);
}

void libafl_qemu_end(enum LibaflQemuEndStatus status) {
  _libafl_sync_exit_call1(LIBAFL_QEMU_COMMAND_END, status);
}

void libafl_qemu_save(void) {
  _libafl_sync_exit_call0(LIBAFL_QEMU_COMMAND_SAVE);
}

void libafl_qemu_load(void) {
  _libafl_sync_exit_call0(LIBAFL_QEMU_COMMAND_LOAD);
}

libafl_word libafl_qemu_version(void) {
  return _libafl_sync_exit_call0(LIBAFL_QEMU_COMMAND_VERSION);
}

void libafl_qemu_internal_error(void) {
  _libafl_sync_exit_call0(LIBAFL_QEMU_COMMAND_INTERNAL_ERROR);
}

void lqprintf(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  int res = vsnprintf(_lqprintf_buffer, LIBAFL_QEMU_PRINTF_MAX_SIZE, fmt, args);
  va_end(args);

  if (res >= LIBAFL_QEMU_PRINTF_MAX_SIZE) {
    //
    libafl_qemu_internal_error();
  }

  _libafl_sync_exit_call2(LIBAFL_QEMU_COMMAND_LQPRINTF,
                          (libafl_word)_lqprintf_buffer, res);
}

#endif