#ifndef LIBAFL_QEMU_H
#define LIBAFL_QEMU_H

#include "libafl_qemu_defs.h"
#include "libafl_qemu_arch.h"

#define LIBAFL_QEMU_PRINTF_MAX_SIZE 4096

/**
 * LibAFL QEMU header file.
 *
 * This file is a portable header file used to build target harnesses more
 * conveniently. Its main purpose is to generate ready-to-use calls to
 * communicate with the fuzzer. The list of commands is available at the bottom
 * of this file. The rest mostly consists of macros generating the code used by
 * the commands.
 */

enum LibaflQemuEndStatus {
  LIBAFL_QEMU_END_UNKNOWN = 0,
  LIBAFL_QEMU_END_OK = 1,
  LIBAFL_QEMU_END_CRASH = 2,
};

libafl_word libafl_qemu_start_virt(void *buf_vaddr, libafl_word max_len);

libafl_word libafl_qemu_start_phys(void *buf_paddr, libafl_word max_len);

libafl_word libafl_qemu_input_virt(void *buf_vaddr, libafl_word max_len);

libafl_word libafl_qemu_input_phys(void *buf_paddr, libafl_word max_len);

void libafl_qemu_end(enum LibaflQemuEndStatus status);

void libafl_qemu_save(void);

void libafl_qemu_load(void);

libafl_word libafl_qemu_version(void);

void libafl_qemu_page_current_allow(void);

void libafl_qemu_internal_error(void);

void __attribute__((format(printf, 1, 2))) lqprintf(const char *fmt, ...);

void libafl_qemu_test(void);

void libafl_qemu_trace_vaddr_range(libafl_word start, libafl_word end);

void libafl_qemu_trace_vaddr_size(libafl_word start, libafl_word size);

#include "libafl_qemu_impl.h"

#endif
