/**
 * LibAFL QEMU common.
 *
 * Common definitions.
 *
 */

#ifndef LIBAFL_QEMU_COMMON_H
#define LIBAFL_QEMU_COMMON_H

#include "defs.h"

#define LIBAFL_CUSTOM_INSN_OPCODE 0x66f23a0f
#define LIBAFL_BACKDOOR_OPCODE 0x44f23a0f
#define LIBAFL_QEMU_TEST_VALUE 0xcafebabe

enum lqemu_map_kind {
  LQEMU_MAP_COV,
  LQEMU_MAP_CMP,
};

enum lqemu_addr_kind {
  LQEMU_ADDR_PHYS,
  LQEMU_ADDR_VIRT,
};

struct lqemu_map {
  enum lqemu_map_kind map_kind;
  enum lqemu_addr_kind addr_kind;
  lqword addr;
  lqword len;

  // makes sense iif addr_kind == LQEMU_ADDR_VIRT
  bool is_physically_contiguous;
};

enum LibaflQemuEndStatus {
  LIBAFL_QEMU_END_UNKNOWN = 0,
  LIBAFL_QEMU_END_OK = 1,
  LIBAFL_QEMU_END_CRASH = 2,
};

typedef enum LibaflQemuCommand {
  LIBAFL_QEMU_COMMAND_START_VIRT = 0,
  LIBAFL_QEMU_COMMAND_START_PHYS = 1,
  LIBAFL_QEMU_COMMAND_END = 4,
  LIBAFL_QEMU_COMMAND_SAVE = 5,
  LIBAFL_QEMU_COMMAND_LOAD = 6,
  LIBAFL_QEMU_COMMAND_VERSION = 7,
  LIBAFL_QEMU_COMMAND_VADDR_FILTER_ALLOW = 8,
  LIBAFL_QEMU_COMMAND_INTERNAL_ERROR = 9,
  LIBAFL_QEMU_COMMAND_LQPRINTF = 10,
  LIBAFL_QEMU_COMMAND_TEST = 11,
  LIBAFL_QEMU_COMMAND_SET_MAP = 12,
} LibaflExit;

#endif
