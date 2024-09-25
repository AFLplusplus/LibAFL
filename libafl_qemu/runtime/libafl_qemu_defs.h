#ifndef LIBAFL_QEMU_DEFS
#define LIBAFL_QEMU_DEFS

#define LIBAFL_STRINGIFY(s) #s
#define XSTRINGIFY(s) LIBAFL_STRINGIFY(s)

#if __STDC_VERSION__ >= 201112L
  #define STATIC_CHECKS                                   \
    _Static_assert(sizeof(void *) <= sizeof(libafl_word), \
                   "pointer type should not be larger and libafl_word");
#else
  #define STATIC_CHECKS
#endif

#define LIBAFL_SYNC_EXIT_OPCODE 0x66f23a0f
#define LIBAFL_BACKDOOR_OPCODE 0x44f23a0f

#define LIBAFL_QEMU_TEST_VALUE 0xcafebabe

#define LIBAFL_QEMU_HDR_VERSION_NUMBER 0111  // TODO: find a nice way to set it.

typedef enum LibaflQemuCommand {
  LIBAFL_QEMU_COMMAND_START_VIRT = 0,
  LIBAFL_QEMU_COMMAND_START_PHYS = 1,
  LIBAFL_QEMU_COMMAND_INPUT_VIRT = 2,
  LIBAFL_QEMU_COMMAND_INPUT_PHYS = 3,
  LIBAFL_QEMU_COMMAND_END = 4,
  LIBAFL_QEMU_COMMAND_SAVE = 5,
  LIBAFL_QEMU_COMMAND_LOAD = 6,
  LIBAFL_QEMU_COMMAND_VERSION = 7,
  LIBAFL_QEMU_COMMAND_VADDR_FILTER_ALLOW = 8,
  LIBAFL_QEMU_COMMAND_INTERNAL_ERROR = 9,
  LIBAFL_QEMU_COMMAND_LQPRINTF = 10,
  LIBAFL_QEMU_COMMAND_TEST = 11,
} LibaflExit;

#endif
