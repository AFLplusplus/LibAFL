#include "lqemu.h"

#define LIBAFL_DEFINE_FUNCTIONS(name, opcode)                                  \
  lqword LQEMU_CALLING_CONVENTION _lqemu_##name##_call0(lqword cmd) {          \
    lqword ret;                                                                \
    __asm__ volatile("mov x0, %1\n"                                            \
                     ".word " XSTRINGIFY(opcode) "\n"                          \
                                                 "mov %0, x0\n"                \
                     : "=r"(ret)                                               \
                     : "r"(cmd)                                                \
                     : "x0");                                                  \
    return ret;                                                                \
  }                                                                            \
                                                                               \
  lqword LQEMU_CALLING_CONVENTION _lqemu_##name##_call1(lqword cmd,            \
                                                        lqword arg1) {         \
    lqword ret;                                                                \
    __asm__ volatile("mov x0, %1\n"                                            \
                     "mov x1, %2\n"                                            \
                     ".word " XSTRINGIFY(opcode) "\n"                          \
                                                 "mov %0, x0\n"                \
                     : "=r"(ret)                                               \
                     : "r"(cmd), "r"(arg1)                                     \
                     : "x0", "x1");                                            \
    return ret;                                                                \
  }                                                                            \
                                                                               \
  lqword LQEMU_CALLING_CONVENTION _lqemu_##name##_call2(                       \
      lqword cmd, lqword arg1, lqword arg2) {                                  \
    lqword ret;                                                                \
    __asm__ volatile("mov x0, %1\n"                                            \
                     "mov x1, %2\n"                                            \
                     "mov x2, %3\n"                                            \
                     ".word " XSTRINGIFY(opcode) "\n"                          \
                                                 "mov %0, x0\n"                \
                     : "=r"(ret)                                               \
                     : "r"(cmd), "r"(arg1), "r"(arg2)                          \
                     : "x0", "x1", "x2");                                      \
    return ret;                                                                \
  }

// Generates sync exit functions
LIBAFL_DEFINE_FUNCTIONS(custom_insn, LIBAFL_CUSTOM_INSN_OPCODE)

// Generates backdoor functions
LIBAFL_DEFINE_FUNCTIONS(backdoor, LIBAFL_BACKDOOR_OPCODE)
