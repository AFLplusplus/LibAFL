#include "lqemu.h"

#define LIBAFL_DEFINE_FUNCTIONS(name, opcode)                                  \
  lqword LLQEMU_CALLING_CONVENTION _lqemu_##name##_call0(lqword action) {      \
    lqword ret;                                                                \
    __asm__ volatile("mov r0, %1\n"                                            \
                     ".word " XSTRINGIFY(opcode) "\n"                          \
                                                 "mov %0, r0\n"                \
                     : "=r"(ret)                                               \
                     : "r"(action)                                             \
                     : "r0");                                                  \
    return ret;                                                                \
  }                                                                            \
                                                                               \
  lqword LLQEMU_CALLING_CONVENTION _lqemu_##name##_call1(lqword action,        \
                                                         lqword arg1) {        \
    lqword ret;                                                                \
    __asm__ volatile("mov r0, %1\n"                                            \
                     "mov r1, %2\n"                                            \
                     ".word " XSTRINGIFY(opcode) "\n"                          \
                                                 "mov %0, r0\n"                \
                     : "=r"(ret)                                               \
                     : "r"(action), "r"(arg1)                                  \
                     : "r0", "r1");                                            \
    return ret;                                                                \
  }                                                                            \
                                                                               \
  lqword LLQEMU_CALLING_CONVENTION _lqemu_##name##_call2(                      \
      lqword action, lqword arg1, lqword arg2) {                               \
    lqword ret;                                                                \
    __asm__ volatile("mov r0, %1\n"                                            \
                     "mov r1, %2\n"                                            \
                     "mov r2, %3\n"                                            \
                     ".word " XSTRINGIFY(opcode) "\n"                          \
                                                 "mov %0, r0\n"                \
                     : "=r"(ret)                                               \
                     : "r"(action), "r"(arg1), "r"(arg2)                       \
                     : "r0", "r1", "r2");                                      \
    return ret;                                                                \
  }

LIBAFL_DEFINE_FUNCTIONS(custom_insn, LIBAFL_CUSTOM_INSN_OPCODE)

LIBAFL_DEFINE_FUNCTIONS(backdoor, LIBAFL_BACKDOOR_OPCODE)
