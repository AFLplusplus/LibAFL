#include "lqemu.h"

#define LIBAFL_DEFINE_FUNCTIONS(name, opcode)                                  \
  lqword LQEMU_CALLING_CONVENTION _lqemu_##name##_call0(lqword cmd) {          \
    lqword ret;                                                                \
    __asm__ volatile("mov %1, %%rax\n"                                         \
                     ".4byte " XSTRINGIFY(opcode) "\n"                         \
                                                  "mov %%rax, %0\n"            \
                     : "=g"(ret)                                               \
                     : "g"(cmd)                                                \
                     : "%rax");                                                \
    return ret;                                                                \
  }                                                                            \
                                                                               \
  lqword LQEMU_CALLING_CONVENTION _lqemu_##name##_call1(lqword cmd,            \
                                                        lqword arg1) {         \
    lqword ret;                                                                \
    __asm__ volatile("mov %1, %%rax\n"                                         \
                     "mov %2, %%rdi\n"                                         \
                     ".4byte " XSTRINGIFY(opcode) "\n"                         \
                                                  "mov %%rax, %0\n"            \
                     : "=g"(ret)                                               \
                     : "g"(cmd), "g"(arg1)                                     \
                     : "%rax", "%rdi");                                        \
    return ret;                                                                \
  }                                                                            \
                                                                               \
  lqword LQEMU_CALLING_CONVENTION _lqemu_##name##_call2(                       \
      lqword cmd, lqword arg1, lqword arg2) {                                  \
    lqword ret;                                                                \
    __asm__ volatile("mov %1, %%rax\n"                                         \
                     "mov %2, %%rdi\n"                                         \
                     "mov %3, %%rsi\n"                                         \
                     ".4byte " XSTRINGIFY(opcode) "\n"                         \
                                                  "mov %%rax, %0\n"            \
                     : "=g"(ret)                                               \
                     : "g"(cmd), "g"(arg1), "g"(arg2)                          \
                     : "%rax", "%rdi", "%rsi");                                \
    return ret;                                                                \
  }

LIBAFL_DEFINE_FUNCTIONS(custom_insn, LIBAFL_CUSTOM_INSN_OPCODE)

LIBAFL_DEFINE_FUNCTIONS(backdoor, LIBAFL_BACKDOOR_OPCODE)
