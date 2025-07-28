#ifndef LQEMU_COMPILER_COMMON_H
#define LQEMU_COMPILER_COMMON_H

#define noinline __attribute__((noinline))
#define fmtarg __attribute__((format(printf, 1, 2)))

#if __STDC_VERSION__ >= 201112L
#define STATIC_CHECKS                                                          \
  _Static_assert(sizeof(void *) <= sizeof(lqword),                             \
                 "pointer type should not be larger and libafl_word");
#endif

#endif
