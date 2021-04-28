#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

// TODO compile time flag
#define MAP_SIZE 65536

extern uint8_t libafl_cmp_map[MAP_SIZE];

#ifdef _WIN32
#define RETADDR (uintptr_t)_ReturnAddress()
#else
#define RETADDR (uintptr_t)__builtin_return_address(0)
#endif

#ifdef __GNUC__
#define MAX(a, b)           \
  ({                        \
                            \
    __typeof__(a) _a = (a); \
    __typeof__(b) _b = (b); \
    _a > _b ? _a : _b;      \
                            \
  })
#else
#define MAX(a, b) (((a) > (b)) ? (a) : (b)) 
#endif

#ifdef _MSC_VER
#include <intrin.h>
#define __builtin_popcount __popcnt
#define __builtin_popcountll __popcnt64
#endif

#if defined(__APPLE__)
  #pragma weak __sanitizer_cov_trace_const_cmp1 = __sanitizer_cov_trace_cmp1
  #pragma weak __sanitizer_cov_trace_const_cmp2 = __sanitizer_cov_trace_cmp2
  #pragma weak __sanitizer_cov_trace_const_cmp4 = __sanitizer_cov_trace_cmp4
  #pragma weak __sanitizer_cov_trace_const_cmp8 = __sanitizer_cov_trace_cmp8
#elif defined(_MSC_VER)
  #pragma comment(linker, "/alternatename:__sanitizer_cov_trace_const_cmp1=__sanitizer_cov_trace_cmp1")
  #pragma comment(linker, "/alternatename:__sanitizer_cov_trace_const_cmp2=__sanitizer_cov_trace_cmp2")
  #pragma comment(linker, "/alternatename:__sanitizer_cov_trace_const_cmp4=__sanitizer_cov_trace_cmp4")
  #pragma comment(linker, "/alternatename:__sanitizer_cov_trace_const_cmp8=__sanitizer_cov_trace_cmp8")
#else
void __sanitizer_cov_trace_const_cmp1(uint8_t arg1, uint8_t arg2) __attribute__((alias("__sanitizer_cov_trace_cmp1")));
void __sanitizer_cov_trace_const_cmp2(uint16_t arg1, uint16_t arg2)
    __attribute__((alias("__sanitizer_cov_trace_cmp2")));
void __sanitizer_cov_trace_const_cmp4(uint32_t arg1, uint32_t arg2)
    __attribute__((alias("__sanitizer_cov_trace_cmp4")));
void __sanitizer_cov_trace_const_cmp8(uint64_t arg1, uint64_t arg2)
    __attribute__((alias("__sanitizer_cov_trace_cmp8")));
#endif

void __sanitizer_cov_trace_cmp1(uint8_t arg1, uint8_t arg2) {

  uintptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);
  k &= MAP_SIZE - 1;
  libafl_cmp_map[k] = MAX(libafl_cmp_map[k], (__builtin_popcount(~(arg1 ^ arg2))));

}

void __sanitizer_cov_trace_cmp2(uint16_t arg1, uint16_t arg2) {

  uintptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);
  k &= MAP_SIZE - 1;
  libafl_cmp_map[k] = MAX(libafl_cmp_map[k], (__builtin_popcount(~(arg1 ^ arg2))));

}

void __sanitizer_cov_trace_cmp4(uint32_t arg1, uint32_t arg2) {

  uintptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);
  k &= MAP_SIZE - 1;
  libafl_cmp_map[k] = MAX(libafl_cmp_map[k], (__builtin_popcount(~(arg1 ^ arg2))));

}

void __sanitizer_cov_trace_cmp8(uint64_t arg1, uint64_t arg2) {

  uintptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);
  k &= MAP_SIZE - 1;
  libafl_cmp_map[k] = MAX(libafl_cmp_map[k], (__builtin_popcountll(~(arg1 ^ arg2))));

}

void __sanitizer_cov_trace_switch(uint64_t val, uint64_t *cases) {

  uintptr_t rt = RETADDR;
  if (cases[1] == 64) {

    for (uint64_t i = 0; i < cases[0]; i++) {

      uintptr_t k = rt + i;
      k = (k >> 4) ^ (k << 8);
      k &= MAP_SIZE - 1;
      libafl_cmp_map[k] = MAX(libafl_cmp_map[k], (__builtin_popcountll(~(val ^ cases[i + 2]))));

    }

  } else {

    for (uint64_t i = 0; i < cases[0]; i++) {

      uintptr_t k = rt + i;
      k = (k >> 4) ^ (k << 8);
      k &= MAP_SIZE - 1;
      libafl_cmp_map[k] = MAX(libafl_cmp_map[k], (__builtin_popcount(~(val ^ cases[i + 2]))));

    }

  }

}
