#include "common.h"
#include "value_profile.h"
#include "cmplog.h"

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

#ifdef SANCOV_VALUE_PROFILE
  __libafl_targets_value_profile1(k, arg1, arg2);
#endif

}

void __sanitizer_cov_trace_cmp2(uint16_t arg1, uint16_t arg2) {

  uintptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);
  k &= MAP_SIZE - 1;

#ifdef SANCOV_VALUE_PROFILE
  __libafl_targets_value_profile2(k, arg1, arg2);
#endif

}

void __sanitizer_cov_trace_cmp4(uint32_t arg1, uint32_t arg2) {

  uintptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);
  k &= MAP_SIZE - 1;

#ifdef SANCOV_VALUE_PROFILE
  __libafl_targets_value_profile4(k, arg1, arg2);
#endif

}

void __sanitizer_cov_trace_cmp8(uint64_t arg1, uint64_t arg2) {

  uintptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);
  k &= MAP_SIZE - 1;
  libafl_cmp_map[k] = MAX(libafl_cmp_map[k], (__builtin_popcountll(~(arg1 ^ arg2))));

#ifdef SANCOV_VALUE_PROFILE
  __libafl_targets_value_profile8(k, arg1, arg2);
#endif

}

void __sanitizer_cov_trace_switch(uint64_t val, uint64_t *cases) {

  uintptr_t rt = RETADDR;

  for (uint64_t i = 0; i < cases[0]; i++) {

    uintptr_t k = rt + i;
    k = (k >> 4) ^ (k << 8);
    k &= MAP_SIZE - 1;
    // val , cases[i + 2]
#ifdef SANCOV_VALUE_PROFILE
    switch (cases[1]) {
        case 8:
        __libafl_targets_value_profile1(k, (uint8_t)val, (uint8_t)cases[i + 2]);
        break;
        case 16:
        __libafl_targets_value_profile2(k, (uint16_t)val, (uint16_t)cases[i + 2]);
        break;
        case 32:
        __libafl_targets_value_profile4(k, (uint32_t)val, (uint32_t)cases[i + 2]);
        break;
        default:
        __libafl_targets_value_profile8(k, val, cases[i + 2]);
        break;
    }
#endif

  }

}
