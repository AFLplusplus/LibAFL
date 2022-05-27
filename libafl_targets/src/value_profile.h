#ifndef __LIBAFL_TARGETS_VALUE_PROFILE__
#define __LIBAFL_TARGETS_VALUE_PROFILE__

#include "common.h"

#ifndef CMP_MAP_SIZE
  #define CMP_MAP_SIZE 65536
#endif

extern uint8_t libafl_cmp_map[CMP_MAP_SIZE];

#ifdef _MSC_VER
  #include <intrin.h>
  #define __builtin_popcount __popcnt
  #define __builtin_popcountll __popcnt64
#endif

static void __libafl_targets_value_profile1(uintptr_t k, uint8_t arg1,
                                            uint8_t arg2) {
  libafl_cmp_map[k] =
      MAX(libafl_cmp_map[k], (__builtin_popcount(~(arg1 ^ arg2))));
}

static void __libafl_targets_value_profile2(uintptr_t k, uint16_t arg1,
                                            uint16_t arg2) {
  libafl_cmp_map[k] =
      MAX(libafl_cmp_map[k], (__builtin_popcount(~(arg1 ^ arg2))));
}

static void __libafl_targets_value_profile4(uintptr_t k, uint32_t arg1,
                                            uint32_t arg2) {
  libafl_cmp_map[k] =
      MAX(libafl_cmp_map[k], (__builtin_popcount(~(arg1 ^ arg2))));
}

static void __libafl_targets_value_profile8(uintptr_t k, uint64_t arg1,
                                            uint64_t arg2) {
  libafl_cmp_map[k] =
      MAX(libafl_cmp_map[k], (__builtin_popcountll(~(arg1 ^ arg2))));
}

#endif
