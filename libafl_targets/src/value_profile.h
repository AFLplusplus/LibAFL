#ifndef __LIBAFL_TARGETS_VALUE_PROFILE__
#define __LIBAFL_TARGETS_VALUE_PROFILE__

#include <stdint.h>
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

const uintptr_t kMapSizeInBits = CMP_MAP_SIZE * 8;
const uintptr_t kBitsInByte = sizeof(uint8_t) * 8;

static inline void AddValue(uintptr_t k) {
  uintptr_t Idx = k % kMapSizeInBits;  // adjust it so it fits in map sz

  uintptr_t ByteIdx = Idx / kBitsInByte;
  uintptr_t BitIdx = Idx % kBitsInByte;

  uint8_t Old = libafl_cmp_map[ByteIdx];
  uint8_t New = Old | (1ULL << BitIdx);
  libafl_cmp_map[ByteIdx] = New;
}

#define HUMMING_DISTANCE(a, b) __builtin_popcount(~(a ^ b))
#define ABSOLUTE_DISTANCE(a, b) (a == b ? 0 : __builtin_clzll(a - b) + 1)

static void __libafl_targets_value_profile1(uintptr_t k, uint8_t arg1,
                                            uint8_t arg2) {
  AddValue(k + HUMMING_DISTANCE(arg1, arg2));
  AddValue(k + ABSOLUTE_DISTANCE(arg1, arg2));
}

static void __libafl_targets_value_profile2(uintptr_t k, uint16_t arg1,
                                            uint16_t arg2) {
  AddValue(k + HUMMING_DISTANCE(arg1, arg2));
  AddValue(k + ABSOLUTE_DISTANCE(arg1, arg2));
}

static void __libafl_targets_value_profile4(uintptr_t k, uint32_t arg1,
                                            uint32_t arg2) {
  AddValue(k + HUMMING_DISTANCE(arg1, arg2));
  AddValue(k + ABSOLUTE_DISTANCE(arg1, arg2));
}

static void __libafl_targets_value_profile8(uintptr_t k, uint64_t arg1,
                                            uint64_t arg2) {
  AddValue(k + HUMMING_DISTANCE(arg1, arg2));
  AddValue(k + ABSOLUTE_DISTANCE(arg1, arg2));
}

#endif
