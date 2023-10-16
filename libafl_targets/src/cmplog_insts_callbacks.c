/*
  CMPLOG Callback for instructions
  Why we have functions that does the thing (like cmplog_instructions_inlined
  and __libafl_targets_cmplog_instructions?) because for
  __libafl_targets_cmplog_instructions, we can't inline them (they need to be
  exposed so that sancov can find them) but when we use our LLVM Passes we could
  just inline them, resulting one less function call per one cmplog calling
  site.
*/
#include <stdint.h>
#include <sys/types.h>
#include "cmplog.h"
extern CmpLogMap         *libafl_cmplog_map_ptr;
extern CmpLogMapExtended *libafl_cmplog_map_extended_ptr;

inline void cmplog_instructions_inlined(uintptr_t k, uint8_t shape,
                                        uint64_t arg1, uint64_t arg2) {
  uint16_t hits;
  if (libafl_cmplog_map_ptr->headers[k].kind != CMPLOG_KIND_INS) {
    libafl_cmplog_map_ptr->headers[k].kind = CMPLOG_KIND_INS;
    libafl_cmplog_map_ptr->headers[k].hits = 1;
    libafl_cmplog_map_ptr->headers[k].shape = shape;
    hits = 0;
  } else {
    hits = libafl_cmplog_map_ptr->headers[k].hits++;
    if (libafl_cmplog_map_ptr->headers[k].shape < shape) {
      libafl_cmplog_map_ptr->headers[k].shape = shape;
    }
  }
  hits &= CMPLOG_MAP_H - 1;
  libafl_cmplog_map_ptr->vals.operands[k][hits].v0 = arg1;
  libafl_cmplog_map_ptr->vals.operands[k][hits].v1 = arg2;
}

inline int16_t cmplog_instructions_extended_inlined(uintptr_t k, uint8_t shape,
                                                    uint64_t arg1,
                                                    uint64_t arg2,
                                                    uint8_t  attr) {
  uint16_t hits;
  if (libafl_cmplog_map_extended_ptr->headers[k].type != CMPLOG_KIND_INS) {
    libafl_cmplog_map_extended_ptr->headers[k].type = CMPLOG_KIND_INS;
    libafl_cmplog_map_extended_ptr->headers[k].hits = 1;
    libafl_cmplog_map_extended_ptr->headers[k].shape = shape;
    hits = 0;
  } else {
    hits = libafl_cmplog_map_extended_ptr->headers[k].hits++;
    if (libafl_cmplog_map_extended_ptr->headers[k].shape < shape) {
      libafl_cmplog_map_extended_ptr->headers[k].shape = shape;
    }
  }
  hits &= CMPLOG_MAP_H - 1;
  libafl_cmplog_map_extended_ptr->vals.operands[k][hits].v0 = arg1;
  libafl_cmplog_map_extended_ptr->vals.operands[k][hits].v1 = arg2;
  libafl_cmplog_map_extended_ptr->headers[k].attribute = attr;
  return hits;
}
void __cmplog_ins_hook1_extended(uint8_t arg1, uint8_t arg2, uint8_t attr) {
  if (!libafl_cmplog_enabled) { return; }
  libafl_cmplog_enabled = false;
  uintptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);
  k &= CMPLOG_MAP_W - 1;

  cmplog_instructions_extended_inlined(k, 0, arg1, arg2, attr);
  libafl_cmplog_enabled = true;
}
void __cmplog_ins_hook1(uint8_t arg1, uint8_t arg2) {
  if (!libafl_cmplog_enabled) { return; }
  libafl_cmplog_enabled = false;
  uintptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);
  k &= CMPLOG_MAP_W - 1;

  cmplog_instructions_inlined(k, 1, arg1, arg2);
  libafl_cmplog_enabled = true;
}
void __cmplog_ins_hook1_ctx_extended(uint32_t ctx, uint8_t arg1, uint8_t arg2, uint8_t attr) {
  if (!libafl_cmplog_enabled) { return; }
  libafl_cmplog_enabled = false;
  uintptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);
  k ^= ctx;
  k &= CMPLOG_MAP_W - 1;
  

  cmplog_instructions_extended_inlined(k, 0, arg1, arg2, attr);
  libafl_cmplog_enabled = true;
}
void __cmplog_ins_hook1_ctx(uint32_t ctx, uint8_t arg1, uint8_t arg2) {
  if (!libafl_cmplog_enabled) { return; }
  libafl_cmplog_enabled = false;
  uintptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);
  k ^= ctx;
  k &= CMPLOG_MAP_W - 1;

  cmplog_instructions_inlined(k, 1, arg1, arg2);
  libafl_cmplog_enabled = true;
}

void __cmplog_ins_hook2_extended(uint16_t arg1, uint16_t arg2, uint8_t attr) {
  if (!libafl_cmplog_enabled) { return; }
  libafl_cmplog_enabled = false;
  uintptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);
  k &= CMPLOG_MAP_W - 1;

  cmplog_instructions_extended_inlined(k, 1, arg1, arg2, attr);
  libafl_cmplog_enabled = true;
}
void __cmplog_ins_hook2(uint16_t arg1, uint16_t arg2) {
  if (!libafl_cmplog_enabled) { return; }
  libafl_cmplog_enabled = false;
  uintptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);
  k &= CMPLOG_MAP_W - 1;

  cmplog_instructions_inlined(k, 2, arg1, arg2);
  libafl_cmplog_enabled = true;
}
void __cmplog_ins_hook2_ctx_extended(uint32_t ctx, uint16_t arg1, uint16_t arg2, uint8_t attr) {
  if (!libafl_cmplog_enabled) { return; }
  libafl_cmplog_enabled = false;
  uintptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);
  k ^= ctx;
  k &= CMPLOG_MAP_W - 1;

  cmplog_instructions_extended_inlined(k, 1, arg1, arg2, attr);
  libafl_cmplog_enabled = true;
}
void __cmplog_ins_hook2_ctx(uint32_t ctx, uint16_t arg1, uint16_t arg2) {
  if (!libafl_cmplog_enabled) { return; }
  libafl_cmplog_enabled = false;
  uintptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);
  k ^= ctx;
  k &= CMPLOG_MAP_W - 1;

  cmplog_instructions_inlined(k, 2, arg1, arg2);
  libafl_cmplog_enabled = true;
}


void __cmplog_ins_hook4_extended(uint32_t arg1, uint32_t arg2, uint8_t attr) {
  if (!libafl_cmplog_enabled) { return; }
  libafl_cmplog_enabled = false;
  uintptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);
  k &= CMPLOG_MAP_W - 1;

  cmplog_instructions_extended_inlined(k, 3, arg1, arg2, attr);
  libafl_cmplog_enabled = true;
}
void __cmplog_ins_hook4(uint32_t arg1, uint32_t arg2) {
  if (!libafl_cmplog_enabled) { return; }
  libafl_cmplog_enabled = false;
  uintptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);
  k &= CMPLOG_MAP_W - 1;

  cmplog_instructions_inlined(k, 4, arg1, arg2);
  libafl_cmplog_enabled = true;
}
void __cmplog_ins_hook4_ctx_extended(uint32_t ctx, uint32_t arg1, uint32_t arg2, uint8_t attr) {
  if (!libafl_cmplog_enabled) { return; }
  libafl_cmplog_enabled = false;
  uintptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);
  k ^= ctx;
  k &= CMPLOG_MAP_W - 1;

  cmplog_instructions_extended_inlined(k, 3, arg1, arg2, attr);
  libafl_cmplog_enabled = true;
}
void __cmplog_ins_hook4_ctx(uint32_t ctx, uint32_t arg1, uint32_t arg2) {
  if (!libafl_cmplog_enabled) { return; }
  libafl_cmplog_enabled = false;
  uintptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);
  k ^= ctx;
  k &= CMPLOG_MAP_W - 1;

  cmplog_instructions_inlined(k, 4, arg1, arg2);
  libafl_cmplog_enabled = true;
}

void __cmplog_ins_hook8_extended(uint64_t arg1, uint64_t arg2, uint8_t attr) {
  if (!libafl_cmplog_enabled) { return; }
  libafl_cmplog_enabled = false;
  uintptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);
  k &= CMPLOG_MAP_W - 1;

  cmplog_instructions_extended_inlined(k, 7, arg1, arg2, attr);
  libafl_cmplog_enabled = true;
}
void __cmplog_ins_hook8(uint64_t arg1, uint64_t arg2) {
  if (!libafl_cmplog_enabled) { return; }
  libafl_cmplog_enabled = false;
  uintptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);
  k &= CMPLOG_MAP_W - 1;

  cmplog_instructions_inlined(k, 8, arg1, arg2);
  libafl_cmplog_enabled = true;
}
void __cmplog_ins_hook8_ctx_extended(uint32_t ctx, uint64_t arg1, uint64_t arg2, uint8_t attr) {
  if (!libafl_cmplog_enabled) { return; }
  libafl_cmplog_enabled = false;
  uintptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);
  k ^= ctx;
  k &= CMPLOG_MAP_W - 1;

  cmplog_instructions_extended_inlined(k, 7, arg1, arg2, attr);
  libafl_cmplog_enabled = true;
}
void __cmplog_ins_hook8_ctx(uint32_t ctx, uint64_t arg1, uint64_t arg2) {
  if (!libafl_cmplog_enabled) { return; }
  libafl_cmplog_enabled = false;
  uintptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);
  k ^= ctx;
  k &= CMPLOG_MAP_W - 1;

  cmplog_instructions_inlined(k, 8, arg1, arg2);
  libafl_cmplog_enabled = true;
}

#ifndef _WIN32
void __cmplog_ins_hook16_extended(uint128_t arg1, uint128_t arg2,
                                  uint8_t attr) {
  if (!libafl_cmplog_enabled) { return; }
  libafl_cmplog_enabled = false;
  uintptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);
  k &= CMPLOG_MAP_W - 1;

  uint16_t hits = cmplog_instructions_extended_inlined(k, 15, arg1, arg2, attr);
  libafl_cmplog_map_extended_ptr->vals.operands[k][hits].v0_128 =
      (uint64_t)(arg1 >> 64);
  libafl_cmplog_map_extended_ptr->vals.operands[k][hits].v1_128 =
      (uint64_t)(arg2 >> 64);
  libafl_cmplog_enabled = true;
}
void __cmplog_ins_hook16(uint128_t arg1, uint128_t arg2) {
  if (!libafl_cmplog_enabled) { return; }
  libafl_cmplog_enabled = false;
  uintptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);
  k &= CMPLOG_MAP_W - 1;

  cmplog_instructions_inlined(k, 16, arg1, arg2);
  libafl_cmplog_enabled = true;
}
void __cmplog_ins_hook16_ctx_extended(uint32_t ctx, uint128_t arg1, uint128_t arg2,
                                  uint8_t attr) {
  if (!libafl_cmplog_enabled) { return; }
  libafl_cmplog_enabled = false;
  uintptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);
  k ^= ctx;
  k &= CMPLOG_MAP_W - 1;

  uint16_t hits = cmplog_instructions_extended_inlined(k, 15, arg1, arg2, attr);
  libafl_cmplog_map_extended_ptr->vals.operands[k][hits].v0_128 =
      (uint64_t)(arg1 >> 64);
  libafl_cmplog_map_extended_ptr->vals.operands[k][hits].v1_128 =
      (uint64_t)(arg2 >> 64);
  libafl_cmplog_enabled = true;
}
void __cmplog_ins_hook16_ctx(uint32_t ctx, uint128_t arg1, uint128_t arg2) {
  if (!libafl_cmplog_enabled) { return; }
  libafl_cmplog_enabled = false;
  uintptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);
  k ^= ctx;
  k &= CMPLOG_MAP_W - 1;

  cmplog_instructions_inlined(k, 16, arg1, arg2);
  libafl_cmplog_enabled = true;
}

void __cmplog_ins_hookN_extended(uint128_t arg1, uint128_t arg2, uint8_t attr,
                                 uint8_t size) {
  if (!libafl_cmplog_enabled) { return; }
  libafl_cmplog_enabled = false;
  uintptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);
  k &= CMPLOG_MAP_W - 1;

  uint16_t hits =
      cmplog_instructions_extended_inlined(k, size - 1, arg1, arg2, attr);
  if (size > 8) {
    libafl_cmplog_map_extended_ptr->vals.operands[k][hits].v0_128 =
        (uint64_t)(arg1 >> 64);
    libafl_cmplog_map_extended_ptr->vals.operands[k][hits].v1_128 =
        (uint64_t)(arg2 >> 64);
  }
  libafl_cmplog_enabled = true;
}
void __cmplog_ins_hookN(uint128_t arg1, uint128_t arg2, uint8_t size) {
  if (!libafl_cmplog_enabled) { return; }
  libafl_cmplog_enabled = false;
  uintptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);
  k &= CMPLOG_MAP_W - 1;

  cmplog_instructions_inlined(k, size, arg1, arg2);
  libafl_cmplog_enabled = true;
}
void __cmplog_ins_hookN_ctx_extended(uint32_t ctx, uint128_t arg1, uint128_t arg2, uint8_t attr,
                                 uint8_t size) {
  if (!libafl_cmplog_enabled) { return; }
  libafl_cmplog_enabled = false;
  uintptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);
  k ^= ctx;
  k &= CMPLOG_MAP_W - 1;

  uint16_t hits =
      cmplog_instructions_extended_inlined(k, size - 1, arg1, arg2, attr);
  if (size > 8) {
    libafl_cmplog_map_extended_ptr->vals.operands[k][hits].v0_128 =
        (uint64_t)(arg1 >> 64);
    libafl_cmplog_map_extended_ptr->vals.operands[k][hits].v1_128 =
        (uint64_t)(arg2 >> 64);
  }
  libafl_cmplog_enabled = true;
}
void __cmplog_ins_hookN_ctx(uint32_t ctx, uint128_t arg1, uint128_t arg2, uint8_t size) {
  if (!libafl_cmplog_enabled) { return; }
  libafl_cmplog_enabled = false;
  uintptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);
  k ^= ctx;
  k &= CMPLOG_MAP_W - 1;

  cmplog_instructions_inlined(k, size, arg1, arg2);
  libafl_cmplog_enabled = true;
}
#endif