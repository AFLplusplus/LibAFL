#include <stdint.h>

#define CMPLOG_MAP_W 65536
#define CMPLOG_MAP_H 32

#define CMPLOG_KIND_INS 0
#define CMPLOG_KIND_RTN 1

typedef struct CmpLogHeader {
    uint16_t hits;
    uint8_t shape;
    uint8_t kind;
} CmpLogHeader;

typedef struct CmpLogOperands {
    uint64_t v0;
    uint64_t v1;
} CmpLogOperands;

typedef struct CmpLogMap {
  CmpLogHeader headers[CMPLOG_MAP_W];
  CmpLogOperands operands[CMPLOG_MAP_W][CMPLOG_MAP_H];
} CmpLogMap;

extern CmpLogMap libafl_cmplog_map;

extern uint8_t libafl_cmplog_enabled;

#if defined(__APPLE__)
  #pragma weak __sanitizer_cov_trace_const_cmp1 = __sanitizer_cov_trace_cmp1
  #pragma weak __sanitizer_cov_trace_const_cmp2 = __sanitizer_cov_trace_cmp2
  #pragma weak __sanitizer_cov_trace_const_cmp4 = __sanitizer_cov_trace_cmp4
  #pragma weak __sanitizer_cov_trace_const_cmp8 = __sanitizer_cov_trace_cmp8
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

  if (!libafl_cmplog_enabled) return;

  uintptr_t k = (uintptr_t)__builtin_return_address(0);
  k = (k >> 4) ^ (k << 8);
  k &= CMPLOG_MAP_W - 1;
  
  uint16_t hits;
  if (libafl_cmplog_map.headers[k].kind != CMPLOG_KIND_INS) {
    libafl_cmplog_map.headers[k].kind = CMPLOG_KIND_INS;
    libafl_cmplog_map.headers[k].hits = 1;
    libafl_cmplog_map.headers[k].shape = 1;
    hits = 0;
  } else {
    hits = libafl_cmplog_map.headers[k].hits++;
    if (libafl_cmplog_map.headers[k].shape < 1) {
      libafl_cmplog_map.headers[k].shape = 1;
    }
  }

  hits &= CMPLOG_MAP_H - 1;
  libafl_cmplog_map.operands[k][hits].v0 = (uint64_t)arg1;
  libafl_cmplog_map.operands[k][hits].v1 = (uint64_t)arg2;
  
}

void __sanitizer_cov_trace_cmp2(uint16_t arg1, uint16_t arg2) {

  if (!libafl_cmplog_enabled) return;

  uintptr_t k = (uintptr_t)__builtin_return_address(0);
  k = (k >> 4) ^ (k << 8);
  k &= CMPLOG_MAP_W - 1;
  
  uint16_t hits;
  if (libafl_cmplog_map.headers[k].kind != CMPLOG_KIND_INS) {
    libafl_cmplog_map.headers[k].kind = CMPLOG_KIND_INS;
    libafl_cmplog_map.headers[k].hits = 1;
    libafl_cmplog_map.headers[k].shape = 2;
    hits = 0;
  } else {
    hits = libafl_cmplog_map.headers[k].hits++;
    if (libafl_cmplog_map.headers[k].shape < 2) {
      libafl_cmplog_map.headers[k].shape = 2;
    }
  }

  hits &= CMPLOG_MAP_H - 1;
  libafl_cmplog_map.operands[k][hits].v0 = (uint64_t)arg1;
  libafl_cmplog_map.operands[k][hits].v1 = (uint64_t)arg2;

}

void __sanitizer_cov_trace_cmp4(uint32_t arg1, uint32_t arg2) {

  if (!libafl_cmplog_enabled) return;

  uintptr_t k = (uintptr_t)__builtin_return_address(0);
  k = (k >> 4) ^ (k << 8);
  k &= CMPLOG_MAP_W - 1;
  
  uint16_t hits;
  if (libafl_cmplog_map.headers[k].kind != CMPLOG_KIND_INS) {
    libafl_cmplog_map.headers[k].kind = CMPLOG_KIND_INS;
    libafl_cmplog_map.headers[k].hits = 1;
    libafl_cmplog_map.headers[k].shape = 4;
    hits = 0;
  } else {
    hits = libafl_cmplog_map.headers[k].hits++;
    if (libafl_cmplog_map.headers[k].shape < 4) {
      libafl_cmplog_map.headers[k].shape = 4;
    }
  }

  hits &= CMPLOG_MAP_H - 1;
  libafl_cmplog_map.operands[k][hits].v0 = (uint64_t)arg1;
  libafl_cmplog_map.operands[k][hits].v1 = (uint64_t)arg2;
}

void __sanitizer_cov_trace_cmp8(uint64_t arg1, uint64_t arg2) {

  if (!libafl_cmplog_enabled) return;

  uintptr_t k = (uintptr_t)__builtin_return_address(0);
  k = (k >> 4) ^ (k << 8);
  k &= CMPLOG_MAP_W - 1;
  
  uint16_t hits;
  if (libafl_cmplog_map.headers[k].kind != CMPLOG_KIND_INS) {
    libafl_cmplog_map.headers[k].kind = CMPLOG_KIND_INS;
    libafl_cmplog_map.headers[k].hits = 1;
    libafl_cmplog_map.headers[k].shape = 8;
    hits = 0;
  } else {
    hits = libafl_cmplog_map.headers[k].hits++;
    if (libafl_cmplog_map.headers[k].shape < 8) {
      libafl_cmplog_map.headers[k].shape = 8;
    }
  }

  hits &= CMPLOG_MAP_H - 1;
  libafl_cmplog_map.operands[k][hits].v0 = (uint64_t)arg1;
  libafl_cmplog_map.operands[k][hits].v1 = (uint64_t)arg2;

}

void __sanitizer_cov_trace_switch(uint64_t val, uint64_t *cases) {

  if (!libafl_cmplog_enabled) return;
  
  uint8_t shape = (uint8_t)cases[1];
  if (shape) {
      shape /= 8;
  }

  for (uint64_t i = 0; i < cases[0]; i++) {

    uintptr_t k = (uintptr_t)__builtin_return_address(0) + i;
    k = (k >> 4) ^ (k << 8);
    k &= CMPLOG_MAP_W - 1;

    uint16_t hits;
    if (libafl_cmplog_map.headers[k].kind != CMPLOG_KIND_INS) {
      libafl_cmplog_map.headers[k].kind = CMPLOG_KIND_INS;
      libafl_cmplog_map.headers[k].hits = 1;
      libafl_cmplog_map.headers[k].shape = shape;
      hits = 0;
    } else {
      hits = libafl_cmplog_map.headers[k].hits++;
      if (libafl_cmplog_map.headers[k].shape < shape) {
        libafl_cmplog_map.headers[k].shape = shape;
      }
    }

    hits &= CMPLOG_MAP_H - 1;
    libafl_cmplog_map.operands[k][hits].v0 = val;
    libafl_cmplog_map.operands[k][hits].v1 = cases[i + 2];

  }

}
