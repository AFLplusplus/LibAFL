#ifndef __LIBAFL_TARGETS_CMPLOG__
#define __LIBAFL_TARGETS_CMPLOG__

#include "common.h"
#include <stddef.h>

#ifndef CMPLOG_MAP_W
  #define CMPLOG_MAP_W 65536
#endif
#ifndef CMPLOG_MAP_H
  #define CMPLOG_MAP_H 32
#endif

#define CMPLOG_RTN_LEN 32

#define CMPLOG_MAP_RTN_H \
  ((CMPLOG_MAP_H * sizeof(CmpLogInstruction)) / sizeof(CmpLogRoutine))

#define CMPLOG_KIND_INS 0
#define CMPLOG_KIND_RTN 1

typedef struct CmpLogHeader {
  uint16_t hits;
  uint8_t  shape;
  uint8_t  kind;
} CmpLogHeader;

typedef struct CmpLogInstruction {
  uint64_t v0;
  uint64_t v1;
} CmpLogInstruction;

typedef struct CmpLogRoutine {
  uint8_t v0[CMPLOG_RTN_LEN];
  uint8_t v1[CMPLOG_RTN_LEN];
} CmpLogRoutine;

typedef struct CmpLogMap {
  CmpLogHeader headers[CMPLOG_MAP_W];
  union {
    CmpLogInstruction operands[CMPLOG_MAP_W][CMPLOG_MAP_H];
    CmpLogRoutine     routines[CMPLOG_MAP_W][CMPLOG_MAP_RTN_H];
  } vals;
} CmpLogMap;

extern CmpLogMap  libafl_cmplog_map;
extern CmpLogMap *libafl_cmplog_map_ptr;

extern uint8_t libafl_cmplog_enabled;

void __libafl_targets_cmplog_instructions(uintptr_t k, uint8_t shape,
                                          uint64_t arg1, uint64_t arg2);

void __libafl_targets_cmplog_routines(uintptr_t k, const uint8_t *ptr1,
                                      const uint8_t *ptr2);

void __libafl_targets_cmplog_routines_len(uintptr_t k, const uint8_t *ptr1,
                                          const uint8_t *ptr2, size_t len);

static inline void __libafl_targets_cmplog(uintptr_t k, uint8_t shape,
                                           uint64_t arg1, uint64_t arg2) {
  if (!libafl_cmplog_enabled) { return; }
  libafl_cmplog_enabled = false;

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
  libafl_cmplog_enabled = true;
}

#endif
