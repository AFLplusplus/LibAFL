#ifndef __LIBAFL_TARGETS_CMPLOG__
#define __LIBAFL_TARGETS_CMPLOG__

#include "common.h"

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


static void __libafl_targets_cmplog(uintptr_t k, uint8_t shape, uint64_t arg1, uint64_t arg2) {


    //if (!libafl_cmplog_enabled) return;

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
  libafl_cmplog_map.operands[k][hits].v0 = arg1;
  libafl_cmplog_map.operands[k][hits].v1 = arg2;
  
}

#endif
