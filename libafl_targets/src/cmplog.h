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

#ifndef _WIN32
typedef struct CmpLogHeaderExtended {
  unsigned hits : 24;
  unsigned id : 24;
  unsigned shape : 5;
  unsigned type : 2;
  unsigned attribute : 4;
  unsigned overflow : 1;
  unsigned reserved : 4;
} __attribute__((packed)) CmpLogHeaderExtended;
#else
__pragma(pack(push, 1)) typedef struct CmpLogHeaderExtended {
  unsigned hits : 24;
  unsigned id : 24;
  unsigned shape : 5;
  unsigned type : 2;
  unsigned attribute : 4;
  unsigned overflow : 1;
  unsigned reserved : 4;
} CmpLogHeaderExtended;
__pragma(pack(pop))
#endif

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

typedef struct CmpLogMapExtended {
  CmpLogHeaderExtended headers[CMPLOG_MAP_W];
  union {
    CmpLogInstruction operands[CMPLOG_MAP_W][CMPLOG_MAP_H];
    CmpLogRoutine     routines[CMPLOG_MAP_W][CMPLOG_MAP_RTN_H];
  } vals;
} CmpLogMapExtended;

extern CmpLogMap  libafl_cmplog_map;
extern CmpLogMap *libafl_cmplog_map_ptr;

extern CmpLogMapExtended  libafl_cmplog_map_extended;
extern CmpLogMapExtended *libafl_cmplog_map_extended_ptr;

extern uint8_t libafl_cmplog_enabled;

void __libafl_targets_cmplog_instructions(uintptr_t k, uint8_t shape,
                                          uint64_t arg1, uint64_t arg2);

void __libafl_targets_cmplog_routines(uintptr_t k, const uint8_t *ptr1,
                                      const uint8_t *ptr2);

void __libafl_targets_cmplog_routines_len(uintptr_t k, const uint8_t *ptr1,
                                          const uint8_t *ptr2, size_t len);

#endif
