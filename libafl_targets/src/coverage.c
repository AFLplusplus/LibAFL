#include "common.h"

typedef uint32_t prev_loc_t;

/* Maximum ngram size */
#define NGRAM_SIZE_MAX 16U

/* Maximum K for top-K context sensitivity */
#define CTX_MAX_K 32U

extern uint8_t __afl_area_ptr_local[0];
uint8_t* __afl_area_ptr = __afl_area_ptr_local;

#if defined(__ANDROID__) || defined(__HAIKU__)
prev_loc_t __afl_prev_loc[NGRAM_SIZE_MAX];
prev_loc_t __afl_prev_caller[CTX_MAX_K];
uint32_t   __afl_prev_ctx;
#else
__thread prev_loc_t __afl_prev_loc[NGRAM_SIZE_MAX];
__thread prev_loc_t __afl_prev_caller[CTX_MAX_K];
__thread uint32_t   __afl_prev_ctx;
#endif
