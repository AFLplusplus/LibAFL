#include "common.h"

typedef uint32_t prev_loc_t;

/* Maximum ngram size */
#define NGRAM_SIZE_MAX 16U

/* Maximum K for top-K context sensitivity */
#define CTX_MAX_K 32U

extern uint8_t __afl_area_ptr_local[0];
uint8_t* __afl_area_ptr = __afl_area_ptr_local;

//#if defined(__ANDROID__) || defined(__HAIKU__)
MAYBE_THREAD_LOCAL prev_loc_t __afl_prev_loc[NGRAM_SIZE_MAX];
MAYBE_THREAD_LOCAL prev_loc_t __afl_prev_caller[CTX_MAX_K];
MAYBE_THREAD_LOCAL uint32_t   __afl_prev_ctx;
