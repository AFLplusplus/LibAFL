#include "common.h"

typedef uint32_t prev_loc_t;

/* Maximum ngram size */
#define NGRAM_SIZE_MAX 16U

/* Maximum K for top-K context sensitivity */
#define CTX_MAX_K 32U

extern uint8_t __afl_area_ptr_local[EDGES_MAP_SIZE];

uint8_t* __afl_area_ptr = __afl_area_ptr_local;


// Weak symbols, LLVM Passes overwrites them if we really use it
#ifdef __linux__
extern uint8_t __attribute__((weak)) __start_libafl_token;
extern uint8_t __attribute__((weak)) __stop_libafl_token;

// Expose the start of libafl_token section as C symbols
uint8_t* __token_start = &__start_libafl_token;
uint8_t* __token_end = &__stop_libafl_token;
#endif



//#if defined(__ANDROID__) || defined(__HAIKU__)
MAYBE_THREAD_LOCAL prev_loc_t __afl_prev_loc[NGRAM_SIZE_MAX];
MAYBE_THREAD_LOCAL prev_loc_t __afl_prev_caller[CTX_MAX_K];
MAYBE_THREAD_LOCAL uint32_t   __afl_prev_ctx;
