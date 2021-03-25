#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MAP_SIZE (16*1024)

int orig_argc;
char **orig_argv;
char **orig_envp;

uint8_t  __lafl_dummy_map[MAP_SIZE];
size_t  __lafl_dummy_map_usize[MAP_SIZE];

uint8_t *__lafl_edges_map = __lafl_dummy_map;
uint8_t *__lafl_cmp_map = __lafl_dummy_map;
size_t *__lafl_alloc_map = __lafl_dummy_map_usize;

uint32_t __lafl_max_edges_size = 0;

void __sanitizer_cov_trace_pc_guard(uint32_t *guard) {

  uint32_t pos = *guard;
  uint16_t val = __lafl_edges_map[pos] + 1;
  __lafl_edges_map[pos] = ((uint8_t) val) + (uint8_t) (val >> 8);
  //__lafl_edges_map[pos] = 1;

}

void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop) {

  if (start == stop || *start) { return; }

  *(start++) = (++__lafl_max_edges_size) & (MAP_SIZE -1);

  while (start < stop) {

    *start = (++__lafl_max_edges_size) & (MAP_SIZE -1);
    start++;

  }

}

#define MAX(a, b)           \
  ({                        \
                            \
    __typeof__(a) _a = (a); \
    __typeof__(b) _b = (b); \
    _a > _b ? _a : _b;      \
                            \
  })

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

  uintptr_t k = (uintptr_t)__builtin_return_address(0);
  k = (k >> 4) ^ (k << 8);
  k &= MAP_SIZE - 1;
  __lafl_cmp_map[k] = MAX(__lafl_cmp_map[k], (__builtin_popcount(~(arg1 ^ arg2))));

}

void __sanitizer_cov_trace_cmp2(uint16_t arg1, uint16_t arg2) {

  uintptr_t k = (uintptr_t)__builtin_return_address(0);
  k = (k >> 4) ^ (k << 8);
  k &= MAP_SIZE - 1;
  __lafl_cmp_map[k] = MAX(__lafl_cmp_map[k], (__builtin_popcount(~(arg1 ^ arg2))));

}

void __sanitizer_cov_trace_cmp4(uint32_t arg1, uint32_t arg2) {

  uintptr_t k = (uintptr_t)__builtin_return_address(0);
  k = (k >> 4) ^ (k << 8);
  k &= MAP_SIZE - 1;
  __lafl_cmp_map[k] = MAX(__lafl_cmp_map[k], (__builtin_popcount(~(arg1 ^ arg2))));

}

void __sanitizer_cov_trace_cmp8(uint64_t arg1, uint64_t arg2) {

  uintptr_t k = (uintptr_t)__builtin_return_address(0);
  k = (k >> 4) ^ (k << 8);
  k &= MAP_SIZE - 1;
  __lafl_cmp_map[k] = MAX(__lafl_cmp_map[k], (__builtin_popcountll(~(arg1 ^ arg2))));

}

void __sanitizer_cov_trace_switch(uint64_t val, uint64_t *cases) {

  uintptr_t rt = (uintptr_t)__builtin_return_address(0);
  if (cases[1] == 64) {

    for (uint64_t i = 0; i < cases[0]; i++) {

      uintptr_t k = rt + i;
      k = (k >> 4) ^ (k << 8);
      k &= MAP_SIZE - 1;
      __lafl_cmp_map[k] = MAX(__lafl_cmp_map[k], (__builtin_popcountll(~(val ^ cases[i + 2]))));

    }

  } else {

    for (uint64_t i = 0; i < cases[0]; i++) {

      uintptr_t k = rt + i;
      k = (k >> 4) ^ (k << 8);
      k &= MAP_SIZE - 1;
      __lafl_cmp_map[k] = MAX(__lafl_cmp_map[k], (__builtin_popcount(~(val ^ cases[i + 2]))));

    }

  }

}

#ifdef _WIN32
#define posix_memalign(p, a, s) (((*(p)) = _aligned_malloc((s), (a))), *(p) ?0 :errno)
#endif

void *malloc(size_t size) {

  uintptr_t k = (uintptr_t)__builtin_return_address(0);
  k = (k >> 4) ^ (k << 8);
  k &= MAP_SIZE - 1;
  __lafl_alloc_map[k] = MAX(__lafl_alloc_map[k], size);

  // We cannot malloc in malloc.
  // Hence, even realloc(NULL, size) would loop in an optimized build.
  // We fall back to a stricter allocation function. Fingers crossed.
  void *ret = NULL;
  posix_memalign(&ret, 1<<6, size);
  return ret;

}

void *calloc(size_t nmemb, size_t size) {

  size *= nmemb;

  uintptr_t k = (uintptr_t)__builtin_return_address(0);
  k = (k >> 4) ^ (k << 8);
  k &= MAP_SIZE - 1;
  __lafl_alloc_map[k] = MAX(__lafl_alloc_map[k], size);

  void *ret = NULL;
  posix_memalign(&ret, 1<<6, size);
  memset(ret, 0, size);
  return ret;

}

static void afl_libfuzzer_copy_args(int argc, char** argv, char** envp) {
   orig_argc = argc;
   orig_argv = argv;
   orig_envp = envp;
}

__attribute__((section(".init_array"))) void (* p_afl_libfuzzer_copy_args)(int,char*[],char*[]) = &afl_libfuzzer_copy_args;

__attribute__((weak)) int LLVMFuzzerInitialize(int *argc, char ***argv);
void afl_libfuzzer_main();

int afl_libfuzzer_init() {

  if (LLVMFuzzerInitialize) {
    return LLVMFuzzerInitialize(&orig_argc, &orig_argv);
  } else {
   return 0;
  }

}
