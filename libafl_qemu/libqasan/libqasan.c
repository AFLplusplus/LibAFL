/*******************************************************************************
Copyright (c) 2019-2020, Andrea Fioraldi


Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*******************************************************************************/

#include "libqasan.h"

#ifdef DEBUG
int __qasan_debug;
#endif
int __qasan_log;

void __libqasan_print_maps(void) {
  int  fd = open("/proc/self/maps", O_RDONLY);
  char buf[4096] = {0};

  read(fd, buf, 4095);
  close(fd);

  size_t len = __libqasan_strlen(buf);

  QASAN_LOG("Guest process maps:\n");
  int   i;
  char *line = NULL;
  for (i = 0; i < len; i++) {
    if (!line) line = &buf[i];
    if (buf[i] == '\n') {
      buf[i] = 0;
      QASAN_LOG("%s\n", line);
      line = NULL;
    }
  }

  if (line) { QASAN_LOG("%s\n", line); }
  QASAN_LOG("\n");
}

int __libqasan_is_initialized = 0;

__attribute__((always_inline)) inline size_t qasan_align_down(size_t val,
                                                              size_t align) {
  return (val & ~(align - 1));
}

__attribute__((always_inline)) inline size_t qasan_align_up(size_t val,
                                                            size_t align) {
  return qasan_align_down(val + align - 1, align);
}

#ifdef ASAN_GUEST
static void __libqasan_map_shadow(void *addr, void *limit) {
  size_t size = (limit - addr) + 1;
  void  *map = mmap(addr, size, PROT_READ | PROT_WRITE,
                    MAP_FIXED | MAP_FIXED_NOREPLACE | MAP_PRIVATE |
                        MAP_ANONYMOUS | MAP_NORESERVE,
                    -1, 0);
  if (map != addr) {
    QASAN_LOG("Failed to map shadow: %p-%p, errno: %d", addr, limit + 1, errno);
    abort();
  }

  if (madvise(addr, size, MADV_HUGEPAGE) != 0) {
    QASAN_LOG("Failed to madvise (MADV_HUGEPAGE) shadow: %p-%p, errno: %d",
              addr, limit + 1, errno);
    abort();
  }
}
#endif

#ifdef ASAN_GUEST

const size_t ALLOC_ALIGN_POW = 3;
const size_t ALLOC_ALIGN_SIZE = (1UL << ALLOC_ALIGN_POW);
  #if defined(__x86_64__) || defined(__aarch64__)
    #define SHADOW_OFFSET (0x7fff8000)
  #else
    #define SHADOW_OFFSET (0x20000000)
  #endif
#endif

__attribute__((constructor)) void __libqasan_init() {
  if (__libqasan_is_initialized) { return; }
  __libqasan_is_initialized = 1;

  __libqasan_init_hooks();

  if (getenv("AFL_INST_LIBS") || getenv("QASAN_HOTPACH")) {
    __libqasan_hotpatch();
  }

#ifdef DEBUG
  __qasan_debug = getenv("QASAN_DEBUG") != NULL;
#endif
  __qasan_log = getenv("QASAN_LOG") != NULL;

  QASAN_LOG("QEMU-AddressSanitizer (v%s)\n", QASAN_VERSTR);
  QASAN_LOG(
      "Copyright (C) 2019-2021 Andrea Fioraldi <andreafioraldi@gmail.com>\n");
  QASAN_LOG("\n");

#ifdef ASAN_GUEST
  QASAN_DEBUG("QASAN - Debugging is enabled!!!\n");
  /* MMap our shadow and madvise to use huge pages */
  #if defined(__x86_64__) || defined(__aarch64__)
  // [0x10007fff8000, 0x7fffffffffff] 	HighMem
  // [0x02008fff7000, 0x10007fff7fff] 	HighShadow
  // [0x00008fff7000, 0x02008fff6fff] 	ShadowGap
  // [0x00007fff8000, 0x00008fff6fff] 	LowShadow
  // [0x000000000000, 0x00007fff7fff] 	LowMem
  __libqasan_map_shadow((void *)0x02008fff7000, (void *)0x10007fff7fff);
  __libqasan_map_shadow((void *)0x00007fff8000, (void *)0x00008fff6fff);

  #else
  // [0x40000000, 0xffffffff] 	HighMem
  // [0x28000000, 0x3fffffff] 	HighShadow
  // [0x24000000, 0x27ffffff] 	ShadowGap
  // [0x20000000, 0x23ffffff] 	LowShadow
  // [0x00000000, 0x1fffffff] 	LowMem
  __libqasan_map_shadow((void *)0x28000000, (void *)0x3fffffff);
  __libqasan_map_shadow((void *)0x20000000, (void *)0x23ffffff);
  #endif

#endif

  // if (__qasan_log) { __libqasan_print_maps(); }
}

#ifdef ASAN_GUEST

__attribute__((always_inline)) static inline char *qasan_get_shadow(
    const char *start) {
  size_t shadow_addr = ((size_t)start >> ALLOC_ALIGN_POW) + SHADOW_OFFSET;
  return ((char *)shadow_addr);
}

__attribute__((always_inline)) static inline const char *qasan_align_ptr_down(
    const char *start, size_t n) {
  return (const char *)qasan_align_down((size_t)start, n);
}

__attribute__((always_inline)) static inline const char *qasan_align_ptr_up(
    const char *start, size_t n) {
  return qasan_align_ptr_down(&start[n - 1], n);
}

static bool qemu_mem_test(const char *k_start, const char *k_end) {
  for (const char *cursor = k_start; cursor < k_end; cursor++) {
    char k = *cursor;
    if (k != 0) {
      QASAN_DEBUG("qemu_mem_test - k_start: %p, k_end: %p, cursor: %p, k: %d\n",
                  k_start, k_end, cursor, k);
      return true;
    }
  }

  return false;
}

static void qemu_mem_set(char *k_start, char *k_end, char val) {
  for (char *cursor = (char *)k_start; cursor < k_end; cursor++) {
    *cursor = val;
  }
}

/* Our end point should be 8-byte aligned */
void qasan_load(const char *start, size_t len) {
  QASAN_DEBUG("LOAD: %p-%p\n", start, &start[len]);
  if (qasan_is_poison(start, len)) {
    QASAN_LOG("Region is poisoned: %p-%p\n", start, &start[len]);
    abort();
  }
}

void qasan_store(const char *start, size_t len) {
  QASAN_DEBUG("STORE: %p-%p\n", start, &start[len]);
  if (qasan_is_poison(start, len)) {
    QASAN_LOG("Region is poisoned: %p-%p\n", start, &start[len]);
    abort();
  }
}

void qasan_poison(const char *start, size_t len, char val) {
  const char *end = &start[len];
  QASAN_DEBUG("POISON: %p-%p, (%zu) 0x%02x\n", start, end, len, val);

  const char *start_aligned = qasan_align_ptr_up(start, ALLOC_ALIGN_SIZE);
  const char *end_aligned = qasan_align_ptr_down(end, ALLOC_ALIGN_SIZE);

  if (len == 0) return;

  if (end != end_aligned) {
    QASAN_LOG("Region end is unaligned: %p-%p, end_aligned: %p\n", start, end,
              end_aligned);
    abort();
  }

  /* k > 0 (first k bytes are UN-poisoned */
  size_t first_unpoisoned = ALLOC_ALIGN_SIZE - (start_aligned - start);
  QASAN_DEBUG("UNPOIS - first_unpoisoned: %zu\n", first_unpoisoned);

  char *k_start = qasan_get_shadow(start);
  QASAN_DEBUG("UNPOISON - k_start: %p\n", k_start);

  if (first_unpoisoned == 0) {
    *k_start = val;
  } else {
    *k_start = first_unpoisoned;
  }

  /*
   * The end is aligned, so we can round up the start and deal with the
   * remaining aligned buffer now
   */
  char *k_start_aligned = qasan_get_shadow(start_aligned);
  char *k_end_aligned = qasan_get_shadow(end_aligned);

  QASAN_DEBUG("POISONk: %p-%p\n", k_start_aligned, k_end_aligned);

  qemu_mem_set(k_start_aligned, k_end_aligned, val);
  QASAN_DEBUG("POISONED: %p-%p, 0x%02x\n", start, end, val);
}

void qasan_unpoison(const char *start, size_t len) {
  const char *end = &start[len];
  QASAN_DEBUG("UNPOISON: %p-%p (%zu)\n", start, end, len);

  const char *start_aligned = qasan_align_ptr_up(start, ALLOC_ALIGN_SIZE);
  const char *end_aligned = qasan_align_ptr_down(end, ALLOC_ALIGN_SIZE);

  if (len == 0) return;

  if (start_aligned != start) {
    QASAN_LOG("Region start is unaligned: %p-%p, start_aligned: %p\n", start,
              end, start_aligned);
    abort();
  }

  char *k_start_aligned = qasan_get_shadow(k_start_aligned);
  char *k_end_aligned = qasan_get_shadow(k_end_aligned);

  QASAN_DEBUG("UNPOISONk: %p-%p\n", k_start_aligned, k_end_aligned);

  qemu_mem_set(k_start_aligned, k_end_aligned, 0);

  size_t last_unpoisoned = end - end_aligned;
  QASAN_DEBUG("UNPOISON - last_unpoisoned: %zu\n", last_unpoisoned);

  char *k_end = qasan_get_shadow(end);
  QASAN_DEBUG("UNPOISON - k_end: %p\n", k_end);

  *k_end = (char)last_unpoisoned;

  QASAN_DEBUG("UNPOISONED: %p-%p\n", start, end);
}

bool qasan_is_poison(const char *start, size_t len) {
  const char *end = &start[len];
  QASAN_DEBUG("IS POISON: %p-%p (%zu)\n", start, end, len);

  const char *start_aligned = qasan_align_ptr_up(start, ALLOC_ALIGN_SIZE);
  const char *end_aligned = qasan_align_ptr_down(end, ALLOC_ALIGN_SIZE);

  if (len == 0) return false;

  /* If our start is unaligned */
  if (start_aligned != start) {
    char *k_start = qasan_get_shadow(start);
    QASAN_DEBUG("IS POISON - k_start: %p\n", k_start);

    size_t first_k = (size_t)*k_start;
    QASAN_DEBUG("IS POISON - first_k: %zu\n", first_k);

    /* If our buffer ends within the first shadow byte */
    if (end < start_aligned) {
      size_t first_len = end - end_aligned;
      QASAN_DEBUG("IS POISON - first_len: %zu\n", first_len);

      if ((first_k != 0) && (first_len > first_k)) {
        QASAN_DEBUG(
            "qasan_is_poison #1 - start_aligned: %p, end_aligned: %p, first_k: "
            "%d, first_len: %zu\n",
            start_aligned, end_aligned, first_k, first_len);
        return true;
      }

      return false;
    }

    /*
     * If our buffer extends beyond the first shadow byte, then it must be
     * zero
     */
    if (first_k != 0) {
      QASAN_DEBUG(
          "qasan_is_poison #2 - start_aligned: %p, end_aligned: %p, first_k: "
          "%d\n",
          start_aligned, end_aligned, first_k);
      return true;
    }
  }

  /* If our end is unaligned */
  if (end_aligned != end) {
    size_t last_len = end - end_aligned;
    QASAN_DEBUG("IS POISON - last_len: %zu\n", last_len);

    char *k_end = qasan_get_shadow(end);
    QASAN_DEBUG("IS POISON - k_end: %p\n", k_end);

    char last_k = *k_end;
    QASAN_DEBUG("IS POISON - last_k: %zu\n", last_k);

    if ((last_k != 0) && (last_len > last_k)) {
      QASAN_DEBUG(
          "qasan_is_poison #3 - start_aligned: %p, end_aligned: %p, last_k: "
          "%d, last_len: %zu\n",
          start_aligned, end_aligned, last_k, last_len);
      return true;
    }
  }

  const char *k_start_aligned = qasan_get_shadow(start_aligned);
  QASAN_DEBUG("IS POISON - k_start_aligned: %p\n", k_start_aligned);

  const char *k_end_aligned = qasan_get_shadow(end_aligned);
  QASAN_DEBUG("IS POISON - k_end_aligned: %p\n", k_end_aligned);

  return qemu_mem_test(k_start_aligned, k_end_aligned);
}

void qasan_alloc(const char *start, const char *end) {
  QASAN_DEBUG("ALLOC: %p-%p\n", start, end);
  /* Do Nothing - We don't track allocations */
}

void qasan_dealloc(const char *start) {
  QASAN_DEBUG("DEALLOC: %p\n", start);
  /* Do Nothing - We don't track allocations */
}

int qasan_swap(int state) {
  QASAN_DEBUG("SWAP: %d\n", state);
  /* Do Nothing */
  return 0;
}
#endif

int __libc_start_main(int (*main)(int, char **, char **), int argc, char **argv,
                      int (*init)(int, char **, char **), void (*fini)(void),
                      void (*rtld_fini)(void), void *stack_end) {
  typeof(&__libc_start_main) orig = dlsym(RTLD_NEXT, "__libc_start_main");

  __libqasan_init();

  return orig(main, argc, argv, init, fini, rtld_fini, stack_end);
}
