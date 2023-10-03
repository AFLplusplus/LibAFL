// From AFL++'s afl-compiler-rt.c

#define CMPLOG_MODULE
#include "common.h"
#include "cmplog.h"
#include <string.h>

#if defined(_WIN32)

  #include <windows.h>

void *__libafl_asan_region_is_poisoned(void *beg, size_t size) {
  (void)beg;
  (void)size;
  return NULL;
}

  #pragma comment( \
      linker,      \
      "/alternatename:__asan_region_is_poisoned=__libafl_asan_region_is_poisoned")

#elif defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))

  #include <unistd.h>
  #include <sys/syscall.h>
  #include <fcntl.h>

static int dummy_fd[2] = {2, 2};
static int dymmy_initialized = 0;

__attribute__((weak)) void *__asan_region_is_poisoned(const void *beg,
                                                      size_t      size) {
  (void)beg;
  (void)size;
  return NULL;
}

#endif

CmpLogMap *libafl_cmplog_map_ptr = &libafl_cmplog_map;

void __libafl_targets_cmplog_instructions(uintptr_t k, uint8_t shape,
                                          uint64_t arg1, uint64_t arg2) {
  STATIC_ASSERT(sizeof(libafl_cmplog_map_ptr->vals.operands) ==
                sizeof(libafl_cmplog_map_ptr->vals.routines));

  __libafl_targets_cmplog(k, shape, arg1, arg2);
}

// POSIX shenanigan to see if an area is mapped.
// If it is mapped as X-only, we have a problem, so maybe we should add a check
// to avoid to call it on .text addresses
static long area_is_valid(const void *ptr, size_t len) {
  if (!ptr || __asan_region_is_poisoned(ptr, len)) { return 0; }

  long valid_len;

#if defined(_WIN32)
  if (IsBadReadPtr(ptr, len)) { return 0; }
  valid_len = (long)len;
#elif defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
  if (!dymmy_initialized) {
    if ((dummy_fd[1] = open("/dev/urandom", O_WRONLY)) < 0) {
      if (pipe(dummy_fd) < 0) { dummy_fd[1] = 1; }
    }
    dymmy_initialized = 1;
  }

  valid_len = syscall(SYS_write, dummy_fd[1], ptr, len);

  if (valid_len <= 0 || valid_len > (long)len) { return 0; }
#endif

  // even if the write succeed this can be a false positive if we cross
  // a page boundary. who knows why.

  char *p = (char *)ptr;
#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
  long page_size = sysconf(_SC_PAGE_SIZE);
#else
  long page_size = 4096;  // Yolo
#endif
  char *page = (char *)((uintptr_t)p & ~(page_size - 1)) + page_size;

  if (page > p + len) {
    // no, not crossing a page boundary
    return valid_len;
  } else {
    // yes it crosses a boundary, hence we can only return the length of
    // rest of the first page, we cannot detect if the next page is valid
    // or not, neither by SYS_write nor msync() :-(
    return (long)(page - p);
  }
}

// cmplog routines after area check
void __libafl_targets_cmplog_routines_checked(uintptr_t k, const uint8_t *ptr1,
                                              const uint8_t *ptr2, size_t len) {
  libafl_cmplog_enabled = false;
  uint32_t hits;

  if (libafl_cmplog_map_ptr->headers[k].kind != CMPLOG_KIND_RTN) {
    libafl_cmplog_map_ptr->headers[k].kind = CMPLOG_KIND_RTN;
    libafl_cmplog_map_ptr->headers[k].hits = 1;
    libafl_cmplog_map_ptr->headers[k].shape = len;
    hits = 0;
  } else {
    hits = libafl_cmplog_map_ptr->headers[k].hits++;
    if (libafl_cmplog_map_ptr->headers[k].shape < len) {
      libafl_cmplog_map_ptr->headers[k].shape =
          len;  // TODO; adjust len for AFL++'s cmplog protocol
    }
  }

  hits &= CMPLOG_MAP_RTN_H - 1;
  MEMCPY(libafl_cmplog_map_ptr->vals.routines[k][hits].v0, ptr1, len);
  MEMCPY(libafl_cmplog_map_ptr->vals.routines[k][hits].v1, ptr2, len);
  libafl_cmplog_enabled = true;
}

// Very generic cmplog routines callback
void __libafl_targets_cmplog_routines(uintptr_t k, const uint8_t *ptr1,
                                      const uint8_t *ptr2) {
  if (!libafl_cmplog_enabled) { return; }

  int l1, l2;
  if ((l1 = area_is_valid(ptr1, CMPLOG_RTN_LEN)) <= 0 ||
      (l2 = area_is_valid(ptr2, CMPLOG_RTN_LEN)) <= 0) {
    return;
  }
  int len = MIN(l1, l2);

  __libafl_targets_cmplog_routines_checked(k, ptr1, ptr2, len);
}

// cmplog routines but with len specified
void __libafl_targets_cmplog_routines_len(uintptr_t k, const uint8_t *ptr1,
                                          const uint8_t *ptr2, size_t len) {
  if (!libafl_cmplog_enabled) { return; }

  if (area_is_valid(ptr1, CMPLOG_RTN_LEN) <= 0 ||
      area_is_valid(ptr2, CMPLOG_RTN_LEN) <= 0) {
    return;
  }

  __libafl_targets_cmplog_routines_checked(k, ptr1, ptr2, len);
}

void __cmplog_rtn_hook(const uint8_t *ptr1, const uint8_t *ptr2) {
  uintptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);
  k &= CMPLOG_MAP_W - 1;

  __libafl_targets_cmplog_routines(k, ptr1, ptr2);
}

void __cmplog_rtn_hook_n(const uint8_t *ptr1, const uint8_t *ptr2,
                         uint64_t len) {
  (void)(len);
  __cmplog_rtn_hook(ptr1, ptr2);
}

/* hook for string functions, eg. strcmp, strcasecmp etc. */
void __cmplog_rtn_hook_str(const uint8_t *ptr1, uint8_t *ptr2) {
  if (!libafl_cmplog_enabled) { return; }
  if (unlikely(!ptr1 || !ptr2)) return;

  // these strnlen could indeed fail. but if it fails here it will sigsegv in
  // the following hooked function call anyways
  int len1 = strnlen(ptr1, 30) + 1;
  int len2 = strnlen(ptr2, 30) + 1;
  int l = MAX(len1, len2);

  l = MIN(l, area_is_valid(ptr1, l + 1));  // can we really access it? check
  l = MIN(l, area_is_valid(ptr2, l + 1));  // can we really access it? check

  if (l < 2) return;

  intptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);
  k &= CMPLOG_MAP_W - 1;

  __libafl_targets_cmplog_routines_checked(k, ptr1, ptr2, l);
}

/* hook for string with length functions, eg. strncmp, strncasecmp etc.
   Note that we ignore the len parameter and take longer strings if present. */
void __cmplog_rtn_hook_strn(uint8_t *ptr1, uint8_t *ptr2, uint64_t len) {
  if (!libafl_cmplog_enabled) { return; }
  if (unlikely(!ptr1 || !ptr2)) return;

  int len0 = MIN(len, 31);  // cap by 31
  // these strnlen could indeed fail. but if it fails here it will sigsegv in
  // the following hooked function call anyways
  int len1 = strnlen(ptr1, len0);
  int len2 = strnlen(ptr2, len0);
  int l = MAX(len1, len2);

  l = MIN(l, area_is_valid(ptr1, l + 1));  // can we really access it? check
  l = MIN(l, area_is_valid(ptr2, l + 1));  // can we really access it? check

  if (l < 2) return;

  intptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);
  k &= CMPLOG_MAP_W - 1;

  __libafl_targets_cmplog_routines_checked(k, ptr1, ptr2, l);
}

// gcc libstdc++
// _ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE7compareEPKc
static const uint8_t *get_gcc_stdstring(const uint8_t *string) {
  uint32_t *len = (uint32_t *)(string + 8);

  if (*len < 16) {  // in structure
    return (string + 16);
  } else {  // in memory
    uint8_t **ptr = (uint8_t **)string;
    return (*ptr);
  }
}

// llvm libc++ _ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocator
//             IcEEE7compareEmmPKcm
static const uint8_t *get_llvm_stdstring(const uint8_t *string) {
  // length is in: if ((string[0] & 1) == 0) {uint8_t len = (string[0] >> 1);}
  // or: if (string[0] & 1) {uint32_t *len = (uint32_t *) (string + 8);}

  if (string[0] & 1) {  // in memory
    uint8_t **ptr = (uint8_t **)(string + 16);
    return (*ptr);
  } else {  // in structure
    return (string + 1);
  }
}

void __cmplog_rtn_gcc_stdstring_cstring(const uint8_t *stdstring,
                                        const uint8_t *cstring) {
  if (!libafl_cmplog_enabled) { return; }
  int l1 = area_is_valid(stdstring, 32);
  if (l1 <= 0) { return; }
  int l2 = area_is_valid(cstring, 32);
  if (l2 <= 0) { return; }

  int len = MIN(31, MIN(l1, l2));

  uintptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);
  k &= CMPLOG_MAP_W - 1;
  __libafl_targets_cmplog_routines_checked(k, get_gcc_stdstring(stdstring),
                                           cstring, len);
}

void __cmplog_rtn_gcc_stdstring_stdstring(const uint8_t *stdstring1,
                                          const uint8_t *stdstring2) {
  if (!libafl_cmplog_enabled) { return; }
  int l1 = area_is_valid(stdstring1, 32);
  if (l1 <= 0) { return; }
  int l2 = area_is_valid(stdstring2, 32);
  if (l2 <= 0) { return; }

  int       len = MIN(31, MIN(l1, l2));
  uintptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);
  k &= CMPLOG_MAP_W - 1;
  __libafl_targets_cmplog_routines_checked(k, get_gcc_stdstring(stdstring1),
                                           get_gcc_stdstring(stdstring2), len);
}

void __cmplog_rtn_llvm_stdstring_cstring(const uint8_t *stdstring,
                                         const uint8_t *cstring) {
  if (!libafl_cmplog_enabled) { return; }
  int l1 = area_is_valid(stdstring, 32);
  if (l1 <= 0) { return; }
  int l2 = area_is_valid(cstring, 32);
  if (l2 <= 0) { return; }

  int       len = MIN(31, MIN(l1, l2));
  uintptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);
  k &= CMPLOG_MAP_W - 1;
  __libafl_targets_cmplog_routines_checked(k, get_llvm_stdstring(stdstring),
                                           cstring, len);
}

void __cmplog_rtn_llvm_stdstring_stdstring(const uint8_t *stdstring1,
                                           const uint8_t *stdstring2) {
  if (!libafl_cmplog_enabled) { return; }
  int l1 = area_is_valid(stdstring1, 32);
  if (l1 <= 0) { return; }
  int l2 = area_is_valid(stdstring2, 32);
  if (l2 <= 0) { return; }

  int len = MIN(31, MIN(l1, l2));

  uintptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);
  k &= CMPLOG_MAP_W - 1;
  __libafl_targets_cmplog_routines_checked(k, get_llvm_stdstring(stdstring1),
                                           get_llvm_stdstring(stdstring2), len);
}
