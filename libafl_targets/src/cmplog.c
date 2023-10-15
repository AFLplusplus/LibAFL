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

CmpLogMap         *libafl_cmplog_map_ptr = &libafl_cmplog_map;
CmpLogMapExtended *libafl_cmplog_map_extended_ptr = &libafl_cmplog_map_extended;

void __libafl_targets_cmplog_instructions(uintptr_t k, uint8_t shape,
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

void __libafl_targets_cmplog_instructions_extended(uintptr_t k, uint8_t shape,
                                                   uint64_t arg1, uint64_t arg2,
                                                   uint8_t attr) {
  if (!libafl_cmplog_enabled) { return; }
  libafl_cmplog_enabled = false;

  uint16_t hits;
  if (libafl_cmplog_map_extended_ptr->headers[k].type != CMPLOG_KIND_INS) {
    libafl_cmplog_map_extended_ptr->headers[k].type = CMPLOG_KIND_INS;
    libafl_cmplog_map_extended_ptr->headers[k].hits = 1;
    libafl_cmplog_map_extended_ptr->headers[k].shape = shape;
    hits = 0;
  } else {
    hits = libafl_cmplog_map_extended_ptr->headers[k].hits++;
    if (libafl_cmplog_map_extended_ptr->headers[k].shape < shape) {
      libafl_cmplog_map_extended_ptr->headers[k].shape = shape;
    }
  }

  hits &= CMPLOG_MAP_H - 1;
  libafl_cmplog_map_extended_ptr->vals.operands[k][hits].v0 = arg1;
  libafl_cmplog_map_extended_ptr->vals.operands[k][hits].v1 = arg2;
  libafl_cmplog_map_extended_ptr->headers[k].attribute = attr;
  libafl_cmplog_enabled = true;
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
