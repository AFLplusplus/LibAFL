/*******************************************************************************
Copyright (c) 2019-2024, Andrea Fioraldi


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

/*
Mmap hooks for libqasan by Alessandro "cube" De Vito
<alessandro.devito@stackbits.eu>

*/

#include "libqasan.h"
#include <features.h>
#include <errno.h>
#include <stddef.h>
#include <assert.h>
#include <pthread.h>
#include <sys/mman.h>

#ifdef __GLIBC__
  #define USE_LIBC_ALLOC
#endif

#if __STDC_VERSION__ < 201112L || \
    (defined(__FreeBSD__) && __FreeBSD_version < 1200000)
// use this hack if not C11
typedef struct {
  long long   __ll;
  long double __ld;

} max_align_t;

#endif

#ifdef USE_LIBC_ALLOC

void *(*__lq_libc_mmap)(void *, size_t, int, int, int, off_t);
int (*__lq_libc_munmap)(void *, size_t);

#else

// TODO: include from mmap.c

#endif

int __libqasan_mmap_initialized;

void __libqasan_init_mmap(void) {
  if (__libqasan_mmap_initialized) return;

#ifdef USE_LIBC_ALLOC
  __lq_libc_mmap = dlsym(RTLD_NEXT, "mmap");
  __lq_libc_munmap = dlsym(RTLD_NEXT, "munmap");
#endif

  __libqasan_mmap_initialized = 1;
  QASAN_LOG("\n");
  QASAN_LOG("mmap initialization done.\n");
  QASAN_LOG("\n");
}

void *__libqasan_mmap(void *addr, size_t length, int prot, int flags, int fd,
                      off_t offset) {
  __libqasan_init_mmap();

  int   state = QASAN_SWAP(QASAN_DISABLED);  // disable qasan for this thread
  void *p = __lq_libc_mmap(addr, length, prot, flags, fd, offset);
  QASAN_SWAP(state);

  if (!p) return NULL;

  QASAN_UNPOISON(p, length);

  QASAN_ALLOC(p, (uintptr_t)p + length);

  // We don't memset the memory, as it's not guaranteed to be writable.

  return p;
}

int __libqasan_munmap(void *addr, size_t length) {
  __libqasan_init_mmap();

  int state = QASAN_SWAP(QASAN_DISABLED);  // disable qasan for this thread
  int ret = __lq_libc_munmap(addr, length);
  QASAN_SWAP(state);

  if (ret == -1) return -1;

  // Omitting memory poisoning for unmapped regions as accessing them would
  // result in an error anyway.

  // TODO: add a syscall to deallocate addr->addr + length
  QASAN_DEALLOC(addr);

  return ret;
}
