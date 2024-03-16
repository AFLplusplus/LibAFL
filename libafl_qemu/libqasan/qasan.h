/*******************************************************************************
Copyright (c) 2019-2021, Andrea Fioraldi


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

#ifndef __QASAN_H__
#define __QASAN_H__

#define DEBUG 1

#define QASAN_VERSTR "0.3"

#define QASAN_FAKESYS_NR 0xa2a4

enum {
  QASAN_ACTION_CHECK_LOAD,
  QASAN_ACTION_CHECK_STORE,
  QASAN_ACTION_POISON,
  QASAN_ACTION_USER_POISON,
  QASAN_ACTION_UNPOISON,
  QASAN_ACTION_IS_POISON,
  QASAN_ACTION_ALLOC,
  QASAN_ACTION_DEALLOC,
  QASAN_ACTION_ENABLE,
  QASAN_ACTION_DISABLE,
  QASAN_ACTION_SWAP_STATE,
};

/* shadow map byte values */
#define ASAN_VALID 0x00
#define ASAN_PARTIAL1 0x01
#define ASAN_PARTIAL2 0x02
#define ASAN_PARTIAL3 0x03
#define ASAN_PARTIAL4 0x04
#define ASAN_PARTIAL5 0x05
#define ASAN_PARTIAL6 0x06
#define ASAN_PARTIAL7 0x07
#define ASAN_ARRAY_COOKIE 0xac
#define ASAN_STACK_RZ 0xf0
#define ASAN_STACK_LEFT_RZ 0xf1
#define ASAN_STACK_MID_RZ 0xf2
#define ASAN_STACK_RIGHT_RZ 0xf3
#define ASAN_STACK_FREED 0xf5
#define ASAN_STACK_OOSCOPE 0xf8
#define ASAN_GLOBAL_RZ 0xf9
#define ASAN_HEAP_RZ 0xe9
#define ASAN_USER 0xf7
#define ASAN_HEAP_LEFT_RZ 0xfa
#define ASAN_HEAP_RIGHT_RZ 0xfb
#define ASAN_HEAP_FREED 0xfd

#define QASAN_ENABLED (0)
#define QASAN_DISABLED (1)

// fake syscall, works only for QASan user-mode!!!

#include <unistd.h>

#ifdef ASAN_GUEST
  #include <stdbool.h>

void qasan_load(const char *start, size_t len);
void qasan_store(const char *start, size_t len);
void qasan_poison(const char *start, size_t len, char val);
void qasan_unpoison(const char *start, size_t len);
bool qasan_is_poison(const char *start, size_t len);

void qasan_alloc(const char *start, const char *end);
void qasan_dealloc(const char *start);
int  qasan_swap(int state);

  #define QASAN_LOAD(ptr, len) qasan_load((const char *)(ptr), (size_t)(len))
  #define QASAN_STORE(ptr, len) qasan_store((const char *)(ptr), (size_t)(len))
  #define QASAN_POISON(ptr, len, poison_byte) \
    qasan_poison((const char *)(ptr), (size_t)(len), (char)(poison_byte))
  #define QASAN_USER_POISON(ptr, len) QASAN_POISON(ptr, len, ASAN_USER)
  #define QASAN_UNPOISON(ptr, len) \
    qasan_unpoison((const char *)(ptr), (size_t)(len))
  #define QASAN_IS_POISON(ptr, len) \
    qasan_is_poison((const char *)(ptr), (size_t)(len))
  #define QASAN_ALLOC(start, end) \
    qasan_alloc((const char *)(start), (const char *)(end))
  #define QASAN_DEALLOC(ptr) qasan_dealloc((const char *)(ptr))
  #define QASAN_SWAP(state) qasan_swap((int)(state))
#else

  #define QASAN_CALL0(action) \
    syscall(QASAN_FAKESYS_NR, action, NULL, NULL, NULL)
  #define QASAN_CALL1(action, arg1) \
    syscall(QASAN_FAKESYS_NR, action, arg1, NULL, NULL)
  #define QASAN_CALL2(action, arg1, arg2) \
    syscall(QASAN_FAKESYS_NR, action, arg1, arg2, NULL)
  #define QASAN_CALL3(action, arg1, arg2, arg3) \
    syscall(QASAN_FAKESYS_NR, action, arg1, arg2, arg3)

  #define QASAN_LOAD(ptr, len) QASAN_CALL2(QASAN_ACTION_CHECK_LOAD, ptr, len)
  #define QASAN_STORE(ptr, len) QASAN_CALL2(QASAN_ACTION_CHECK_STORE, ptr, len)

  #define QASAN_POISON(ptr, len, poison_byte) \
    QASAN_CALL3(QASAN_ACTION_POISON, ptr, len, poison_byte)
  #define QASAN_USER_POISON(ptr, len) \
    QASAN_CALL3(QASAN_ACTION_POISON, ptr, len, ASAN_USER)
  #define QASAN_UNPOISON(ptr, len) QASAN_CALL2(QASAN_ACTION_UNPOISON, ptr, len)
  #define QASAN_IS_POISON(ptr, len) \
    QASAN_CALL2(QASAN_ACTION_IS_POISON, ptr, len)

  #define QASAN_ALLOC(start, end) QASAN_CALL2(QASAN_ACTION_ALLOC, start, end)
  #define QASAN_DEALLOC(ptr) QASAN_CALL1(QASAN_ACTION_DEALLOC, ptr)

  #define QASAN_SWAP(state) QASAN_CALL1(QASAN_ACTION_SWAP_STATE, state)
#endif

#endif
