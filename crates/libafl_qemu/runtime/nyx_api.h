/*
 * kAFl/Nyx low-level interface definitions
 *
 * Copyright 2022 Sergej Schumilo, Cornelius Aschermann
 * Copyright 2022 Intel Corporation
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef NYX_API_H
#define NYX_API_H

#ifndef __KERNEL__
  // userspace
  #include <stdarg.h>
  #include <stdio.h>

  #ifdef __MINGW64__
    #ifndef uint64_t
      #define uint64_t UINT64
    #endif
    #ifndef int32_t
      #define int32_t INT32
    #endif
    #ifndef uint32_t
      #define uint32_t UINT32
    #endif
    #ifndef u_long
      #define u_long UINT64
    #endif
    #ifndef uint8_t
      #define uint8_t UINT8
    #endif
  #else
    #include <stdint.h>
  #endif
#else
  // Linux kernel
  #include <linux/stdarg.h>
  #include <linux/types.h>
#endif

#define HYPERCALL_KAFL_RAX_ID 0x01f
#define HYPERCALL_KAFL_ACQUIRE 0
#define HYPERCALL_KAFL_GET_PAYLOAD 1
#define HYPERCALL_KAFL_GET_PROGRAM 2 /* deprecated */
#define HYPERCALL_KAFL_GET_ARGV 3    /* deprecated */
#define HYPERCALL_KAFL_RELEASE 4
#define HYPERCALL_KAFL_SUBMIT_CR3 5
#define HYPERCALL_KAFL_SUBMIT_PANIC 6
#define HYPERCALL_KAFL_SUBMIT_KASAN 7
#define HYPERCALL_KAFL_PANIC 8
#define HYPERCALL_KAFL_KASAN 9
#define HYPERCALL_KAFL_LOCK 10
#define HYPERCALL_KAFL_INFO 11 /* deprecated */
#define HYPERCALL_KAFL_NEXT_PAYLOAD 12
#define HYPERCALL_KAFL_PRINTF 13
#define HYPERCALL_KAFL_PRINTK_ADDR 14 /* deprecated */
#define HYPERCALL_KAFL_PRINTK 15      /* deprecated */

/* user space only hypercalls */
#define HYPERCALL_KAFL_USER_RANGE_ADVISE 16
#define HYPERCALL_KAFL_USER_SUBMIT_MODE 17
#define HYPERCALL_KAFL_USER_FAST_ACQUIRE 18
/* 19 is already used for exit reason KVM_EXIT_KAFL_TOPA_MAIN_FULL */
#define HYPERCALL_KAFL_USER_ABORT 20
#define HYPERCALL_KAFL_TIMEOUT 21 /* deprecated */
#define HYPERCALL_KAFL_RANGE_SUBMIT 29
#define HYPERCALL_KAFL_REQ_STREAM_DATA 30
#define HYPERCALL_KAFL_PANIC_EXTENDED 32

#define HYPERCALL_KAFL_CREATE_TMP_SNAPSHOT 33
#define HYPERCALL_KAFL_DEBUG_TMP_SNAPSHOT \
  34 /* hypercall for debugging / development purposes */

#define HYPERCALL_KAFL_GET_HOST_CONFIG 35
#define HYPERCALL_KAFL_SET_AGENT_CONFIG 36

#define HYPERCALL_KAFL_DUMP_FILE 37

#define HYPERCALL_KAFL_REQ_STREAM_DATA_BULK 38
#define HYPERCALL_KAFL_PERSIST_PAGE_PAST_SNAPSHOT 39

/* hypertrash only hypercalls */
#define HYPERTRASH_HYPERCALL_MASK 0xAA000000

#define HYPERCALL_KAFL_NESTED_PREPARE (0 | HYPERTRASH_HYPERCALL_MASK)
#define HYPERCALL_KAFL_NESTED_CONFIG (1 | HYPERTRASH_HYPERCALL_MASK)
#define HYPERCALL_KAFL_NESTED_ACQUIRE (2 | HYPERTRASH_HYPERCALL_MASK)
#define HYPERCALL_KAFL_NESTED_RELEASE (3 | HYPERTRASH_HYPERCALL_MASK)
#define HYPERCALL_KAFL_NESTED_HPRINTF (4 | HYPERTRASH_HYPERCALL_MASK)

#define HPRINTF_MAX_SIZE 0x1000 /* up to 4KB hprintf strings */

#define KAFL_MODE_64 0
#define KAFL_MODE_32 1
#define KAFL_MODE_16 2

typedef volatile struct {
  int32_t size;
  uint8_t data[];
} kAFL_payload;

typedef volatile struct {
  uint64_t ip[4];
  uint64_t size[4];
  uint8_t  enabled[4];
} kAFL_ranges;

#if defined(__i386__)
static inline uint32_t kAFL_hypercall(uint32_t p1, uint32_t p2) {
  uint32_t nr = HYPERCALL_KAFL_RAX_ID;
  asm volatile("vmcall" : "=a"(nr) : "a"(nr), "b"(p1), "c"(p2));
  return nr;
}
#elif defined(__x86_64__)
static inline uint64_t kAFL_hypercall(uint64_t p1, uint64_t p2) {
  uint64_t nr = HYPERCALL_KAFL_RAX_ID;
  asm volatile("vmcall" : "=a"(nr) : "a"(nr), "b"(p1), "c"(p2));
  return nr;
}
#endif

static void habort(char *msg) __attribute__((unused));
static void habort(char *msg) {
  kAFL_hypercall(HYPERCALL_KAFL_USER_ABORT, (uintptr_t)msg);
}

static void hprintf(const char *format, ...) __attribute__((unused));
static void hprintf(const char *format, ...) {
  static char hprintf_buffer[HPRINTF_MAX_SIZE] __attribute__((aligned(4096)));

  va_list args;
  va_start(args, format);
  vsnprintf((char *)hprintf_buffer, HPRINTF_MAX_SIZE, format, args);
  // printf("%s", hprintf_buffer);
  kAFL_hypercall(HYPERCALL_KAFL_PRINTF, (uintptr_t)hprintf_buffer);
  va_end(args);
}

#define NYX_HOST_MAGIC 0x4878794e
#define NYX_AGENT_MAGIC 0x4178794e

#define NYX_HOST_VERSION 2
#define NYX_AGENT_VERSION 1

typedef struct {
  uint32_t host_magic;
  uint32_t host_version;
  uint32_t bitmap_size;
  uint32_t ijon_bitmap_size;
  uint32_t payload_buffer_size;
  uint32_t worker_id;
  /* more to come */
} __attribute__((packed)) host_config_t;

typedef volatile struct {
  uint32_t agent_magic;
  uint32_t agent_version;
  uint8_t  agent_timeout_detection;
  uint8_t  agent_tracing;
  uint8_t  agent_ijon_tracing;
  uint8_t  agent_non_reload_mode;
  uint64_t trace_buffer_vaddr;
  uint64_t ijon_trace_buffer_vaddr;
  uint32_t coverage_bitmap_size;
  uint32_t input_buffer_size;
  uint8_t  dump_payloads; /* set by hypervisor */
                          /* more to come */
} __attribute__((packed)) agent_config_t;

typedef struct {
  uint64_t file_name_str_ptr;
  uint64_t data_ptr;
  uint64_t bytes;
  uint8_t  append;
} __attribute__((packed)) kafl_dump_file_t;

typedef struct {
  char     file_name[256];
  uint64_t num_addresses;
  uint64_t addresses[479];
} __attribute__((packed)) req_data_bulk_t;

#endif /* NYX_API_H */