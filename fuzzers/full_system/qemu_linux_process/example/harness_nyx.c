// Adapted from
// https://github.com/google/fuzzing/blob/master/tutorial/libFuzzer/fuzz_me.cc
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <assert.h>

#include <nyx_api.h>

#define PAGE_SIZE 4096
#define PAYLOAD_MAX_SIZE (1 * 1024 * 1024)

bool FuzzMe(const uint8_t *Data, size_t DataSize) {
  if (DataSize > 3) {
    if (Data[0] == 'F') {
      if (Data[1] == 'U') {
        if (Data[2] == 'Z') {
          if (Data[3] == 'Z') { return true; }
        }
      }
    }
  }

  return false;
}

/**
 * Allocate page-aligned memory
 */
void *malloc_resident_pages(size_t num_pages) {
  size_t data_size = PAGE_SIZE * num_pages;
  void  *ptr = NULL;

  if ((ptr = aligned_alloc(PAGE_SIZE, data_size)) == NULL) {
    fprintf(stderr, "Allocation failure: %s\n", strerror(errno));
    goto err_out;
  }

  // ensure pages are aligned and resident
  memset(ptr, 0x42, data_size);
  if (mlock(ptr, data_size) == -1) {
    fprintf(stderr, "Error locking scratch buffer: %s\n", strerror(errno));
    goto err_out;
  }

  assert(((uintptr_t)ptr % PAGE_SIZE) == 0);
  return ptr;
err_out:
  free(ptr);
  return NULL;
}

void hrange_submit(unsigned id, uintptr_t start, uintptr_t end) {
  uint64_t range_arg[3] __attribute__((aligned(PAGE_SIZE)));
  memset(range_arg, 0, sizeof(range_arg));

  range_arg[0] = start;
  range_arg[1] = end;
  range_arg[2] = id;

  kAFL_hypercall(HYPERCALL_KAFL_RANGE_SUBMIT, (uintptr_t)range_arg);
}

int agent_init(int verbose) {
  host_config_t host_config;

  hprintf("Nyx agent init");

  // set ready state
  kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
  kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);

  kAFL_hypercall(HYPERCALL_KAFL_GET_HOST_CONFIG, (uintptr_t)&host_config);

  if (verbose) {
    fprintf(stderr, "GET_HOST_CONFIG\n");
    fprintf(stderr, "\thost magic:  0x%x, version: 0x%x\n",
            host_config.host_magic, host_config.host_version);
    fprintf(stderr, "\tbitmap size: 0x%x, ijon:    0x%x\n",
            host_config.bitmap_size, host_config.ijon_bitmap_size);
    fprintf(stderr, "\tpayload size: %u KB\n",
            host_config.payload_buffer_size / 1024);
    fprintf(stderr, "\tworker id: %d\n", host_config.worker_id);
  }

  if (host_config.host_magic != NYX_HOST_MAGIC) {
    hprintf("HOST_MAGIC mismatch: %08x != %08x\n", host_config.host_magic,
            NYX_HOST_MAGIC);
    habort("HOST_MAGIC mismatch!");
    return -1;
  }

  if (host_config.host_version != NYX_HOST_VERSION) {
    hprintf("HOST_VERSION mismatch: %08x != %08x\n", host_config.host_version,
            NYX_HOST_VERSION);
    habort("HOST_VERSION mismatch!");
    return -1;
  }

  if (host_config.payload_buffer_size > PAYLOAD_MAX_SIZE) {
    hprintf("Fuzzer payload size too large: %lu > %lu\n",
            host_config.payload_buffer_size, PAYLOAD_MAX_SIZE);
    habort("Host payload size too large!");
    return -1;
  }

  agent_config_t agent_config = {0};
  agent_config.agent_magic = NYX_AGENT_MAGIC;
  agent_config.agent_version = NYX_AGENT_VERSION;
  // agent_config.agent_timeout_detection = 0; // timeout by host
  // agent_config.agent_tracing = 0; // trace by host
  // agent_config.agent_ijon_tracing = 0; // no IJON
  agent_config.agent_non_reload_mode = 0;  // no persistent mode
  // agent_config.trace_buffer_vaddr = 0xdeadbeef;
  // agent_config.ijon_trace_buffer_vaddr = 0xdeadbeef;
  agent_config.coverage_bitmap_size = host_config.bitmap_size;
  // agent_config.input_buffer_size;
  // agent_config.dump_payloads; // set by hypervisor (??)

  kAFL_hypercall(HYPERCALL_KAFL_SET_AGENT_CONFIG, (uintptr_t)&agent_config);

  return 0;
}

int main() {
  kAFL_payload *pbuf = malloc_resident_pages(PAYLOAD_MAX_SIZE / PAGE_SIZE);
  assert(pbuf);

  agent_init(1);

  kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_CR3, 0);
  hrange_submit(0, 0x0, 0x00007fffffffffff);

  kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (uint64_t)pbuf);

  hprintf("payload size addr: %p", &pbuf->size);
  hprintf("payload addr: %p", &pbuf->data);

  while (true) {
    kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);
    kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);

    // Call the target
    bool ret = FuzzMe(pbuf->data, pbuf->size);

    if (ret) { kAFL_hypercall(HYPERCALL_KAFL_PANIC, 0); }

    kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
  }

  habort("post-release code has been triggered. Snapshot error?");
}