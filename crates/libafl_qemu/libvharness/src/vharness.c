#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "vharness.h"

volatile char input_buf[VHARNESS_MAX_INPUT_SIZE];

struct vharness_input vharness_init(void) {
  // make sure the input is really allocated
  for (size_t i = 0; i < VHARNESS_MAX_INPUT_SIZE; i += getpagesize()) {
    input_buf[i] = 0;
  }

  return (struct vharness_input){
      .input = input_buf,
      .input_size = 0,
      .input_max_size = VHARNESS_MAX_INPUT_SIZE,
      .pos = 0,
  };
}

void vharness_reset(struct vharness_input *vinput, size_t input_size) {
  vinput->pos = 0;
  vinput->input_size = input_size;
}

size_t vharness_remaining_size(struct vharness_input *vinput) {
  return vinput->input_size - vinput->pos;
}

bool vharness_get_buf(struct vharness_input *vinput, void *buf,
                      size_t buf_len) {
  if (vharness_remaining_size(vinput) < buf_len) {
    return false;
  }

  memcpy(buf, (const char*) vinput->input + vinput->pos, buf_len);
  vinput->pos += buf_len;

  return true;
}

bool vharness_get_u64(struct vharness_input *vinput, uint64_t *val) {
  return vharness_get_buf(vinput, val, sizeof(val));
}

bool vharness_get_u32(struct vharness_input *vinput, uint32_t *val) {
  return vharness_get_buf(vinput, val, sizeof(val));
}

bool vharness_get_int(struct vharness_input *vinput, int *val) {
  return vharness_get_buf(vinput, val, sizeof(val));
}
