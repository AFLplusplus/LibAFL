#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "vharness.h"

struct vharness_input vharness_init(size_t input_max_size) {
  char *input = malloc(input_max_size);

  // make sure the pages are really allocated
  for (size_t i = 0; i < input_max_size; i += getpagesize()) {
    input[i] = 'A';
  }

  return (struct vharness_input){
      .input = input,
      .input_size = 0,
      .input_max_size = input_max_size,
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

  memcpy(buf, vinput->input + vinput->pos, buf_len);
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
