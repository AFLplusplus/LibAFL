#ifndef VHARNESS_H
#define VHARNESS_H

#include "api.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VHARNESS_MAX_INPUT_SIZE (1 * 1024 * 1024)

struct vharness_input {
  volatile char *input;
  size_t input_max_size;
  size_t input_size;
  size_t pos;
};

struct vharness_input vharness_init(void);
void vharness_reset(struct vharness_input *vinput, size_t input_size);

size_t vharness_remaining_size(struct vharness_input *vinput);
bool vharness_get_buf(struct vharness_input *vinput, void *buf, size_t buf_len);
bool vharness_get_u32(struct vharness_input *vinput, uint32_t *val);
bool vharness_get_u64(struct vharness_input *vinput, uint64_t *val);
bool vharness_get_int(struct vharness_input *vinput, int *val);

#endif
