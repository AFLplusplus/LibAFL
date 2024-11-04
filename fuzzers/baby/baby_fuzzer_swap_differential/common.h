#ifndef LIBAFL_COMMON_H
#define LIBAFL_COMMON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ACCEPT true
#define REJECT false

bool both_require(const uint8_t *bytes, size_t len);

#endif  // LIBAFL_COMMON_H
