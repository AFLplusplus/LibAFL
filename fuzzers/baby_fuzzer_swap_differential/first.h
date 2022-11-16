#ifndef LIBAFL_FIRST_H
#define LIBAFL_FIRST_H

#include "common.h"
#include <stddef.h>
#include <stdint.h>

bool inspect_first(const uint8_t *bytes, size_t len);

#endif  // LIBAFL_FIRST_H
