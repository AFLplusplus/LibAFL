#include "common.h"

bool both_require(const uint8_t *bytes, size_t len) {
  if (len >= 1 && bytes[0] == 'a') {
    if (len >= 2 && bytes[1] == 'b') {
      if (len >= 3 && bytes[2] == 'c') { return ACCEPT; }
    }
  }
  return REJECT;
}