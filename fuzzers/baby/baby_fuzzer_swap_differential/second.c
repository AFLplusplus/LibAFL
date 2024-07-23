#include "second.h"

bool inspect_second(const uint8_t *bytes, size_t len) {
  if (both_require(bytes, len)) {
    if (len >= 5 && bytes[4] == 'e') { return ACCEPT; }
  }
  return REJECT;
}