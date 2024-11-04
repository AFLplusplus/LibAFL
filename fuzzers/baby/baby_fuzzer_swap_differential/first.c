#include "first.h"

bool inspect_first(const uint8_t *bytes, size_t len) {
  if (both_require(bytes, len)) {
    if (len >= 4 && bytes[3] == 'd') { return ACCEPT; }
  }
  return REJECT;
}
