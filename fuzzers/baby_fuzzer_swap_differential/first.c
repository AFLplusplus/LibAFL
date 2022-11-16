#include "first.h"

bool inspect_first(const uint8_t *bytes, size_t len) {
  if (len >= 1 && bytes[0] == 'a') {
    if (len >= 2 && bytes[1] == 'b') {
      if (len >= 3 && bytes[2] == 'c') {
        if (len >= 4 && bytes[3] == 'd') {
          return ACCEPT;
        }
      }
    }
  }
  return REJECT;
}
