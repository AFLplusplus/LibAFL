#include "second.h"

bool inspect_second(const uint8_t *bytes, size_t len) {
  if (len >= 5 && bytes[4] == 'e') {
    if (len >= 6 && bytes[5] == 'f') {
      if (len >= 7 && bytes[6] == 'g') {
        if (len == 8 && bytes[7] == 'h') {
          return ACCEPT;
        }
      }
    }
  }
  return REJECT;
}