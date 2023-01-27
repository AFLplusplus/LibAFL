#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *bytes, size_t len) {
  if (len >= 1 && bytes[0] == 'a') {
    if (len >= 2 && bytes[1] == 'b') {
      if (len >= 3 && bytes[2] == 'c') {
        if (len >= 4 && bytes[3] == 'a') {
          if (len >= 5 && bytes[4] == 'b') {
            if (len >= 6 && bytes[5] == 'c') {
              __builtin_trap();
            }
          }
        }
      }
    }
  }
  return 0;
}
