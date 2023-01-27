#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *bytes, size_t len) {
  const uint64_t *data = (const uint64_t *) bytes;
  const size_t actual_len = len / sizeof(uint64_t);
  if (actual_len >= 1 && data[0] == 'a') {
    if (actual_len >= 2 && data[1] == 'b') {
      if (actual_len >= 3 && data[2] == 'c') {
        if (actual_len >= 4 && data[3] == data[0]) {
          if (actual_len >= 5 && data[4] == data[1]) {
            if (actual_len >= 6 && data[5] == data[2]) {
              __builtin_trap();
            }
          }
        }
      }
    }
  }
  return 0;
}
