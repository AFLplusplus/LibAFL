#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size >= 5 && memcmp(data, "CRASH", 5) == 0) {
    printf("TRIGGERING CRASH!\n");
    abort();
  }
  return 0;
}
