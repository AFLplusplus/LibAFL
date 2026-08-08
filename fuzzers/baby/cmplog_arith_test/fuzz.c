#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define TARGET_RESULT ((uint32_t)0x12345678)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 8) { return 0; }

  uint32_t x, y;
  memcpy(&x, data, sizeof(x));
  memcpy(&y, data + 4, sizeof(y));

  uint32_t result = (x * 3) + (y / 2);

  if (result == TARGET_RESULT) { abort(); }

  return 0;
}
