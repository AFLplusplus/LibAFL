#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

void LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Size > 3 && Data[0] == 'B' && Data[1] == 'U' && Data[2] == 'G') {
    abort();
  }
}

int main() {
  uint8_t buf[4] = "test";
  LLVMFuzzerTestOneInput(buf, 4);
  return 0;
}
