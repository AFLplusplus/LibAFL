#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // printf("Got %ld bytes.\n", Size);
    if (Size >= 4 && *(uint32_t*)Data == 0xaabbccdd)
      abort();
}

int main() {

  char buf [10] = {0};
  LLVMFuzzerTestOneInput(buf, 10);

}
