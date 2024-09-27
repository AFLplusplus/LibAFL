#include <stdint.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int main() {
  char buf[10] = {0};
  LLVMFuzzerTestOneInput(buf, 10);
}
