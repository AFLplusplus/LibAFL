#include <stdint.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Size >= 8 && *(uint32_t *)Data == 0xaabbccdd) { abort(); }
  return 0;
}

/*
int main() {

  char buf [10] = {0};
  LLVMFuzzerTestOneInput(buf, 10);

}*/
