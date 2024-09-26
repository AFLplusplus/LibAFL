#include <stdint.h>
#include <stdlib.h>
#include <string>

void asan_crash() {
  int *array = new int[100];
  delete[] array;
  array[5] += 1;
  fprintf(stdout, "%d\n", array[5]);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // abort();
  if (size == 10) { asan_crash(); }
  return 0;
}
