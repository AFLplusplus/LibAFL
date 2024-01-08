#include <stdint.h>
#include <stdlib.h>
#include <string>

extern "C" int heap_uaf_read(const uint8_t *_data, size_t _size) {
  int *array = new int[100];
  delete[] array;
  fprintf(stdout, "%d\n", array[5]);
  return 0;
}

extern "C" int heap_uaf_write(const uint8_t *_data, size_t _size) {
  int *array = new int[100];
  delete[] array;
  array[5] = 1;
  return 0;
}

extern "C" int heap_oob_read(const uint8_t *_data, size_t _size) {
  int *array = new int[100];
  fprintf(stdout, "%d\n", array[100]);
  return 0;
}

extern "C" int heap_oob_write(const uint8_t *_data, size_t _size) {
  int *array = new int[100];
  array[100] = 1;
  return 0;
}
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // abort();
  return 0;
}
