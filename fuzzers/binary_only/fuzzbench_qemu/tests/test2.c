#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  char array[40] = {};
  char v = *(uint8_t *)Data;
  v = v + 120;
  // printf("%p %p %p\n", array, v, Data);

  array[v] = 0x0;
  if (v % 2 == 0) {
    array[0] = 1;
  } else {
    array[0] = 2;
  }

  return 0;
}

/*
int main() {

  char buf [10] = {0};
  LLVMFuzzerTestOneInput(buf, 10);

}*/
