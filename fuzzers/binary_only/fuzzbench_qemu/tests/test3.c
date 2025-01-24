#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  int array[16] = {};

  array[1] = 114514;
  if (Size % 2 == 0) {
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
