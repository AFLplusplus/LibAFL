#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int fibonacci(int a) {
  if (a == 0 || a == 1) {
    return 1;
  } else {
    return fibonacci(a - 1) + fibonacci(a - 2);
  }
}

int transfer(int size) {
  if (size > 4) {
    return 4;
  } else
    return size;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Size > 4) { fprintf(stderr, "%d\n", fibonacci(transfer(Size))); }
}

/*
int main() {

  char buf [10] = {0};
  LLVMFuzzerTestOneInput(buf, 10);

}*/
