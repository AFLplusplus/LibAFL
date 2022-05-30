#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

extern "C" __declspec(dllexport) size_t
    LLVMFuzzerTestOneInput(const char *data, unsigned int len) {
  if (data[0] == 'b') {
    if (data[1] == 'a') {
      if (data[2] == 'd') { printf("AAA"); }
    }
  }
  return 0;
}