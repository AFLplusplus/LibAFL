#include <stdint.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Size >= 4) {
    if (Data[0] == 'A') {
      if (Data[1] == 'B') {
        if (Data[2] == 'C') {
          if (Data[3] == 'D') {
             abort();
          }
        }
      }
    } else if (Data[0] == 'Z') {
       if (Size >= 5 && Data[4] == 'X') {
         // another path
       }
    }
  }
  return 0;
}

/*
int main() {

  char buf [10] = {0};
  LLVMFuzzerTestOneInput(buf, 10);

}*/
