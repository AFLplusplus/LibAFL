#include <stdint.h>
#define len 2

int main() {
  volatile unsigned char a;  // = 0x1;
  volatile unsigned char b;  // = 0x0;
  volatile unsigned char c = 0;  // The result, so should be initialized at 0;

  /*volatile unsigned char f[len];

  for(int i = 0; i< len; i++){
    f[i] = i;
  }*/
  c = 0x1;
  if (a > b) {
    c = 0x2;
    if (a > 0x20) {
      c = 0x3;
      if (a == 0x50) {
        c = 0x4;
        if (b == 0x24) { c = 0x5; }
      }
    }
  }
  /*
  a = 0xDE;
  b = 0xEA;
  c = 0xBE;
  */
  return c;
}