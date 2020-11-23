#include <stdio.h>
#include <stdint.h>

int target_func(const uint8_t *buf, size_t size) {

  /*printf("BUF (%ld): ", size);
  for (int i = 0; i < size; i++) {
      printf("%02X", buf[i]);
  }
  printf("\n");*/
  
  switch (buf[0]) {

    case 1:
      if (buf[1] == 0x44) {
        //__builtin_trap();
        return 8;
      }

      break;
    case 0xff:
      if (buf[2] == 0xff) {
        if (buf[1] == 0x44) {
          //*(char *)(0xdeadbeef) = 1;
          return 9;
        }
      }

      break;
    default:
      break;

  }

  return 1;

}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  return target_func(Data, Size);
}
