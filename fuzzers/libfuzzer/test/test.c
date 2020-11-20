#include <stdio.h>
#include <stdint.h>

// gcc -shared -o libdemo.so demo-so.c -w
int target_func(char *buf, int size) {

  printf("buffer:%p, size:%p\n", buf, size);
  switch (buf[0]) {

    case 1:
      puts("222");
      if (buf[1] == '\x44') {

        puts("null ptr deference");
        *(char *)(0) = 1;

      }

      break;
    case 0xff:
      if (buf[2] == '\xff') {

        if (buf[1] == '\x44') {

          puts("crash....");
          *(char *)(0xdeadbeef) = 1;

        }

      }

      break;
    default:
      puts("default action");
      break;

  }

  return 1;

}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  return target_func(Data, Size);
}
