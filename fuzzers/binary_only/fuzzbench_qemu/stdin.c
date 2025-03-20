#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(int argc, char **argv) {
  printf("%d\n", argc);
  for (int i = 0; i < argc; i++) {
    printf("%s\n", argv[i]);
  }

  char buffer[16];
  int res = fread(buffer, 1, 16, stdin);
  buffer[15] = 0;
  printf("%s\n", buffer);

  return 0;
}
