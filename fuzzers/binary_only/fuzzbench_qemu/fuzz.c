#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>

int main() {
  char buffer[16];

  // Read exactly 16 bytes from stdin
  size_t bytesRead = fread(buffer, 1, 16, stdin);
  buffer[15] = 0;
  if (bytesRead != 16) {
    fprintf(stderr, "Failed to read 16 bytes. Read %zu bytes.\n", bytesRead);
    printf("%d\n", errno);
    return 1;
  }
  printf("we read %s\n", buffer);
  // sleep(3);

  if (buffer[0] == 'a') {
    if (buffer[1] == 'b') {
      if (buffer[2] == 'c') {
        if (buffer[3] == 'd') { abort(); }
      }
    }
  }
}
