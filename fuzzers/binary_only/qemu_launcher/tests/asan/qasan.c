// taken from
// https://github.com/AFLplusplus/AFLplusplus/blob/da2d4d8258d725f79c2daa22bf3b1a59c593e472/frida_mode/test/fasan/test.c

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#define UNUSED_PARAMETER(x) (void)(x)

#define LOG(x)                              \
  do {                                      \
    char buf[] = x;                         \
    write(STDERR_FILENO, buf, sizeof(buf)); \
                                            \
  } while (false);

void LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char *buf = malloc(10);

  if (buf == NULL) return;

  switch (*data) {
    /* Underflow */
    case 'U':
      LOG("Underflow\n");
      buf[-1] = '\0';
      free(buf);
      break;
    /* Overflow */
    case 'O':
      LOG("Overflow\n");
      buf[10] = '\0';
      free(buf);
      break;
    /* Double free */
    case 'D':
      LOG("Double free\n");
      free(buf);
      free(buf);
      break;
    /* Use after free */
    case 'A':
      LOG("Use after free\n");
      free(buf);
      buf[0] = '\0';
      break;
    /* Test Limits (OK) */
    case 'T':
      LOG("Test-Limits - No Error\n");
      buf[0] = 'A';
      buf[9] = 'I';
      free(buf);
      break;
    case 'M':
      LOG("Memset too many\n");
      memset(buf, '\0', 11);
      free(buf);
      break;
    default:
      LOG("Nop - No Error\n");
      break;
  }
}

int main(int argc, char **argv) {
  UNUSED_PARAMETER(argc);
  UNUSED_PARAMETER(argv);

  char input = '\0';

  if (argc > 1) { input = argv[1][0]; }
  LLVMFuzzerTestOneInput(&input, 1);

  LOG("DONE\n");
  return 0;
}
