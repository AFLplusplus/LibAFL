#include <stdio.h>
#include <stdlib.h>

// The following line is needed for shared memeory testcase fuzzing
__AFL_FUZZ_INIT();

int main(int argc, char **argv) {
  FILE *file = stdin;
  if (argc > 1) { file = fopen(argv[1], "rb"); }

  // The following three lines are for normal fuzzing.
  /*
  char buf[16];
  char* p = fgets(buf, 16, file);
  buf[15] = 0;
  */

  // The following line is also needed for shared memory testcase fuzzing
  unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

  printf("input: %s\n", buf);

  if (buf[0] == 'a') {
    if (buf[1] == 'b') {
      if (buf[2] == 'a') {
        fprintf(stdout, "abort1");
        abort();
      }
      if (buf[2] == 'b') {
        fprintf(stdout, "abort2");
        abort();
      }
      if (buf[2] == 'c') {
        fprintf(stdout, "abort3");
        abort();
      }
    }
  }

  return 0;
}
