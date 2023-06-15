#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// The following line is needed for shared memory testcase fuzzing
__AFL_FUZZ_INIT();

void vuln(char *buf) {
  if (strcmp(buf, "vuln") == 0) { abort(); }
}

int main(int argc, char **argv) {
  // Start the forkserver at this point (i.e., forks will happen here)
  __AFL_INIT();

  // The following five lines are for normal fuzzing.
  /*
  FILE *file = stdin;
  if (argc > 1) { file = fopen(argv[1], "rb"); }
  char  buf[16];
  char *p = fgets(buf, 16, file);
  buf[15] = 0;
  */

  // The following line is also needed for shared memory testcase fuzzing
  unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;  // must be after __AFL_INIT

  // printf("input: %s\n", buf);
  if (buf[0] == 'b') {
    if (buf[1] == 'a') {
      if (buf[2] == 'd') { abort(); }
    }
  }
  vuln((char *)buf);

  return 0;
}