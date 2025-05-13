#include <stdio.h>

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
  int            len = __AFL_FUZZ_TESTCASE_LEN;

  printf("{\"len\": %d}", len);

  return 0;
}