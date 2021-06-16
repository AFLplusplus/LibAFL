// We only want to link our fuzzer main, if the target doesn't specify its own main - hence we define `main` as `weak` in this file.
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

// jump to rust
void fuzzer_main();

// Link in a dummy llvm test to non-fuzzing builds, for configure et al.
int __attribute__((weak)) LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len) {
  (void) buf;
  (void) len;
  fprintf(stderr, "LibAFL - No LLVMFuzzerTestOneInput function found! Linker error?\n");
  fflush(stderr);
  abort();
}

int __attribute__((weak)) main(int argc, char *argv[]) {
  (void) argc;
  (void) argv;
  fuzzer_main();
  return 0;
}