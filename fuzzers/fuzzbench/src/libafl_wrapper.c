// We only want to link our fuzzer main, if the target doesn't specify its own main - hence we define `main` as `weak` in this file.
void fuzzer_main();

int __attribute__((weak)) main(int argc, char *argv[]) {
  (void) argc;
  (void) argv;
  fuzzer_main();
  return 0;
}