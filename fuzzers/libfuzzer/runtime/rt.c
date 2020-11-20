

__attribute__((weak)) int LLVMFuzzerInitialize(int *argc, char ***argv);

void afl_libfuzzer_main();

int main(int argc, char** argv) {

  if (LLVMFuzzerInitialize)
    LLVMFuzzerInitialize(&argc, &argv);
  
  afl_libfuzzer_main();
  return 0;

}
