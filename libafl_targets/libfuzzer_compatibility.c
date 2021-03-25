static int orig_argc;
static char **orig_argv;
static char **orig_envp;

static void save_main_args(int argc, char** argv, char** envp) {
   orig_argc = argc;
   orig_argv = argv;
   orig_envp = envp;
}

__attribute__((section(".init_array")))
void (*p_libafl_targets_save_main_args)(int, char*[], char*[]) = &save_main_args;

__attribute__((weak))
int LLVMFuzzerInitialize(int *argc, char ***argv);

int libafl_targets_libfuzzer_init() {

  if (LLVMFuzzerInitialize) {
    return LLVMFuzzerInitialize(&orig_argc, &orig_argv);
  } else {
   return 0;
  }

}
