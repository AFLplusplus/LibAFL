#include "common.h"
#include <stddef.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
EXT_FUNC(LLVMFuzzerInitialize, int, (int *argc, char ***argv), false);
EXT_FUNC(LLVMFuzzerCustomMutator, size_t,
         (uint8_t *Data, size_t Size, size_t MaxSize, unsigned int Seed),
         false);
EXT_FUNC(LLVMFuzzerCustomCrossOver, size_t,
         (const uint8_t *Data1, size_t Size1,
          const uint8_t *Data2, size_t Size2,
          uint8_t *Out, size_t MaxOutSize, unsigned int Seed),
         false);
EXT_FUNC_IMPL(LLVMFuzzerTestOneInput, int, (uint8_t *Data, size_t Size), false) {
  return 0;
}

EXT_FUNC_IMPL(libafl_main, void, (void), false) {
}
EXT_FUNC_IMPL(main, int, (int argc, char** argv), false) {
  libafl_main();
  return 0;
}
#pragma GCC diagnostic pop

EXPORT_FN int libafl_targets_has_libfuzzer_init() {
  return CHECK_WEAK_FN(LLVMFuzzerInitialize);
}

EXPORT_FN int libafl_targets_libfuzzer_init(int *argc, char ***argv) {
  if (libafl_targets_has_libfuzzer_init()) {
    return LLVMFuzzerInitialize(argc, argv);
  } else {
   return 0;
  }
}
