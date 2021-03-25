#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define true 1
#define false 0

#ifdef _WIN32

#ifdef _MSC_VER
#define LIBFUZZER_MSVC 1
#else
#define LIBFUZZER_MSVC 0
#endif  // _MSC_VER

// From Libfuzzer
// Intermediate macro to ensure the parameter is expanded before stringified.
#define STRINGIFY_(A) #A
#define STRINGIFY(A) STRINGIFY_(A)

#if LIBFUZZER_MSVC
// Copied from compiler-rt/lib/sanitizer_common/sanitizer_win_defs.h
#if defined(_M_IX86) || defined(__i386__)
#define WIN_SYM_PREFIX "_"
#else
#define WIN_SYM_PREFIX
#endif

// Declare external functions as having alternativenames, so that we can
// determine if they are not defined.
#define EXTERNAL_FUNC(Name, Default)                                   \
  __pragma(comment(linker, "/alternatename:" WIN_SYM_PREFIX STRINGIFY( \
                               Name) "=" WIN_SYM_PREFIX STRINGIFY(Default)))
#else
// Declare external functions as weak to allow them to default to a specified
// function if not defined explicitly. We must use weak symbols because clang's
// support for alternatename is not 100%, see
// https://bugs.llvm.org/show_bug.cgi?id=40218 for more details.
#define EXTERNAL_FUNC(Name, Default) \
  __attribute__((weak, alias(STRINGIFY(Default))))
#endif  // LIBFUZZER_MSVC

#define EXT_FUNC(NAME, RETURN_TYPE, FUNC_SIG, WARN)         \
  RETURN_TYPE NAME##Def FUNC_SIG {                          \
    printf("ERROR: Function \"%s\" not defined.\n", #NAME); \
    exit(1);                                                \
  }                                                         \
  EXTERNAL_FUNC(NAME, NAME##Def) RETURN_TYPE NAME FUNC_SIG

#else

// Declare these symbols as weak to allow them to be optionally defined.
#define EXT_FUNC(NAME, RETURN_TYPE, FUNC_SIG, WARN)                            \
  __attribute__((weak, visibility("default"))) RETURN_TYPE NAME FUNC_SIG

#endif

EXT_FUNC(LLVMFuzzerInitialize, int, (int *argc, char ***argv), false);
EXT_FUNC(LLVMFuzzerCustomMutator, size_t,
         (uint8_t *Data, size_t Size, size_t MaxSize, unsigned int Seed),
         false);
EXT_FUNC(LLVMFuzzerCustomCrossOver, size_t,
         (const uint8_t *Data1, size_t Size1,
          const uint8_t *Data2, size_t Size2,
          uint8_t *Out, size_t MaxOutSize, unsigned int Seed),
         false);

#undef EXT_FUNC

int libafl_targets_has_libfuzzer_init() {
  return LLVMFuzzerInitialize != NULL;
}

int libafl_targets_libfuzzer_init(int *argc, char ***argv) {
  if (LLVMFuzzerInitialize) {
    return LLVMFuzzerInitialize(argc, argv);
  } else {
   return 0;
  }
}
