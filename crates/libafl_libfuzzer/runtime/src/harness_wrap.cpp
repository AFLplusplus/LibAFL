#include "harness_wrap.h"

extern "C" int libafl_libfuzzer_test_one_input(
    int (*harness)(const uint8_t *, size_t), const uint8_t *data, size_t len) {
  try {
    return harness(data, len);
  } catch (...) {
    return -2;  // custom code for "we died!"
  }
}

#ifdef _WIN32
  // For Windows API functions used by MiMalloc
  #pragma comment(lib, "advapi32.lib")
  // For Windows networking functionality used by LibAFL
  #pragma comment(lib, "ws2_32.lib")
  // For Windows API functions to retrieve user home directory used by Rust STD
  #pragma comment(lib, "userenv.lib")
  // For base Windows API functions like file reads and writes
  #pragma comment(lib, "ntdll.lib")
  // For crypto functions called by LibAFL's random utilities
  #pragma comment(lib, "bcrypt.lib")
  // Required by windows_core
  #pragma comment(lib, "ole32.lib")
  // For debug facilities used in debug builds
  #pragma comment(lib, "dbghelp.lib")

  #pragma comment(linker, "/export:LLVMFuzzerRunDriver")
  #pragma comment(linker, "/export:__sanitizer_cov_8bit_counters_init")
#endif  // _WIN32
