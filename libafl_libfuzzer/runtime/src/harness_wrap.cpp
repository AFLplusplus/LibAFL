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
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "dbghelp.lib")

#pragma comment(linker, "/export:LLVMFuzzerRunDriver")
#pragma comment(linker, "/export:__sanitizer_cov_8bit_counters_init")
#endif // _WIN32
