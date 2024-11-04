#include "harness_wrap.h"

extern "C" int libafl_libfuzzer_test_one_input(
    int (*harness)(const uint8_t *, size_t), const uint8_t *data, size_t len) {
  try {
    return harness(data, len);
  } catch (...) {
    return -2;  // custom code for "we died!"
  }
}
