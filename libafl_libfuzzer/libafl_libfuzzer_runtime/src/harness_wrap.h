#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int libafl_libfuzzer_test_one_input(int (*harness)(const uint8_t *, size_t),
                                    const uint8_t *data, size_t len);

#ifdef __cplusplus
}
#endif
