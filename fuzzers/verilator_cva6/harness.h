#pragma once

#ifdef __cplusplus
extern "C" {
#else
#include <stdint.h>
#endif

void __libafl_ariane_start(const char *input_file);
int __libafl_ariane_test_one_input(int input_fd);

#ifdef __cplusplus
}
#endif