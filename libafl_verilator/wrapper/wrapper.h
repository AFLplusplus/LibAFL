#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>

void __libafl_set_coverage_file_fd(int fd);
int __libafl_get_coverage_file_fd();

void __libafl_process_verilator_coverage();

void __libafl_reset_verilator_coverage();

#ifdef __cplusplus
}
#endif
