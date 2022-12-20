#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#else
#include <stdint.h>
#include <stdbool.h>
#endif

void __libafl_ariane_start(const char *input_file);
void __libafl_ariane_tick();
void __libafl_ariane_terminate();
bool __libafl_ariane_terminated();
void __libafl_ariane_finalize();

#ifdef __cplusplus
}
#endif