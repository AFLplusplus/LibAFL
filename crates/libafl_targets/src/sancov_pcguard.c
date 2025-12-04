#include <stdint.h>
#include "common.h"

void __libafl_targets_trace_pc_guard(uint32_t* guard, uintptr_t pc);

void __sanitizer_cov_trace_pc_guard(uint32_t* guard) {
  uintptr_t pc = RETADDR;
  __libafl_targets_trace_pc_guard(guard, pc);
}
