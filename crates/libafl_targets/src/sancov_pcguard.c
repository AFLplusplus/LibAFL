#include <stdint.h>
#include "common.h"

void __libafl_targets_trace_pc_guard(uint32_t* guard, uintptr_t pc);

/// Specialized trace_pc_guard function for dump_cov mode.
///
/// We need an extra entrypoint into trace_pc_guard for dump_cov mode.
/// __builtin_return_address(0) is not yet supported in stable Rust.
/// We cannot just call down to RETADDR from rust either since then
// _we_ would be the caller..
void __sanitizer_cov_trace_pc_guard(uint32_t* guard) {
  uintptr_t pc = RETADDR;
  __libafl_targets_trace_pc_guard(guard, pc);
}
