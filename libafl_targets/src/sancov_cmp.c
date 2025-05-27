#include "common.h"

#ifdef SANCOV_VALUE_PROFILE
  #include "value_profile.h"
#endif

#ifdef SANCOV_CMPLOG
  #include "cmplog.h"
#endif

// Note: for RETADDR to give us the fuzz target caller address we need
//       to guarantee that this code is inlined. `inline` keyword provides
//       no such guarantees, but a macro does.
#ifdef SANCOV_VALUE_PROFILE
  #define SANCOV_VALUE_PROFILE_CALL(k, arg_size, arg1, arg2, arg1_is_const) \
    k &= CMP_MAP_SIZE - 1;                                                  \
    __libafl_targets_value_profile##arg_size(k, arg1, arg2);
#else
  #define SANCOV_VALUE_PROFILE_CALL(k, arg_size, arg1, arg2, arg1_is_const)
#endif

#ifdef SANCOV_CMPLOG
  #define SANCOV_CMPLOG_CALL(k, arg_size, arg1, arg2, arg1_is_const)         \
    k &= CMPLOG_MAP_W - 1;                                                   \
    cmplog_instructions_checked(k, arg_size, (uint64_t)arg1, (uint64_t)arg2, \
                                arg1_is_const);
#else
  #define SANCOV_CMPLOG_CALL(k, arg_size, arg1, arg2, arg1_is_const)
#endif

#define HANDLE_SANCOV_TRACE_CMP(arg_size, arg1, arg2, arg1_is_const)  \
  {                                                                   \
    uintptr_t k = RETADDR;                                            \
    k = (k >> 4) ^ (k << 8);                                          \
    SANCOV_VALUE_PROFILE_CALL(k, arg_size, arg1, arg2, arg1_is_const) \
    SANCOV_CMPLOG_CALL(k, arg_size, arg1, arg2, arg1_is_const)        \
  }

void __sanitizer_cov_trace_cmp1(uint8_t arg1, uint8_t arg2) {
  HANDLE_SANCOV_TRACE_CMP(1, arg1, arg2, 0);
}

void __sanitizer_cov_trace_cmp2(uint16_t arg1, uint16_t arg2) {
  HANDLE_SANCOV_TRACE_CMP(2, arg1, arg2, 0);
}

void __sanitizer_cov_trace_cmp4(uint32_t arg1, uint32_t arg2) {
  HANDLE_SANCOV_TRACE_CMP(4, arg1, arg2, 0);
}

void __sanitizer_cov_trace_cmp8(uint64_t arg1, uint64_t arg2) {
  HANDLE_SANCOV_TRACE_CMP(8, arg1, arg2, 0);
}

void __sanitizer_cov_trace_switch(uint64_t val, uint64_t *cases) {
  uintptr_t rt = RETADDR;

  // if (!cases[1]) {return;}

  for (uint64_t i = 0; i < cases[0]; i++) {
    uintptr_t k = rt + i;
    k = (k >> 4) ^ (k << 8);
    // val , cases[i + 2]
#ifdef SANCOV_VALUE_PROFILE
    k &= CMP_MAP_SIZE - 1;
    switch (cases[1]) {
      case 8:
        __libafl_targets_value_profile1(k, (uint8_t)val, (uint8_t)cases[i + 2]);
        break;
      case 16:
        __libafl_targets_value_profile2(k, (uint16_t)val,
                                        (uint16_t)cases[i + 2]);
        break;
      case 32:
        __libafl_targets_value_profile4(k, (uint32_t)val,
                                        (uint32_t)cases[i + 2]);
        break;
      default:
        __libafl_targets_value_profile8(k, val, cases[i + 2]);
        break;
    }
#endif
#ifdef SANCOV_CMPLOG
    k &= CMPLOG_MAP_W - 1;
    // Note: cases[i + 2] are the constant values, so keep them in arg1 and
    // indicate that it's const
    cmplog_instructions_checked(k, cases[1] / 8, cases[i + 2], val, 1);
#endif
  }
}

void __sanitizer_cov_trace_const_cmp1(uint8_t arg1, uint8_t arg2) {
  HANDLE_SANCOV_TRACE_CMP(1, arg1, arg2, 1);
}

void __sanitizer_cov_trace_const_cmp2(uint16_t arg1, uint16_t arg2) {
  HANDLE_SANCOV_TRACE_CMP(2, arg1, arg2, 1);
}

void __sanitizer_cov_trace_const_cmp4(uint32_t arg1, uint32_t arg2) {
  HANDLE_SANCOV_TRACE_CMP(4, arg1, arg2, 1);
}

void __sanitizer_cov_trace_const_cmp8(uint64_t arg1, uint64_t arg2) {
  HANDLE_SANCOV_TRACE_CMP(8, arg1, arg2, 1);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

void __sanitizer_cov_trace_pc_indir(uintptr_t Callee) {
  // unused
  // TODO implement
}

#pragma GCC diagnostic pop
