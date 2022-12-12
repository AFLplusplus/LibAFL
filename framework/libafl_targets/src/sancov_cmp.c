#include "common.h"

#ifdef SANCOV_VALUE_PROFILE
#include "value_profile.h"
#endif

#ifdef SANCOV_CMPLOG
#include "cmplog.h"
#endif

void __sanitizer_cov_trace_cmp1(uint8_t arg1, uint8_t arg2) {

  uintptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);

#ifdef SANCOV_VALUE_PROFILE
  k &= CMP_MAP_SIZE - 1;
  __libafl_targets_value_profile1(k, arg1, arg2);
#endif
#ifdef SANCOV_CMPLOG
  k &= CMPLOG_MAP_W - 1;
  __libafl_targets_cmplog(k, 1, (uint64_t)arg1, (uint64_t)arg2);
#endif

}

void __sanitizer_cov_trace_cmp2(uint16_t arg1, uint16_t arg2) {

  uintptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);

#ifdef SANCOV_VALUE_PROFILE
  k &= CMP_MAP_SIZE - 1;
  __libafl_targets_value_profile2(k, arg1, arg2);
#endif
#ifdef SANCOV_CMPLOG
  k &= CMPLOG_MAP_W - 1;
  __libafl_targets_cmplog(k, 2, (uint64_t)arg1, (uint64_t)arg2);
#endif

}

void __sanitizer_cov_trace_cmp4(uint32_t arg1, uint32_t arg2) {

  uintptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);

#ifdef SANCOV_VALUE_PROFILE
  k &= CMP_MAP_SIZE - 1;
  __libafl_targets_value_profile4(k, arg1, arg2);
#endif
#ifdef SANCOV_CMPLOG
  k &= CMPLOG_MAP_W - 1;
  __libafl_targets_cmplog(k, 4, (uint64_t)arg1, (uint64_t)arg2);
#endif

}

void __sanitizer_cov_trace_cmp8(uint64_t arg1, uint64_t arg2) {

  uintptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);

#ifdef SANCOV_VALUE_PROFILE
  k &= CMP_MAP_SIZE - 1;
  __libafl_targets_value_profile8(k, arg1, arg2);
#endif
#ifdef SANCOV_CMPLOG
  k &= CMPLOG_MAP_W - 1;
  __libafl_targets_cmplog(k, 8, (uint64_t)arg1, (uint64_t)arg2);
#endif

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
        __libafl_targets_value_profile2(k, (uint16_t)val, (uint16_t)cases[i + 2]);
        break;
        case 32:
        __libafl_targets_value_profile4(k, (uint32_t)val, (uint32_t)cases[i + 2]);
        break;
        default:
        __libafl_targets_value_profile8(k, val, cases[i + 2]);
        break;
    }
#endif
#ifdef SANCOV_CMPLOG
    k &= CMPLOG_MAP_W - 1;
    __libafl_targets_cmplog(k, cases[1] / 8, val, cases[i + 2]);
#endif


  }

}

void __sanitizer_cov_trace_const_cmp1(uint8_t arg1, uint8_t arg2) {
  __sanitizer_cov_trace_cmp1(arg1, arg2);
}

void __sanitizer_cov_trace_const_cmp2(uint16_t arg1, uint16_t arg2) {
  __sanitizer_cov_trace_cmp2(arg1, arg2);
}

void __sanitizer_cov_trace_const_cmp4(uint32_t arg1, uint32_t arg2) {
  __sanitizer_cov_trace_cmp4(arg1, arg2);
}

void __sanitizer_cov_trace_const_cmp8(uint64_t arg1, uint64_t arg2) {
    __sanitizer_cov_trace_cmp8(arg1, arg2);
}
