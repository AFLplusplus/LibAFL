#include "common.h"

#ifdef SANCOV_VALUE_PROFILE
  #include "value_profile.h"
#endif

#ifdef SANCOV_CMPLOG
  #include "cmplog.h"
  #include <sanitizer/common_interface_defs.h>
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

#ifdef SANCOV_CMPLOG

void __sanitizer_weak_hook_memcmp(void *called_pc, const void *s1,
                                  const void *s2, size_t n, int result) {
  if (result != 0) {
    uintptr_t k = (uintptr_t)called_pc;
    k = (k >> 4) ^ (k << 8);
    k &= CMPLOG_MAP_W - 1;

    __libafl_targets_cmplog_routines_len(k, s1, s2, MIN(n, 32));
  }
}

void __sanitizer_weak_hook_strncmp(void *called_pc, const char *s1,
                                   const char *s2, size_t n, int result) {
  if (result != 0) {
    n = MIN(n, 32);

    uintptr_t k = (uintptr_t)called_pc;
    k = (k >> 4) ^ (k << 8);
    k &= CMPLOG_MAP_W - 1;

    size_t actual_len;
    for (actual_len = 0; actual_len < n; actual_len++) {
      if (s1[actual_len] == 0 || s2[actual_len] == 0) { break; }
    }

    __libafl_targets_cmplog_routines_len(k, (const uint8_t *) s1, (const uint8_t *) s2, actual_len);
  }
}

void __sanitizer_weak_hook_strncasecmp(void *called_pc, const char *s1,
                                       const char *s2, size_t n, int result) {
  __sanitizer_weak_hook_strncmp(called_pc, s1, s2, n, result);
}

void __sanitizer_weak_hook_strcmp(void *called_pc, const char *s1,
                                  const char *s2, int result) {
  if (result != 0) {
    uintptr_t k = (uintptr_t)called_pc;
    k = (k >> 4) ^ (k << 8);
    k &= CMPLOG_MAP_W - 1;

    size_t actual_len;
    for (actual_len = 0; actual_len < 32; actual_len++) {
      if (s1[actual_len] == 0 || s2[actual_len] == 0) { break; }
    }

    __libafl_targets_cmplog_routines_len(k, (const uint8_t *) s1, (const uint8_t *) s2, actual_len);
  }
}

void __sanitizer_weak_hook_strcasecmp(void *called_pc, const char *s1,
                                      const char *s2, int result) {
  __sanitizer_weak_hook_strcmp(called_pc, s1, s2, result);
}

// strstr, strcasestr, memmem unhandled

#endif

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

void __sanitizer_cov_pcs_init(const uintptr_t *pcs_beg,
                              const uintptr_t *pcs_end) {
  // unused
  // TODO implement
}

void __sanitizer_cov_trace_pc_indir(uintptr_t Callee) {
  // unused
  // TODO implement
}

#pragma GCC diagnostic pop
