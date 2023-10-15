/*
  CMPLOG Callback for instructions
  Why we have functions that does the thing (like cmplog_instructions_inlined and __libafl_targets_cmplog_instructions?)
  because for __libafl_targets_cmplog_instructions, we can't inline them (they need to be exposed so that sancov can find them)
  but when we use our LLVM Passes we could just inline them, resulting one less function call per one cmplog calling site.
*/
#include <sys/types.h>

inline cmplog_instructions_inlined
inline cmplog_instructions_inlined_extended
inline cmplog_instructions_ctx_inlined
inline cmplog_instructions_ctx_inlined_extended

void __cmplog_ins_hook1_extended(uint8_t arg1, uint8_t arg2, uint8_t attr) {
  uintptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);
  k &= CMPLOG_MAP_W - 1;

  __libafl_targets_cmplog_instructions_extended(k, 0, arg1, arg2, attr);
}
void __cmplog_ins_hook1(uint8_t arg1, uint8_t arg2) {
  uintptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);
  k &= CMPLOG_MAP_W - 1;

  __libafl_targets_cmplog_instructions(k, 1, arg1, arg2);
}

void __cmplog_ins_hook2_extended(uint16_t arg1, uint16_t arg2, uint8_t attr) {
  uintptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);
  k &= CMPLOG_MAP_W - 1;

  __libafl_targets_cmplog_instructions_extended(k, 1, arg1, arg2, attr);
}
void __cmplog_ins_hook2(uint16_t arg1, uint16_t arg2) {
  uintptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);
  k &= CMPLOG_MAP_W - 1;

  __libafl_targets_cmplog_instructions(k, 2, arg1, arg2);
}

void __cmplog_ins_hook4_extended(uint32_t arg1, uint32_t arg2, uint8_t attr) {
  uintptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);
  k &= CMPLOG_MAP_W - 1;

  __libafl_targets_cmplog_instructions_extended(k, 3, arg1, arg2, attr);
}
void __cmplog_ins_hook4(uint32_t arg1, uint32_t arg2) {
  uintptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);
  k &= CMPLOG_MAP_W - 1;

  __libafl_targets_cmplog_instructions(k, 4, arg1, arg2);
}

void __cmplog_ins_hook8_extended(uint64_t arg1, uint64_t arg2, uint8_t attr) {
  uintptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);
  k &= CMPLOG_MAP_W - 1;

  __libafl_targets_cmplog_instructions_extended(k, 7, arg1, arg2, attr);
}
void __cmplog_ins_hook8(uint64_t arg1, uint64_t arg2) {
  uintptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);
  k &= CMPLOG_MAP_W - 1;

  __libafl_targets_cmplog_instructions(k, 8, arg1, arg2);
}

#ifndef _WIN32
void __cmplog_ins_hook16_extended(uint128_t arg1, uint128_t arg2,
                                  uint8_t attr) {
  uintptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);
  k &= CMPLOG_MAP_W - 1;

  __libafl_targets_cmplog_instructions_extended(k, 15, arg1, arg2, attr);
}
void __cmplog_ins_hook16(uint128_t arg1, uint128_t arg2) {
  uintptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);
  k &= CMPLOG_MAP_W - 1;

  __libafl_targets_cmplog_instructions(k, 16, arg1, arg2);
}

void __cmplog_ins_hookN_extended(uint128_t arg1, uint128_t arg2, uint8_t attr,
                                 uint8_t size) {
  uintptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);
  k &= CMPLOG_MAP_W - 1;

  __libafl_targets_cmplog_instructions_extended(k, size - 1, arg1, arg2, attr);
}
void __cmplog_ins_hookN(uint128_t arg1, uint128_t arg2, uint8_t size) {
  uintptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);
  k &= CMPLOG_MAP_W - 1;

  __libafl_targets_cmplog_instructions(k, size, arg1, arg2);
}
#endif

/*
  CMPLOG Callback for routines
*/

void __cmplog_rtn_hook(const uint8_t *ptr1, const uint8_t *ptr2) {
  uintptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);
  k &= CMPLOG_MAP_W - 1;

  __libafl_targets_cmplog_routines(k, ptr1, ptr2);
}

void __cmplog_rtn_hook_n(const uint8_t *ptr1, const uint8_t *ptr2,
                         uint64_t len) {
  (void)(len);
  __cmplog_rtn_hook(ptr1, ptr2);
}

/* hook for string functions, eg. strcmp, strcasecmp etc. */
void __cmplog_rtn_hook_str(const uint8_t *ptr1, uint8_t *ptr2) {
  if (!libafl_cmplog_enabled) { return; }
  if (unlikely(!ptr1 || !ptr2)) return;

  // these strnlen could indeed fail. but if it fails here it will sigsegv in
  // the following hooked function call anyways
  int len1 = strnlen(ptr1, 30) + 1;
  int len2 = strnlen(ptr2, 30) + 1;
  int l = MAX(len1, len2);

  l = MIN(l, area_is_valid(ptr1, l + 1));  // can we really access it? check
  l = MIN(l, area_is_valid(ptr2, l + 1));  // can we really access it? check

  if (l < 2) return;

  intptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);
  k &= CMPLOG_MAP_W - 1;

  __libafl_targets_cmplog_routines_checked(k, ptr1, ptr2, l);
}

/* hook for string with length functions, eg. strncmp, strncasecmp etc.
   Note that we ignore the len parameter and take longer strings if present. */
void __cmplog_rtn_hook_strn(uint8_t *ptr1, uint8_t *ptr2, uint64_t len) {
  if (!libafl_cmplog_enabled) { return; }
  if (unlikely(!ptr1 || !ptr2)) return;

  int len0 = MIN(len, 31);  // cap by 31
  // these strnlen could indeed fail. but if it fails here it will sigsegv in
  // the following hooked function call anyways
  int len1 = strnlen(ptr1, len0);
  int len2 = strnlen(ptr2, len0);
  int l = MAX(len1, len2);

  l = MIN(l, area_is_valid(ptr1, l + 1));  // can we really access it? check
  l = MIN(l, area_is_valid(ptr2, l + 1));  // can we really access it? check

  if (l < 2) return;

  intptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);
  k &= CMPLOG_MAP_W - 1;

  __libafl_targets_cmplog_routines_checked(k, ptr1, ptr2, l);
}

// gcc libstdc++
// _ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE7compareEPKc
static const uint8_t *get_gcc_stdstring(const uint8_t *string) {
  uint32_t *len = (uint32_t *)(string + 8);

  if (*len < 16) {  // in structure
    return (string + 16);
  } else {  // in memory
    uint8_t **ptr = (uint8_t **)string;
    return (*ptr);
  }
}

// llvm libc++ _ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocator
//             IcEEE7compareEmmPKcm
static const uint8_t *get_llvm_stdstring(const uint8_t *string) {
  // length is in: if ((string[0] & 1) == 0) {uint8_t len = (string[0] >> 1);}
  // or: if (string[0] & 1) {uint32_t *len = (uint32_t *) (string + 8);}

  if (string[0] & 1) {  // in memory
    uint8_t **ptr = (uint8_t **)(string + 16);
    return (*ptr);
  } else {  // in structure
    return (string + 1);
  }
}

void __cmplog_rtn_gcc_stdstring_cstring(const uint8_t *stdstring,
                                        const uint8_t *cstring) {
  if (!libafl_cmplog_enabled) { return; }
  // This gcc string structure has 32 bytes of content at max
  // That's what 32 means!
  if (area_is_valid(stdstring, 32) <= 0) { return; }

  int l1 = area_is_valid(cstring, CMPLOG_RTN_LEN);
  if (l1 <= 0) { return; }

  const uint8_t *string_ptr = get_gcc_stdstring(stdstring);
  int            l2 = area_is_valid(string_ptr, CMPLOG_RTN_LEN);
  if (l2 <= 0) { return; }

  int len = MIN(31, MIN(l1, l2));

  uintptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);
  k &= CMPLOG_MAP_W - 1;
  __libafl_targets_cmplog_routines_checked(k, string_ptr, cstring, len);
}

void __cmplog_rtn_gcc_stdstring_stdstring(const uint8_t *stdstring1,
                                          const uint8_t *stdstring2) {
  if (!libafl_cmplog_enabled) { return; }

  if (area_is_valid(stdstring1, 32) <= 0) { return; };
  if (area_is_valid(stdstring2, 32) <= 0) { return; };

  const uint8_t *string_ptr1 = get_gcc_stdstring(stdstring1);
  int            l1 = area_is_valid(string_ptr1, CMPLOG_RTN_LEN);
  if (l1 <= 0) { return; }

  const uint8_t *string_ptr2 = get_gcc_stdstring(stdstring2);
  int            l2 = area_is_valid(string_ptr2, CMPLOG_RTN_LEN);
  if (l2 <= 0) { return; }

  int len = MIN(31, MIN(l1, l2));

  uintptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);
  k &= CMPLOG_MAP_W - 1;
  __libafl_targets_cmplog_routines_checked(k, string_ptr1, string_ptr2, len);
}

void __cmplog_rtn_llvm_stdstring_cstring(const uint8_t *stdstring,
                                         const uint8_t *cstring) {
  if (!libafl_cmplog_enabled) { return; }

  if (area_is_valid(stdstring, 32) <= 0) { return; }

  int l1 = area_is_valid(cstring, CMPLOG_RTN_LEN);
  if (l1 <= 0) { return; }

  const uint8_t *string_ptr = get_llvm_stdstring(stdstring);
  int            l2 = area_is_valid(string_ptr, CMPLOG_RTN_LEN);
  if (l2 <= 0) { return; }

  int len = MIN(31, MIN(l1, l2));

  uintptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);
  k &= CMPLOG_MAP_W - 1;
  __libafl_targets_cmplog_routines_checked(k, string_ptr, cstring, len);
}

void __cmplog_rtn_llvm_stdstring_stdstring(const uint8_t *stdstring1,
                                           const uint8_t *stdstring2) {
  if (!libafl_cmplog_enabled) { return; }

  if (area_is_valid(stdstring1, 32) <= 0) { return; };
  if (area_is_valid(stdstring2, 32) <= 0) { return; };

  const uint8_t *string_ptr1 = get_gcc_stdstring(stdstring1);
  int l1 = area_is_valid(get_gcc_stdstring(stdstring1), CMPLOG_RTN_LEN);
  if (l1 <= 0) { return; }

  const uint8_t *string_ptr2 = get_gcc_stdstring(stdstring2);
  int l2 = area_is_valid(get_gcc_stdstring(stdstring2), CMPLOG_RTN_LEN);
  if (l2 <= 0) { return; }

  int len = MIN(31, MIN(l1, l2));

  uintptr_t k = RETADDR;
  k = (k >> 4) ^ (k << 8);
  k &= CMPLOG_MAP_W - 1;
  __libafl_targets_cmplog_routines_checked(k, string_ptr1, string_ptr2, len);
}
