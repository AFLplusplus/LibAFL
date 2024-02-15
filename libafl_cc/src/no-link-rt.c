#include <stdint.h>

#if !defined(_WIN32) && defined(__SIZEOF_INT128__)
typedef unsigned __int128 uint128_t;
typedef uint128_t         u128;
#endif

uint8_t *__afl_area_ptr;
uint8_t *__afl_acc_memop_ptr;

void __libafl_targets_cmplog_instructions(uintptr_t k, uint8_t shape,
                                          uint64_t arg1, uint64_t arg2) {
  (void)k;
  (void)shape;
  (void)arg1;
  (void)arg2;
}

void __cmplog_ins_hook1_extended(uint8_t arg1, uint8_t arg2, uint8_t attr) {
  (void)arg1;
  (void)arg2;
  (void)attr;
}
void __cmplog_ins_hook1(uint8_t arg1, uint8_t arg2) {
  (void)arg1;
  (void)arg2;
}

void __cmplog_ins_hook2_extended(uint16_t arg1, uint16_t arg2, uint8_t attr) {
  (void)attr;
  (void)arg1;
  (void)arg2;
}
void __cmplog_ins_hook2(uint16_t arg1, uint16_t arg2) {
  (void)arg1;
  (void)arg2;
}

void __cmplog_ins_hook4_extended(uint32_t arg1, uint32_t arg2, uint8_t attr) {
  (void)attr;
  (void)arg1;
  (void)arg2;
}
void __cmplog_ins_hook4(uint32_t arg1, uint32_t arg2) {
  (void)arg1;
  (void)arg2;
}

void __cmplog_ins_hook8_extended(uint64_t arg1, uint64_t arg2, uint8_t attr) {
  (void)attr;
  (void)arg1;
  (void)arg2;
}
void __cmplog_ins_hook8(uint64_t arg1, uint64_t arg2) {
  (void)arg1;
  (void)arg2;
}

#if !defined(_WIN32) && defined(__SIZEOF_INT128__)
void __cmplog_ins_hook16_extended(uint128_t arg1, uint128_t arg2,
                                  uint8_t attr) {
  (void)attr;
  (void)arg1;
  (void)arg2;
}
void __cmplog_ins_hook16(uint128_t arg1, uint128_t arg2) {
  (void)arg1;
  (void)arg2;
}

void __cmplog_ins_hookN_extended(uint128_t arg1, uint128_t arg2, uint8_t attr,
                                 uint8_t size) {
  (void)attr;
  (void)size;
  (void)arg1;
  (void)arg2;
}
void __cmplog_ins_hookN(uint128_t arg1, uint128_t arg2, uint8_t size) {
  (void)arg1;
  (void)arg2;
  (void)size;
}
#endif

void __cmplog_rtn_hook(uint8_t *ptr1, uint8_t *ptr2) {
  (void)ptr1;
  (void)ptr2;
}
void __cmplog_rtn_hook_extended(uint8_t *ptr1, uint8_t *ptr2) {
  (void)ptr1;
  (void)ptr2;
}

void __cmplog_rtn_hook_n(const uint8_t *ptr1, const uint8_t *ptr2,
                         uint64_t len) {
  (void)ptr1;
  (void)ptr2;
  (void)len;
}
void __cmplog_rtn_hook_n_extended(const uint8_t *ptr1, const uint8_t *ptr2,
                                  uint64_t len) {
  (void)ptr1;
  (void)ptr2;
  (void)len;
}

void __cmplog_rtn_hook_str(const uint8_t *ptr1, uint8_t *ptr2) {
  (void)ptr1;
  (void)ptr2;
}
void __cmplog_rtn_hook_str_extended(const uint8_t *ptr1, uint8_t *ptr2) {
  (void)ptr1;
  (void)ptr2;
}

void __cmplog_rtn_hook_strn(uint8_t *ptr1, uint8_t *ptr2, uint64_t len) {
  (void)ptr1;
  (void)ptr2;
  (void)len;
}
void __cmplog_rtn_hook_strn_extended(uint8_t *ptr1, uint8_t *ptr2,
                                     uint64_t len) {
  (void)ptr1;
  (void)ptr2;
  (void)len;
}

void __cmplog_rtn_gcc_stdstring_cstring(uint8_t *stdstring, uint8_t *cstring) {
  (void)stdstring;
  (void)cstring;
}
void __cmplog_rtn_gcc_stdstring_cstring_extended(uint8_t *stdstring,
                                                 uint8_t *cstring) {
  (void)stdstring;
  (void)cstring;
}

void __cmplog_rtn_gcc_stdstring_stdstring(uint8_t *stdstring1,
                                          uint8_t *stdstring2) {
  (void)stdstring1;
  (void)stdstring2;
}
void __cmplog_rtn_gcc_stdstring_stdstring_extended(uint8_t *stdstring1,
                                                   uint8_t *stdstring2) {
  (void)stdstring1;
  (void)stdstring2;
}

void __cmplog_rtn_llvm_stdstring_cstring(uint8_t *stdstring, uint8_t *cstring) {
  (void)stdstring;
  (void)cstring;
}
void __cmplog_rtn_llvm_stdstring_cstring_extended(uint8_t *stdstring,
                                                  uint8_t *cstring) {
  (void)stdstring;
  (void)cstring;
}

void __cmplog_rtn_llvm_stdstring_stdstring(uint8_t *stdstring1,
                                           uint8_t *stdstring2) {
  (void)stdstring1;
  (void)stdstring2;
}
void __cmplog_rtn_llvm_stdstring_stdstring_extended(uint8_t *stdstring1,
                                                    uint8_t *stdstring2) {
  (void)stdstring1;
  (void)stdstring2;
}
