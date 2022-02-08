#include <stdint.h>

uint8_t* __afl_area_ptr;
uint8_t* __afl_acc_memop_ptr;

void __libafl_targets_cmplog_instructions(uintptr_t k, uint8_t shape, uint64_t arg1, uint64_t arg2) {
    (void)k;
    (void)shape;
    (void)arg1;
    (void)arg2;
}

void __cmplog_rtn_hook(uint8_t *ptr1, uint8_t *ptr2) {
    (void)ptr1;
    (void)ptr2;
}

void __cmplog_rtn_gcc_stdstring_cstring(uint8_t *stdstring, uint8_t *cstring) {
    (void)stdstring;
    (void)cstring;
}

void __cmplog_rtn_gcc_stdstring_stdstring(uint8_t *stdstring1, uint8_t *stdstring2) {
    (void)stdstring1;
    (void)stdstring2;
}

void __cmplog_rtn_llvm_stdstring_cstring(uint8_t *stdstring, uint8_t *cstring) {
    (void)stdstring;
    (void)cstring;
}

void __cmplog_rtn_llvm_stdstring_stdstring(uint8_t *stdstring1, uint8_t *stdstring2) {
    (void)stdstring1;
    (void)stdstring2;
}
