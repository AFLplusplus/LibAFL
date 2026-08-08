#include <stdint.h>

__attribute__((weak)) void __sanitizer_cov_trace_pc_guard_init(uint32_t *start,
                                                               uint32_t *stop) {
}

__attribute__((weak)) void __sanitizer_cov_trace_pc_guard(uint32_t *guard) {
}

__attribute__((weak)) void __cmplog_rtn_hook(uint8_t *ptr1, uint8_t *ptr2) {
}

__attribute__((weak)) void __cmplog_rtn_gcc_stdstring_cstring(
    uint8_t *stdstring, uint8_t *cstring) {
}

__attribute__((weak)) void __cmplog_rtn_gcc_stdstring_stdstring(
    uint8_t *stdstring1, uint8_t *stdstring2) {
}

__attribute__((weak)) void __cmplog_rtn_llvm_stdstring_cstring(
    uint8_t *stdstring, uint8_t *cstring) {
}

__attribute__((weak)) void __cmplog_rtn_llvm_stdstring_stdstring(
    uint8_t *stdstring1, uint8_t *stdstring2) {
}

extern void libafl_main(void);

int main(int argc, char **argv) {
  libafl_main();
  return 0;
}
