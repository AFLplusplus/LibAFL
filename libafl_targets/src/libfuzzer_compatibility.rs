/// We will interact with a C++ target, so use external c functionality
extern "C" {
    /// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
    fn LLVMFuzzerTestOneInput(data: *const u8, size: usize) -> i32;

    // libafl_targets_libfuzzer_init calls LLVMFUzzerInitialize()
    fn libafl_targets_libfuzzer_init() -> i32;
}

pub fn libfuzzer_initialize() -> i32 {
    unsafe { libafl_targets_libfuzzer_init() }
}

pub fn libfuzzer_test_one_input(buf: &[u8]) -> i32 {
    unsafe { LLVMFuzzerTestOneInput(buf.as_ptr(), buf.len()) }
}
