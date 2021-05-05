//! (Libfuzzer)[https://www.llvm.org/docs/LibFuzzer.html]-style runtime wrapper for LibAFL.
//! This makes LibAFL interoperable with harnesses written for other fuzzers like Libfuzzer and AFLplusplus.
//! We will interact with a C++ target, so use external c functionality

extern "C" {
    /// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
    fn LLVMFuzzerTestOneInput(data: *const u8, size: usize) -> i32;

    // libafl_targets_libfuzzer_init calls LLVMFUzzerInitialize()
    fn libafl_targets_libfuzzer_init(argc: *const i32, argv: *const *const *const u8) -> i32;
}

/// Calls the (native) libfuzzer initialize function.
/// # Safety
/// Calls the libfuzzer-style init function which is native code.
#[allow(clippy::similar_names)]
pub fn libfuzzer_initialize(args: &[String]) -> i32 {
    let argv: Vec<*const u8> = args.iter().map(|x| x.as_bytes().as_ptr()).collect();
    assert!(argv.len() < i32::MAX as usize);
    #[allow(clippy::cast_possible_wrap)]
    let argc = argv.len() as i32;
    unsafe {
        libafl_targets_libfuzzer_init(
            &argc as *const i32,
            &argv.as_ptr() as *const *const *const u8,
        )
    }
}

/// Call a single input of a libfuzzer-style cpp-harness
/// # Safety
/// Calls the libfuzzer harness. We actually think the target is unsafe and crashes eventually, that's why we do all this fuzzing.
pub fn libfuzzer_test_one_input(buf: &[u8]) -> i32 {
    unsafe { LLVMFuzzerTestOneInput(buf.as_ptr(), buf.len()) }
}
