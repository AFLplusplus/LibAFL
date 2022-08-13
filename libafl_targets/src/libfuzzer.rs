//! [`Libfuzzer`](https://www.llvm.org/docs/LibFuzzer.html)-style runtime wrapper for `LibAFL`.
//! This makes `LibAFL` interoperable with harnesses written for other fuzzers like `Libfuzzer` and [`AFLplusplus`](aflplus.plus).
//! We will interact with a C++ target, so use external c functionality

use alloc::{string::String, vec::Vec};

extern "C" {
    /// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
    fn LLVMFuzzerTestOneInput(data: *const u8, size: usize) -> i32;

    // libafl_targets_libfuzzer_init calls LLVMFUzzerInitialize()
    fn libafl_targets_libfuzzer_init(argc: *const i32, argv: *const *const *const u8) -> i32;
}

/// Calls the (native) libfuzzer initialize function.
/// Returns the value returned by the init function.
/// # Safety
/// Calls the libfuzzer-style init function which is native code.
#[allow(clippy::similar_names)]
#[allow(clippy::must_use_candidate)] // nobody uses that return code...
pub fn libfuzzer_initialize(args: &[String]) -> i32 {
    let args: Vec<String> = args.iter().map(|x| x.clone() + "\0").collect();
    let argv: Vec<*const u8> = args.iter().map(|x| x.as_bytes().as_ptr()).collect();
    assert!(argv.len() < i32::MAX as usize);
    #[allow(clippy::cast_possible_wrap)]
    let argc = argv.len() as i32;
    unsafe {
        let argv_ptr = argv.as_ptr();
        libafl_targets_libfuzzer_init(core::ptr::addr_of!(argc), core::ptr::addr_of!(argv_ptr))
    }
}

/// Call a single input of a libfuzzer-style cpp-harness
/// # Safety
/// Calls the libfuzzer harness. We actually think the target is unsafe and crashes eventually, that's why we do all this fuzzing.
#[allow(clippy::must_use_candidate)]
pub fn libfuzzer_test_one_input(buf: &[u8]) -> i32 {
    unsafe { LLVMFuzzerTestOneInput(buf.as_ptr(), buf.len()) }
}
