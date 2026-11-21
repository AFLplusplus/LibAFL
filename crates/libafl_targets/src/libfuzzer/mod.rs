//! [`Libfuzzer`](https://www.llvm.org/docs/LibFuzzer.html)-style runtime wrapper for `LibAFL`.
//!
//! This makes `LibAFL` interoperable with harnesses written for other fuzzers like `Libfuzzer` and [`AFLplusplus`](aflplus.plus).
//! We will interact with a C++ target, so use external c functionality

use alloc::{boxed::Box, string::String, vec::Vec};
use core::{
    ffi::{c_char, c_int},
    ptr,
};

mod mutators;
pub use mutators::*;

#[cfg(feature = "libfuzzer_oom")]
mod observers;
#[cfg(feature = "libfuzzer_oom")]
pub use observers::*;

unsafe extern "C" {
    // int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
    fn LLVMFuzzerTestOneInput(data: *const u8, size: usize) -> c_int;

    // libafl_targets_libfuzzer_init calls LLVMFuzzerInitialize()
    fn libafl_targets_libfuzzer_init(argc: *mut c_int, argv: *mut *mut *mut c_char) -> c_int;
}

/// Calls the (native) libfuzzer initialize function.
/// Returns the value returned by the init function.
///
/// # Safety
/// Calls the libfuzzer-style init function which is native code.
#[expect(clippy::must_use_candidate, clippy::similar_names)] // nobody uses that return code...
pub unsafe fn libfuzzer_initialize(args: &[String]) -> i32 {
    let mut argc = c_int::try_from(args.len()).expect("args length exceeds c_int::MAX");
    // Leak NUL-terminated `argv` buffers for `LLVMFuzzerInitialize` callers that retain pointers.
    let mut argv: Vec<*mut c_char> = Vec::with_capacity(args.len() + 1);
    for arg in args {
        let bytes = arg.as_bytes();
        let nul_pos = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        let mut c_arg = Vec::with_capacity(nul_pos + 1);
        c_arg.extend_from_slice(&bytes[..nul_pos]);
        c_arg.push(0);
        argv.push(Box::leak(c_arg.into_boxed_slice()).as_mut_ptr().cast());
    }
    argv.push(ptr::null_mut());
    let mut argv_ptr = Box::leak(argv.into_boxed_slice()).as_mut_ptr();
    unsafe { libafl_targets_libfuzzer_init(&raw mut argc, &raw mut argv_ptr) }
}

/// Call a single input of a libfuzzer-style cpp-harness
///
/// # Safety
/// Calls the libfuzzer harness. We actually think the target is unsafe and crashes eventually, that's why we do all this fuzzing.
#[expect(clippy::must_use_candidate)]
pub unsafe fn libfuzzer_test_one_input(buf: &[u8]) -> i32 {
    unsafe { LLVMFuzzerTestOneInput(buf.as_ptr(), buf.len()) }
}
