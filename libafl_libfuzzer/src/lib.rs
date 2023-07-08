//! libafl_libfuzzer offers a "permanent" replacement for the now-deprecated libfuzzer
//!
//! This crate only offers sufficient functionality to replace libfuzzer for cargo-fuzz in its
//! current state, but may be expanded to handle other flags in the future.
//!
//! This crate links to a (separately built) internal crate which affords the actual functionality.
//! The internal crate must be built separately to ensure flags from dependent crates are not leaked
//! to the runtime (e.g., to prevent coverage being collected on the runtime).

use std::ffi::{c_char, c_int};

pub use libfuzzer_sys::*;

extern "C" {
    pub fn LLVMFuzzerRunDriver(
        argc: *mut c_int,
        argv: *mut *mut *const c_char,
        harness_fn: Option<extern "C" fn(*const u8, usize) -> c_int>,
    ) -> c_int;
}
