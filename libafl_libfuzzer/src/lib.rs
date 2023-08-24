//! `libafl_libfuzzer` offers a "permanent" replacement for the now-deprecated libfuzzer
//!
//! ## Usage
//!
//! To use LibAFL in place of libfuzzer, change the following line in your fuzz/Cargo.toml:
//!
//! ```toml
//! libfuzzer-sys = { version = "*", features = [...] }
//! ```
//!
//! With the following:
//!
//! ```toml
//! libfuzzer-sys = { version = "*", features = [...], package = "libafl_libfuzzer" }
//! ```
//!
//! To use bleeding changes from upstream, use the following:
//!
//! ```toml
//! libfuzzer-sys = { version = "*", features = [...], package = "libafl_libfuzzer", git = "https://github.com/AFLplusplus/LibAFL" }
//! ```
//!
//! ## Flags
//!
//! You can pass additional flags to the libfuzzer runtime in `cargo-fuzz` like so:
//!
//! ```bash
//! cargo fuzz run fuzz_target -- -extra_flag=1
//! ```
//!
//! You will commonly need this for flags such as `-ignore_crashes=1` and `-timeout=5`. In addition
//! to partial support of libfuzzer flags, `libafl_libfuzzer` offers:
//!
//! - `-dedup=n`, with `n` = 1 enabling deduplication of crashes by stacktrace.
//! - `-grimoire=n`, with `n` set to 0 or 1 disabling or enabling [grimoire] mutations, respectively.
//!   - if not specified explicitly, `libafl_libfuzzer` will "guess" which setting is appropriate
//!   - you should disable grimoire if your target is not string-like
//! - `-report=n`, with `n` = 1 causing `libafl_libfuzzer` to emit a report on the corpus content.
//! - `-skip_tracing=n`, with `n` = 1 causing `libafl_libfuzzer` to disable comparison log tracing.
//!   - you should do this if your target performs many comparisons on memory sequences which are
//!     not contained in the input
//! - `-tui=n`, with `n` = 1 enabling a graphical terminal interface.
//!   - experimental; some users report inconsistent behaviour with tui enabled
//!
//! [grimoire]: https://www.usenix.org/conference/usenixsecurity19/presentation/blazytko
//!
//! ### Supported flags from libfuzzer
//!
//! - `-merge`
//! - `-minimize_crash`
//! - `-artifact_prefix`
//! - `-timeout`
//!   - unlike libfuzzer, `libafl_libfuzzer` supports partial second timeouts (e.g. `-timeout=.5`)
//! - `-dict`
//! - `-fork` and `-jobs`
//!   - in `libafl_libfuzzer`, these are synonymous
//! - `-ignore_crashes`, `-ignore_ooms`, and `-ignore_timeouts`
//! - `-rss_limit_mb` and `-malloc_limit_mb`
//! - `-ignore_remaining_args`
//! - `-shrink`
//! - `-runs`
//! - `-close_fd_mask`
//!
//! ## Important notes
//!
//! This crate only offers sufficient functionality to replace libfuzzer for cargo-fuzz in its
//! current state, but may be expanded to handle other flags in the future.
//!
//! This crate links to a (separately built) internal crate which affords the actual functionality.
//! The internal crate must be built separately to ensure flags from dependent crates are not leaked
//! to the runtime (e.g., to prevent coverage being collected on the runtime).

#![doc = document_features::document_features!()]

use std::ffi::{c_char, c_int};

pub use libfuzzer_sys::*;

extern "C" {
    /// `LLVMFuzzerRunDriver` allows for harnesses which specify their own main. See: <https://llvm.org/docs/LibFuzzer.html#using-libfuzzer-as-a-library>
    ///
    /// You can call this function inside of a main function in your harness, or specify `#![no_main]`
    /// to accept the default runtime driver.
    pub fn LLVMFuzzerRunDriver(
        argc: *mut c_int,
        argv: *mut *mut *const c_char,
        harness_fn: Option<extern "C" fn(*const u8, usize) -> c_int>,
    ) -> c_int;
}
