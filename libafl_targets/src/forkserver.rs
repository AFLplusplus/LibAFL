//! Forkserver logic into targets

extern "C" {
    /// Start the forkserver.
    fn __afl_start_forkserver() -> !;
}

/// Start the forkserver from this point. Any shared memory must be created before.
///
/// # Note
///
/// The forkserver logic is written in C and this code is a wrapper.
pub fn start_forkserver() -> ! {
    unsafe { __afl_start_forkserver() }
}
