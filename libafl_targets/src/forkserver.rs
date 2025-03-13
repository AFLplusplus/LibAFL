//! Forkserver logic into targets

unsafe extern "C" {
    /// Map a shared memory region for the edge coverage map.
    fn __afl_map_shm();
    /// Start the forkserver.
    fn __afl_start_forkserver();
}

/// Map a shared memory region for the edge coverage map.
///
/// # Note
///
/// The function's logic is written in C and this code is a wrapper.
pub fn map_shared_memory() {
    unsafe { __afl_map_shm() }
}

/// Start the forkserver from this point. Any shared memory must be created before.
///
/// # Note
///
/// The forkserver logic is written in C and this code is a wrapper.
pub fn start_forkserver() {
    unsafe { __afl_start_forkserver() }
}
