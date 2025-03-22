//! Forkserver logic into targets

unsafe extern "C" {
    /// Map a shared memory region for the edge coverage map.
    fn __afl_map_shm() -> u8;
    /// Map the input shared memory
    fn __afl_map_input_shm() -> u8;
    /// Start the forkserver.
    fn __afl_start_forkserver();
}

/// Map a shared memory region for the edge coverage map, also referred as
/// [`crate::coverage::EDGES_MAP_PTR`]. This function will intialize 
/// [`crate::coverage::EDGES_MAP_PTR`] to a dummy memory region if
/// AFL is not present and return false.
///
/// # Note
///
/// The function's logic is written in C and this code is a wrapper.
pub fn map_shared_memory() -> bool {
    let ret = unsafe { __afl_map_shm() > 0 };
    if !ret {
        log::debug!("Shared memory for edge coverage map is not detected!");
    }
    ret
}

/// Map the input shared memory region, also referred as [`crate::coverage::INPUT_PTR`].
/// [`start_forkserver`] will call this function automatically if the shared
/// memory feature is enabled. Likewise, [`crate::coverage::INPUT_PTR`] will be
/// initialized to a dummy memory region if AFL is not present.
/// 
/// # Note
///
/// The function's logic is written in C and this code is a wrapper.
pub fn map_input_shared_memory() -> bool {
    let ret = unsafe { __afl_map_input_shm() > 0};

    if !ret {
        log::debug!("Shared memory for AFL++ inputs is not detected!");
    }
    ret
}

/// Start the forkserver from this point. Any shared memory must be created before.
///
/// # Note
///
/// The forkserver logic is written in C and this code is a wrapper.
pub fn start_forkserver() {
    unsafe { __afl_start_forkserver() }
}
