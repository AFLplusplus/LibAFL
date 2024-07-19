use libafl_targets::{map_shared_memory, start_forkserver};

#[no_mangle]
pub extern "C" fn libafl_start_forkserver() {
    // Map shared memory region for the edge coverage map
    map_shared_memory();
    // Start the forkserver
    start_forkserver();
}
