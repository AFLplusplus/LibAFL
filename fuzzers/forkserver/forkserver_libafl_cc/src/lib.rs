use libafl_targets::{
    map_input_shared_memory, map_shared_memory, start_forkserver, StdForkserverParent,
};

#[no_mangle]
pub extern "C" fn libafl_start_forkserver() {
    // Map shared memory region for the edge coverage map
    if map_shared_memory().is_err() {
        std::process::exit(1);
    }
    // Map shared memory region for input and its len
    if map_input_shared_memory().is_err() {
        std::process::exit(1);
    };
    // Start the forkserver
    if start_forkserver(&mut StdForkserverParent::new()).is_err() {
        std::process::exit(1);
    };
}
