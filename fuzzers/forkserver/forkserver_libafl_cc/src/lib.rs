use libafl_bolts::shmem::StdShMemProvider;
use libafl_targets::{
    map_input_shared_memory, map_shared_memory, start_forkserver, MaybePersistentForkserverParent,
};

#[no_mangle]
pub extern "C" fn libafl_start_forkserver() {
    let Ok(mut shm_provider) = StdShMemProvider::new() else {
        std::process::exit(1);
    };

    // Map shared memory region for the edge coverage map
    if map_shared_memory(&mut shm_provider).is_err() {
        std::process::exit(1);
    }
    // Map shared memory region for input and its len
    if map_input_shared_memory(&mut shm_provider).is_err() {
        std::process::exit(1);
    };
    // Start the forkserver
    if start_forkserver(&mut MaybePersistentForkserverParent::new()).is_err() {
        std::process::exit(1);
    };
}
