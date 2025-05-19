use libafl_bolts::shmem::{ShMemProvider, StdShMemProvider};
use libafl_targets::{
    map_input_shared_memory, map_shared_memory, start_forkserver, MaybePersistentForkserverParent,
};

#[no_mangle]
pub extern "C" fn libafl_start_forkserver() {
    let mut shm_provider = match StdShMemProvider::new() {
        Ok(shm_provider) => shm_provider,
        Err(err) => {
            eprintln!("Forkserver failed to create shared memory provider: {err}");
            std::process::exit(1);
        }
    };

    // Map shared memory region for the edge coverage map
    if let Err(err) = map_shared_memory(&mut shm_provider) {
        eprintln!("Forkserver failed to create edge map: {err}");
        std::process::exit(1);
    }
    // Map shared memory region for input and its len
    if let Err(err) = map_input_shared_memory(&mut shm_provider) {
        eprintln!("Forkserver failed to create input map: {err}");
        std::process::exit(1);
    }
    // Start the forkserver
    if let Err(err) = start_forkserver(&mut MaybePersistentForkserverParent::new()) {
        eprintln!("Forkserver unexpected error: {err}");
        std::process::exit(1);
    }
}
