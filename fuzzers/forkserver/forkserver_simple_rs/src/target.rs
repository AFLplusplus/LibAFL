use libafl::executors::forkserver::MAX_INPUT_SIZE_DEFAULT;
use libafl_bolts::shmem::{ShMemProvider, StdShMemProvider};
#[cfg(feature = "shared_input_mem")]
use libafl_targets::map_input_shared_memory;
use libafl_targets::{
    map_shared_memory, start_forkserver, ForkserverState, MaybePersistentForkserverParent,
    EDGES_MAP_PTR, INPUT_LENGTH_PTR, INPUT_PTR, SHM_FUZZING,
};

static mut BUF: [u8; MAX_INPUT_SIZE_DEFAULT] = [0u8; MAX_INPUT_SIZE_DEFAULT];

fn read_input() -> &'static [u8] {
    if unsafe { SHM_FUZZING != 0 } {
        let len = unsafe { *INPUT_LENGTH_PTR } as usize;
        return unsafe { core::slice::from_raw_parts(INPUT_PTR, len) };
    }
    let n = unsafe { libc::read(0, &raw mut BUF as *mut libc::c_void, MAX_INPUT_SIZE_DEFAULT) };
    assert!(n >= 0);
    unsafe {
        INPUT_PTR = &raw mut BUF as *mut u8;
        *INPUT_LENGTH_PTR = n as u32;
    }
    unsafe { core::slice::from_raw_parts(&raw const BUF as *const u8, n as usize) }
}

fn process_input(buf: &[u8]) {
    // Guide the fuzzer toward the "bad" string by setting coverage
    // as each successive character matches.
    #[allow(clippy::len_zero)]
    if buf.len() > 0 && buf[0] == b'b' {
        unsafe { EDGES_MAP_PTR.add(0).write(1) };
    }
    if buf.len() > 1 && buf[1] == b'a' {
        unsafe { EDGES_MAP_PTR.add(1).write(1) };
    }
    if buf.len() > 2 && buf[2] == b'd' {
        unsafe { EDGES_MAP_PTR.add(2).write(1) };
    }

    if buf.starts_with(b"bad") {
        unsafe { libc::raise(libc::SIGABRT) };
    }
}

fn is_persistent() -> bool {
    std::env::var("__AFL_PERSISTENT").is_ok_and(|v| v == "1")
}

fn main() {
    let mut shm_provider = StdShMemProvider::new().unwrap();

    // Map the coverage map shared memory set up by the fuzzer.
    map_shared_memory(&mut shm_provider).unwrap();

    #[cfg(feature = "shared_input_mem")]
    {
        // SHM_FUZZING tells the forkserver parent that we can receive inputs
        // via shared memory instead of stdin. The parent will write the input
        // into the shared memory region and signal us to process it.
        unsafe { SHM_FUZZING = 1 };
        map_input_shared_memory(&mut shm_provider).unwrap();
    }

    // `MaybePersistentForkserverParent` supports both one-shot and persistent
    // forkserver modes. In persistent mode, the child is resumed via SIGCONT
    // instead of being re-forked for each input.
    match start_forkserver(&mut MaybePersistentForkserverParent::new()).unwrap() {
        ForkserverState::Child if is_persistent() => loop {
            process_input(read_input());
            // SIGSTOP tells the parent we're done with this input
            // and ready for the next one. The parent resumes us with SIGCONT.
            unsafe { libc::raise(libc::SIGSTOP) };
        },
        ForkserverState::Child => {
            process_input(read_input());
        }
        _ => {}
    }
}
