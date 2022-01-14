//! the ``StacktraceObserver`` looks up the stacktrace on the execution thread and computes a hash for it for dedupe

use crate::{
    bolts::{
        shmem::{
            unix_shmem::ashmem::AshmemShMem, GenericShMem, MmapShMem, ShMem, ShMemId,
            ShMemProvider, ShMemType, StdShMem, UnixShMem,
        },
        tuples::Named,
    },
    observers::Observer,
    Error,
};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

/// A struct that stores needed information to persist the backtrace across prcesses/runs
#[derive(Debug)]
pub struct BacktraceSharedMemoryWrapper {
    /// ID of the shared memory
    shmem_id: Option<ShMemId>,
    /// Size of the shared memory
    shmem_size: Option<usize>,
    /// Type of the shared memory
    shmem_type: Option<ShMemType>,
}

impl BacktraceSharedMemoryWrapper {
    fn update_shmem_info(&mut self, shmem_id: ShMemId, shmem_size: usize, shmem_type: ShMemType) {
        self.shmem_id = Some(shmem_id);
        self.shmem_size = Some(shmem_size);
        self.shmem_type = Some(shmem_type);
    }

    fn is_ready(&self) -> bool {
        match (self.shmem_id, self.shmem_size, self.shmem_type.as_ref()) {
            (None, _, _) => false,
            (_, None, _) => false,
            (_, _, None) => false,
            _ => true,
        }
    }

    fn get_generic_shmem(&self) -> GenericShMem {
        if self.is_ready() {
            let id = self.shmem_id.unwrap();
            let size = self.shmem_size.unwrap();
            let g_shmem: GenericShMem;
            match self.shmem_type.as_ref().unwrap() {
                ShMemType::AshmemShMem => {
                    g_shmem =
                        GenericShMem::AshmemShMem(AshmemShMem::from_id_and_size(id, size).unwrap());
                }
                ShMemType::MmapShMem => {
                    g_shmem =
                        GenericShMem::MmapShMem(MmapShMem::from_id_and_size(id, size).unwrap());
                }
                ShMemType::StdShMem => {
                    g_shmem = GenericShMem::StdShMem(StdShMem::from_id_and_size(id, size).unwrap());
                }
                ShMemType::UnixShMem => {
                    g_shmem =
                        GenericShMem::UnixShMem(UnixShMem::from_id_and_size(id, size).unwrap());
                } // _ => panic!("Unknown ShMemType"),
            }

            g_shmem
        } else {
            panic!("Cannot get generic shmem from uninitialized item");
        }
    }

    fn store_stacktrace_hash(&self, hash: u64) {
        let mut g_shmem = self.get_generic_shmem();
        let map = g_shmem.map_mut();
        let hash_bytes = hash.to_be_bytes();
        for i in 0..hash_bytes.len() {
            map[i] = hash_bytes[i]
        }
    }

    fn get_stacktrace_hash(&self) -> u64 {
        let g_shmem = self.get_generic_shmem();
        let map = g_shmem.map();
        let mut bytes: [u8; 8] = [0; 8];
        for i in 0..8 {
            bytes[i] = map[i];
        }
        u64::from_be_bytes(bytes)
    }
}

// Used for fuzzers not running in the same process
/// Static variable storing shared memory information
pub static mut BACKTRACE_SHMEM_DATA: BacktraceSharedMemoryWrapper = BacktraceSharedMemoryWrapper {
    shmem_id: None,
    shmem_size: None,
    shmem_type: None,
};

/// Used for in process fuzzing (InProccessExecutor)
/// This could be later wrapped in a shared memory struct implementing ShMem
pub static mut LOCAL_HASH: u64 = 0;

/// Utilities for setting up the signal handler and panic handler to collect the backtrace
pub mod stacktrace_hooks {
    use crate::bolts::os::unix_signals::Signal;
    use crate::observers::LOCAL_HASH;
    use ahash::AHasher;
    use backtrace::Backtrace;
    use libc::{
        c_int, c_void, sigaction, sigaddset, sigemptyset, siginfo_t, SA_NODEFER, SA_SIGINFO,
        SIGALRM,
    };
    use std::hash::Hasher;
    use std::{mem, panic, ptr};

    /// Collects the backtrace via Backtrace and Debug
    /// Debug used for dev purposes, will hash symbols later
    pub fn collect_backtrace() {
        let b = Backtrace::new();
        // will use symbols later
        let trace = format!("{:?}", b);
        eprintln!("{}", trace);
        let mut hasher = AHasher::new_with_keys(0, 0);
        hasher.write(trace.as_bytes());
        let hash = hasher.finish();
        println!("backtrace collected with hash={}", hash);
        unsafe {
            // If run with InProcessForkExecutor
            if crate::observers::BACKTRACE_SHMEM_DATA.is_ready() {
                crate::observers::BACKTRACE_SHMEM_DATA.store_stacktrace_hash(hash);
            } else {
                // if run with InProcessExecutor
                LOCAL_HASH = hash;
            }
        }
    }

    /// setup backtrace collection in a rust panic hook when the harness is rust code
    pub fn setup_rust_panic_hook() {
        panic::set_hook(Box::new(|_panic_info| {
            collect_backtrace();
        }));
    }

    /// setup backtrace collection in a signal handler when the harness is linked via FFI
    pub unsafe fn setup_signal_handler() {
        println!("setting up stacktrace signal handler");
        fn signal_handler(sig: c_int, _info: siginfo_t, _con: *mut c_void) {
            println!("Received signal sig={}", sig);
            collect_backtrace();
        }
        let signals = vec![
            Signal::SigAlarm,
            Signal::SigUser2,
            Signal::SigAbort,
            Signal::SigBus,
            Signal::SigPipe,
            Signal::SigFloatingPointException,
            Signal::SigIllegalInstruction,
            Signal::SigSegmentationFault,
            Signal::SigTrap,
        ];
        let mut sa: sigaction = mem::zeroed();
        sigemptyset(&mut sa.sa_mask as *mut libc::sigset_t);
        sigaddset(&mut sa.sa_mask as *mut libc::sigset_t, SIGALRM);
        sa.sa_sigaction = signal_handler as usize;
        sa.sa_flags = SA_NODEFER | SA_SIGINFO;
        for sig in signals {
            sigaction(sig as i32, &mut sa as *mut sigaction, ptr::null_mut());
        }
    }
}

/// An enum encoding the types of harnesses
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum HarnessType {
    /// Harness type when the harness is rust code
    RUST,
    /// Harness type when the harness is linked via FFI (e.g C code)
    FFI,
    /// Harness is a shell command
    COMMAND,
}

/// An observer looking at the stacktrace if a run crashes (For rust code)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StacktraceObserver {
    observer_name: String,
    harness_type: HarnessType,
    hash: Option<u64>,
}

impl StacktraceObserver {
    /// Creates a new [`StacktraceObserver`] with the given name.
    #[must_use]
    pub fn new(observer_name: String, harness_type: HarnessType) -> Self {
        match harness_type {
            HarnessType::RUST => stacktrace_hooks::setup_rust_panic_hook(),
            HarnessType::FFI => unsafe { stacktrace_hooks::setup_signal_handler() },
            HarnessType::COMMAND => (),
        }
        Self {
            observer_name,
            harness_type,
            hash: None,
        }
    }

    /// Gets the hash value of this observer.
    #[must_use]
    pub fn hash(&self) -> &Option<u64> {
        &self.hash
    }

    /// Updates the hash value of this observer.
    pub fn update_hash(&mut self, hash: u64) {
        self.hash = Some(hash);
    }

    /// Clears the current hash value
    pub fn clear_hash(&mut self) {
        self.hash = None;
    }

    /// Sets up the shared memory information in the static object BACKTRACE_SHMEM_DATA
    pub fn setup_shmem<SP: ShMemProvider>(&self, shmem_provider: SP) {
        println!("panic hook is being set");
        let shmem_map = shmem_provider.to_owned().new_map(5000).unwrap();
        let shmem_id = shmem_map.id();
        let shmem_size = shmem_map.len();
        let shmem_type = shmem_map.get_type();

        unsafe {
            BACKTRACE_SHMEM_DATA.update_shmem_info(shmem_id, shmem_size, shmem_type);
        }
    }
}

impl Default for StacktraceObserver {
    fn default() -> Self {
        Self::new("StacktraceObserver".to_string(), HarnessType::RUST)
    }
}

impl<I, S> Observer<I, S> for StacktraceObserver
where
    I: Debug,
{
    fn pre_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        Ok(())
    }

    fn post_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        unsafe {
            if BACKTRACE_SHMEM_DATA.is_ready() {
                let hash = BACKTRACE_SHMEM_DATA.get_stacktrace_hash();
                println!("hash from parent process is {}", hash);
                self.update_hash(hash);
            } else {
                // Makes sense only when run with an InProcessExecutor
                if LOCAL_HASH > 0 {
                    self.update_hash(LOCAL_HASH);
                    LOCAL_HASH = 0;
                }
            }
        }
        Ok(())
    }
}

impl Named for StacktraceObserver {
    fn name(&self) -> &str {
        &self.observer_name
    }
}
