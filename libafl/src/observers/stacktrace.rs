//! the ``StacktraceObserver`` looks up the stacktrace on the execution thread and computes a hash for it for dedupe

use crate::{
    bolts::{
        shmem::{ShMem, ShMemProvider, StdShMem, StdShMemProvider},
        tuples::Named,
    },
    observers::Observer,
    Error,
};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

use super::ObserverWithHashField;

/// A struct that stores needed information to persist the backtrace across prcesses/runs
#[derive(Debug)]
pub struct BacktraceSharedMemoryWrapper {
    /// shared memory
    shmem: Option<StdShMem>,
}

impl BacktraceSharedMemoryWrapper {
    fn set_shmem(&mut self, shmem: StdShMem) {
        self.shmem = Some(shmem);
    }

    fn is_ready(&self) -> bool {
        match &self.shmem {
            Some(_) => true,
            None => false,
        }
    }

    fn get_shmem(&self) -> &StdShMem {
        if self.is_ready() {
            self.shmem.as_ref().unwrap()
        } else {
            panic!("Cannot get generic shmem from uninitialized item");
        }
    }

    fn get_shmem_mut(&mut self) -> &mut StdShMem {
        if self.is_ready() {
            self.shmem.as_mut().unwrap()
        } else {
            panic!("Cannot get generic shmem from uninitialized item");
        }
    }

    fn store_stacktrace_hash(&mut self, hash: u64) {
        let shmem = self.get_shmem_mut();
        let map = shmem.map_mut();
        let hash_bytes = hash.to_be_bytes();
        for i in 0..hash_bytes.len() {
            map[i] = hash_bytes[i]
        }
    }

    fn get_stacktrace_hash(&self) -> u64 {
        let shmem = self.get_shmem();
        let map = shmem.map();
        let mut bytes: [u8; 8] = [0; 8];
        for i in 0..8 {
            bytes[i] = map[i];
        }
        u64::from_be_bytes(bytes)
    }
}

// Used for fuzzers not running in the same process
/// Static variable storing shared memory information
pub static mut BACKTRACE_SHMEM_DATA: BacktraceSharedMemoryWrapper =
    BacktraceSharedMemoryWrapper { shmem: None };

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

/// An observer looking at the backtrace of rust code harness
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BacktraceObserver {
    observer_name: String,
    harness_type: HarnessType,
    hash: Option<u64>,
}

impl BacktraceObserver {
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

    /// Sets up the shared memory information in the static object BACKTRACE_SHMEM_DATA
    pub fn setup_shmem(&self) {
        let shmem_provider = StdShMemProvider::new();
        println!("panic hook is being set");
        let shmem = shmem_provider.unwrap().new_map(5000).unwrap();
        unsafe {
            BACKTRACE_SHMEM_DATA.set_shmem(shmem);
        }
    }
}

impl ObserverWithHashField for BacktraceObserver {
    /// Gets the hash value of this observer.
    #[must_use]
    fn hash(&self) -> &Option<u64> {
        &self.hash
    }

    /// Updates the hash value of this observer.
    fn update_hash(&mut self, hash: u64) {
        self.hash = Some(hash);
    }

    /// Clears the current hash value
    fn clear_hash(&mut self) {
        self.hash = None;
    }
}

impl Default for BacktraceObserver {
    fn default() -> Self {
        Self::new("StacktraceObserver".to_string(), HarnessType::RUST)
    }
}

impl<I, S> Observer<I, S> for BacktraceObserver
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

impl Named for BacktraceObserver {
    fn name(&self) -> &str {
        &self.observer_name
    }
}
