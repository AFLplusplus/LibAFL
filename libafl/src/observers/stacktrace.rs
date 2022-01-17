//! the ``StacktraceObserver`` looks up the stacktrace on the execution thread and computes a hash for it for dedupe

use crate::{
    bolts::{
        shmem::{ShMem, ShMemProvider, StdShMem, StdShMemProvider},
        tuples::Named,
    },
    executors::ExitKind,
    observers::Observer,
    Error,
};
use ahash::AHasher;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{fmt::Debug, hash::Hasher, io::Read, process::ChildStderr};

use super::ObserverWithHashField;

/// A struct that stores needed information to persist the backtrace across prcesses/runs
#[derive(Debug)]
pub enum BacktraceHashValueWrapper {
    /// shared memory instance
    Shmem(Box<StdShMem>),
    /// static variable
    StaticVariable(u64),
    /// Neither is set
    None,
}

impl BacktraceHashValueWrapper {
    fn store_stacktrace_hash(&mut self, hash: u64) {
        match self {
            Self::Shmem(shmem) => {
                let map = shmem.map_mut();
                let hash_bytes = hash.to_be_bytes();
                map.copy_from_slice(&hash_bytes);
            }
            Self::StaticVariable(_) => {
                *self = Self::StaticVariable(hash);
            }
            Self::None => panic!("BacktraceSharedMemoryWrapper is not set yet22!"),
        }
    }

    fn get_stacktrace_hash(&self) -> u64 {
        match &self {
            Self::Shmem(shmem) => {
                let map = shmem.map();
                u64::from_be_bytes(map[0..8].try_into().expect("Incorrectly sized"))
            }
            Self::StaticVariable(var) => *var,
            Self::None => panic!("BacktraceSharedMemoryWrapper is not set yet11!"),
        }
    }
}

// Used for fuzzers not running in the same process
/// Static variable storing shared memory information
pub static mut BACKTRACE_HASH_VALUE: BacktraceHashValueWrapper = BacktraceHashValueWrapper::None;

/// Utilities for setting up the signal handler and panic handler to collect the backtrace
pub mod stacktrace_hooks {
    use crate::bolts::os::unix_signals::Signal;
    use ahash::AHasher;
    use backtrace::Backtrace;
    use libc::{
        c_int, c_void, sigaction, sigaddset, sigemptyset, siginfo_t, SA_NODEFER, SA_SIGINFO,
        SIGALRM,
    };
    use std::hash::Hasher;
    use std::{mem, panic, ptr};

    /// Collects the backtrace via Backtrace and Debug
    /// (Debug is currently used for dev purposes, symbols hash will be used eventually)
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
            crate::observers::BACKTRACE_HASH_VALUE.store_stacktrace_hash(hash);
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
}

/// An observer looking at the backtrace after the harness crashes
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BacktraceObserver {
    observer_name: String,
    harness_type: HarnessType,
    hash: Option<u64>,
}

impl BacktraceObserver {
    /// Creates a new [`StacktraceObserver`] with the given name.
    #[must_use]
    pub fn new(observer_name: &str, harness_type: HarnessType) -> Self {
        match harness_type {
            HarnessType::RUST => stacktrace_hooks::setup_rust_panic_hook(),
            HarnessType::FFI => unsafe { stacktrace_hooks::setup_signal_handler() },
        }
        Self {
            observer_name: observer_name.to_string(),
            harness_type,
            hash: None,
        }
    }

    /// Setup the shared memory and store it in [`BACKTRACE_HASH_VALUE`]
    pub fn setup_shmem() {
        let shmem_provider = StdShMemProvider::new();
        println!("panic hook is being set");
        let shmem = shmem_provider.unwrap().new_map(8).unwrap();
        let boxed_shmem = Box::<StdShMem>::new(shmem);
        unsafe {
            BACKTRACE_HASH_VALUE = BacktraceHashValueWrapper::Shmem(boxed_shmem);
        }
    }

    /// Init the [`BACKTRACE_HASH_VALUE`] to `BacktraceHashValueWrapper::StaticVariable(0)`
    pub fn setup_static_variable() {
        unsafe {
            BACKTRACE_HASH_VALUE = BacktraceHashValueWrapper::StaticVariable(0);
        }
    }

    /// returns harness_type for this [`BacktraceObserver`] instance
    pub fn get_harness_type(&self) -> &HarnessType {
        &self.harness_type
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
        Self::new("BacktraceObserver", HarnessType::RUST)
    }
}

impl<I, S> Observer<I, S> for BacktraceObserver
where
    I: Debug,
{
    fn pre_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        Ok(())
    }

    fn post_exec(&mut self, _state: &mut S, _input: &I, exit_kind: &ExitKind) -> Result<(), Error> {
        unsafe {
            let hash = BACKTRACE_HASH_VALUE.get_stacktrace_hash();
            println!("hash from parent process is {}", hash);
            self.update_hash(hash);
        }
        Ok(())
    }
}

impl Named for BacktraceObserver {
    fn name(&self) -> &str {
        &self.observer_name
    }
}

/// returns the recommended ASAN runtime flags to capture the backtrace correctly
#[must_use]
pub fn get_asan_runtime_flags() -> String {
    let flags = vec![
        "exitcode=0",
        "abort_on_error=1",
        "handle_abort=1",
        "handle_segv=1",
        "handle_sigbus=1",
        "handle_sigill=1",
        "handle_sigfpe=1",
    ];

    flags.join(":")
}

/// An observer looking at the backtrace of target command using ASAN output
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CommandBacktraceObserver {
    observer_name: String,
    hash: Option<u64>,
}

impl CommandBacktraceObserver {
    /// Creates a new [`StacktraceObserver`] with the given name.
    #[must_use]
    pub fn new(observer_name: &str) -> Self {
        Self {
            observer_name: observer_name.to_string(),
            hash: None,
        }
    }

    /// parse ASAN error output emited by the target command and compute the hash
    pub fn parse_asan_output(&mut self, stderr: &mut ChildStderr) {
        let mut buf = String::new();
        let read = stderr
            .read_to_string(&mut buf)
            .expect("Failed to read the child process stderr");
        println!("Read {} bytes : {}", read, buf);
        let mut hasher = AHasher::new_with_keys(0, 0);
        let matcher = Regex::new("\\s*#[0-9]*\\s0x[0-9a-f]*\\sin\\s(.*)").unwrap();
        matcher.captures_iter(&buf).for_each(|m| {
            let g = m.get(1).unwrap();
            hasher.write(g.as_str().as_bytes());
        });
        let hash = hasher.finish();
        self.update_hash(hash);
    }
}

impl ObserverWithHashField for CommandBacktraceObserver {
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

impl Default for CommandBacktraceObserver {
    fn default() -> Self {
        Self::new("CommandBacktraceObserver")
    }
}

impl<I, S> Observer<I, S> for CommandBacktraceObserver
where
    I: Debug,
{
    fn pre_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        Ok(())
    }

    fn post_exec(
        &mut self,
        _state: &mut S,
        _input: &I,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        Ok(())
    }
}

impl Named for CommandBacktraceObserver {
    fn name(&self) -> &str {
        &self.observer_name
    }
}
