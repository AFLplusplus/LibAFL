//! the ``StacktraceObserver`` looks up the stacktrace on the execution thread and computes a hash for it for dedupe

use crate::{
    bolts::{
        shmem::{ShMem, ShMemProvider, StdShMem, StdShMemProvider},
        tuples::Named,
    },
    executors::ExitKind,
    inputs::Input,
    observers::Observer,
    Error,
};
use ahash::AHasher;
use backtrace::Backtrace;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{
    collections::hash_map::DefaultHasher, fmt::Debug, hash::Hasher, io::Read, process::ChildStderr,
};

use super::ObserverWithHashField;

/// A struct that stores needed information to persist the backtrace across prcesses/runs
#[derive(Debug)]
pub enum BacktraceHashValueWrapper {
    /// shared memory instance
    Shmem(Box<StdShMem>),
    /// static variable
    StaticVariable((u64, u64)),
    /// Neither is set
    None,
}

impl BacktraceHashValueWrapper {
    /// store a hash value in the [`BacktraceHashValueWrapper`]
    fn store_stacktrace_hash(&mut self, bt_hash: u64, input_hash: u64) {
        match self {
            Self::Shmem(shmem) => {
                let map = shmem.map_mut();
                let bt_hash_bytes = bt_hash.to_be_bytes();
                let input_hash_bytes = input_hash.to_be_bytes();
                map.copy_from_slice(&[bt_hash_bytes, input_hash_bytes].concat());
            }
            Self::StaticVariable(_) => {
                *self = Self::StaticVariable((bt_hash, input_hash));
            }
            Self::None => panic!("BacktraceSharedMemoryWrapper is not set yet22!"),
        }
    }

    /// get the hash value from the [`BacktraceHashValueWrapper`]
    fn get_stacktrace_hash(&self) -> (u64, u64) {
        match &self {
            Self::Shmem(shmem) => {
                let map = shmem.map();
                (
                    u64::from_be_bytes(map[0..8].try_into().expect("Incorrectly sized")),
                    u64::from_be_bytes(map[8..16].try_into().expect("Incorrectly sized")),
                )
            }
            Self::StaticVariable(hash_tuple) => *hash_tuple,
            Self::None => {
                panic!("BacktraceSharedMemoryWrapper is not set yet11!")
            }
        }
    }
}

// Used for fuzzers not running in the same process
/// Static variable storing shared memory information
pub static mut BACKTRACE_HASH_VALUE: BacktraceHashValueWrapper = BacktraceHashValueWrapper::None;

/// Collects the backtrace via [`Backtrace`] and [`Debug`]
/// ([`Debug`] is currently used for dev purposes, symbols hash will be used eventually)
#[must_use]
pub fn collect_backtrace() -> u64 {
    let b = Backtrace::new();
    // will use symbols later
    let trace = format!("{:?}", b);
    eprintln!("{}", trace);
    let mut hasher = AHasher::new_with_keys(0, 0);
    hasher.write(trace.as_bytes());
    let hash = hasher.finish();
    println!(
        "backtrace collected with hash={} at pid={}",
        hash,
        std::process::id()
    );
    hash
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
    /// Creates a new [`BacktraceObserver`] with the given name.
    #[must_use]
    pub fn new(observer_name: &str, harness_type: HarnessType) -> Self {
        Self {
            observer_name: observer_name.to_string(),
            harness_type,
            hash: None,
        }
    }

    /// Setup the shared memory and store it in [`BACKTRACE_HASH_VALUE`]
    pub fn setup_shmem() {
        let shmem_provider = StdShMemProvider::new();
        let mut shmem = shmem_provider.unwrap().new_map(16).unwrap();
        shmem.map_mut().fill(0);
        let boxed_shmem = Box::<StdShMem>::new(shmem);
        unsafe {
            BACKTRACE_HASH_VALUE = BacktraceHashValueWrapper::Shmem(boxed_shmem);
        }
    }

    /// Init the [`BACKTRACE_HASH_VALUE`] to [`BacktraceHashValueWrapper::StaticVariable`](0)
    pub fn setup_static_variable() {
        unsafe {
            BACKTRACE_HASH_VALUE = BacktraceHashValueWrapper::StaticVariable((0, 0));
        }
    }

    /// returns harness_type for this [`BacktraceObserver`] instance
    pub fn harness_type(&self) -> &HarnessType {
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
    I: Input + Debug,
{
    fn pre_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        Ok(())
    }

    fn post_exec(&mut self, _state: &mut S, input: &I, exit_kind: &ExitKind) -> Result<(), Error> {
        let mut hasher = DefaultHasher::new();
        input.hash(&mut hasher);
        let input_hash = hasher.finish();
        let (bt_hash, current_input_hash) = unsafe { BACKTRACE_HASH_VALUE.get_stacktrace_hash() };
        if current_input_hash != input_hash {
            match exit_kind {
                ExitKind::Crash => {
                    println!("Got crash, will collect");
                    let bt_hash = collect_backtrace();
                    unsafe { BACKTRACE_HASH_VALUE.store_stacktrace_hash(bt_hash, input_hash) };
                    self.update_hash(bt_hash);
                }
                _ => (),
            }
        } else {
            println!("double call");
            match exit_kind {
                ExitKind::Crash => {
                    println!("hash from parent process is {}", bt_hash);
                    self.update_hash(bt_hash);
                }
                _ => (),
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
    /// Creates a new [`BacktraceObserver`] with the given name.
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
