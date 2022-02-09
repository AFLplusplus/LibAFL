//! the ``StacktraceObserver`` looks up the stacktrace on the execution thread and computes a hash for it for dedupe

use crate::{
    bolts::{
        shmem::{ShMemProvider, StdShMemProvider},
        tuples::Named,
        AsMutSlice, AsSlice,
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
    collections::hash_map::DefaultHasher,
    fmt::Debug,
    fs::{self, File},
    hash::Hasher,
    io::Read,
    path::Path,
    process::ChildStderr,
};

use super::ObserverWithHashField;

type StdShMem = <StdShMemProvider as ShMemProvider>::ShMem;
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
                let map = shmem.as_mut_slice();
                let bt_hash_bytes = bt_hash.to_be_bytes();
                let input_hash_bytes = input_hash.to_be_bytes();
                map.copy_from_slice(&[bt_hash_bytes, input_hash_bytes].concat());
            }
            Self::StaticVariable(_) => {
                *self = Self::StaticVariable((bt_hash, input_hash));
            }
            Self::None => panic!("BacktraceSharedMemoryWrapper is not set yet!"),
        }
    }

    /// get the hash value from the [`BacktraceHashValueWrapper`]
    fn get_stacktrace_hash(&self) -> Result<(u64, u64), Error> {
        match &self {
            Self::Shmem(shmem) => {
                let map = shmem.as_slice();
                Ok((
                    u64::from_be_bytes(map[0..8].try_into()?),
                    u64::from_be_bytes(map[8..16].try_into()?),
                ))
            }
            Self::StaticVariable(hash_tuple) => Ok(*hash_tuple),
            Self::None => Err(Error::IllegalState(
                "BacktraceSharedMemoryWrapper is not set yet!".into(),
            )),
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
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum HarnessType {
    /// Harness type when the harness is rust code
    RUST,
    /// Harness type when the harness is linked via FFI (e.g C code)
    FFI,
}

/// An observer looking at the backtrace after the harness crashes
#[allow(clippy::unsafe_derive_deserialize)]
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
        let mut shmem = shmem_provider.unwrap().new_shmem(16).unwrap();
        shmem.as_mut_slice().fill(0);
        let boxed_shmem = Box::<StdShMem>::new(shmem);
        unsafe {
            BACKTRACE_HASH_VALUE = BacktraceHashValueWrapper::Shmem(boxed_shmem);
        }
    }

    /// Init the [`BACKTRACE_HASH_VALUE`] to [`BacktraceHashValueWrapper::StaticVariable`] with `(0.0)`
    pub fn setup_static_variable() {
        unsafe {
            BACKTRACE_HASH_VALUE = BacktraceHashValueWrapper::StaticVariable((0, 0));
        }
    }

    /// returns `harness_type` for this [`BacktraceObserver`] instance
    #[must_use]
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
    fn post_exec(&mut self, _state: &mut S, input: &I, exit_kind: &ExitKind) -> Result<(), Error> {
        // run if this call resulted after a crash
        if exit_kind == &ExitKind::Crash {
            // hash input
            let mut hasher = DefaultHasher::new();
            input.hash(&mut hasher);
            let input_hash = hasher.finish();
            // get last backtrace hash and associated input hash
            let (bt_hash, current_input_hash) =
                unsafe { BACKTRACE_HASH_VALUE.get_stacktrace_hash()? };
            // replace if this is a new input
            if current_input_hash != input_hash {
                let bt_hash = collect_backtrace();
                unsafe { BACKTRACE_HASH_VALUE.store_stacktrace_hash(bt_hash, input_hash) };
            }
            // update hash field in this observer
            self.update_hash(bt_hash);
        }
        Ok(())
    }

    fn post_exec_child(
        &mut self,
        state: &mut S,
        input: &I,
        exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        self.post_exec(state, input, exit_kind)
    }
}

impl Named for BacktraceObserver {
    fn name(&self) -> &str {
        &self.observer_name
    }
}

/// static variable of ASAN log path
pub static ASAN_LOG_PATH: &str = "./asanlog";

/// returns the recommended ASAN runtime flags to capture the backtrace correctly with `log_path` set
#[must_use]
pub fn get_asan_runtime_flags_with_log_path() -> String {
    let mut flags = get_asan_runtime_flags();
    flags.push_str(":log_path=");
    flags.push_str(ASAN_LOG_PATH);
    flags
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
pub struct ASANBacktraceObserver {
    observer_name: String,
    hash: Option<u64>,
}

impl ASANBacktraceObserver {
    /// Creates a new [`BacktraceObserver`] with the given name.
    #[must_use]
    pub fn new(observer_name: &str) -> Self {
        Self {
            observer_name: observer_name.to_string(),
            hash: None,
        }
    }

    /// read ASAN output from the child stderr and parse it.
    pub fn parse_asan_output_from_childstderr(
        &mut self,
        stderr: &mut ChildStderr,
    ) -> Result<(), Error> {
        let mut buf = String::new();
        stderr.read_to_string(&mut buf)?;
        self.parse_asan_output(&buf);
        Ok(())
    }

    /// read ASAN output from the log file and parse it.
    pub fn parse_asan_output_from_asan_log_file(&mut self, pid: i32) -> Result<(), Error> {
        let log_path = format!("{}.{}", ASAN_LOG_PATH, pid);
        let mut asan_output = File::open(Path::new(&log_path))?;

        let mut buf = String::new();
        asan_output.read_to_string(&mut buf)?;
        fs::remove_file(&log_path)?;

        self.parse_asan_output(&buf);
        Ok(())
    }

    /// parse ASAN error output emited by the target command and compute the hash
    pub fn parse_asan_output(&mut self, output: &str) {
        let mut hasher = AHasher::new_with_keys(0, 0);
        let matcher = Regex::new("\\s*#[0-9]*\\s0x[0-9a-f]*\\sin\\s(.*)").unwrap();
        matcher.captures_iter(output).for_each(|m| {
            let g = m.get(1).unwrap();
            hasher.write(g.as_str().as_bytes());
        });
        let hash = hasher.finish();
        self.update_hash(hash);
    }
}

impl ObserverWithHashField for ASANBacktraceObserver {
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

impl Default for ASANBacktraceObserver {
    fn default() -> Self {
        Self::new("ASANBacktraceObserver")
    }
}

impl<I, S> Observer<I, S> for ASANBacktraceObserver
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

impl Named for ASANBacktraceObserver {
    fn name(&self) -> &str {
        &self.observer_name
    }
}
