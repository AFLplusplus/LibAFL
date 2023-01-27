//! the ``StacktraceObserver`` looks up the stacktrace on the execution thread and computes a hash for it for dedupe

use alloc::string::{String, ToString};
use std::{
    fmt::Debug,
    fs::{self, File},
    io::Read,
    path::Path,
    process::ChildStderr,
};

use backtrace::Backtrace;
use regex::Regex;
use serde::{Deserialize, Serialize};

use super::ObserverWithHashField;
use crate::{
    bolts::{ownedref::OwnedRefMut, tuples::Named},
    executors::ExitKind,
    inputs::UsesInput,
    observers::Observer,
    Error,
};

/// Collects the backtrace via [`Backtrace`] and [`Debug`]
/// ([`Debug`] is currently used for dev purposes, symbols hash will be used eventually)
#[must_use]
pub fn collect_backtrace() -> u64 {
    let b = Backtrace::new_unresolved();
    if b.frames().is_empty() {
        return 0;
    }
    let mut hash = 0;
    for frame in &b.frames()[1..] {
        hash ^= frame.ip() as u64;
    }
    // will use symbols later
    // let trace = format!("{:?}", b);
    // eprintln!("{}", trace);
    // println!(
    //     "backtrace collected with hash={} at pid={}",
    //     hash,
    //     std::process::id()
    // );
    hash
}

/// An enum encoding the types of harnesses
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum HarnessType {
    /// Harness type when the target is in the same process
    InProcess,
    /// Harness type when the target is a child process
    Child,
}

/// An observer looking at the backtrace after the harness crashes
#[allow(clippy::unsafe_derive_deserialize)]
#[derive(Serialize, Deserialize, Debug)]
pub struct BacktraceObserver<'a> {
    observer_name: String,
    hash: OwnedRefMut<'a, Option<u64>>,
    harness_type: HarnessType,
}

impl<'a> BacktraceObserver<'a> {
    /// Creates a new [`BacktraceObserver`] with the given name.
    #[must_use]
    pub fn new(
        observer_name: &str,
        backtrace_hash: &'a mut Option<u64>,
        harness_type: HarnessType,
    ) -> Self {
        Self {
            observer_name: observer_name.to_string(),
            hash: OwnedRefMut::Ref(backtrace_hash),
            harness_type,
        }
    }

    /// Updates the hash value of this observer.
    fn update_hash(&mut self, hash: u64) {
        *self.hash.as_mut() = Some(hash);
    }

    /// Clears the current hash value (sets it to `None`)
    fn clear_hash(&mut self) {
        *self.hash.as_mut() = None;
    }
}

impl<'a> ObserverWithHashField for BacktraceObserver<'a> {
    /// Gets the hash value of this observer.
    #[must_use]
    fn hash(&self) -> Option<u64> {
        *self.hash.as_ref()
    }
}

impl<'a, S> Observer<S> for BacktraceObserver<'a>
where
    S: UsesInput,
{
    fn post_exec(
        &mut self,
        _state: &mut S,
        _input: &S::Input,
        exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        if self.harness_type == HarnessType::InProcess {
            if exit_kind == &ExitKind::Crash {
                self.update_hash(collect_backtrace());
            } else {
                self.clear_hash();
            }
        }
        Ok(())
    }

    fn post_exec_child(
        &mut self,
        _state: &mut S,
        _input: &S::Input,
        exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        if self.harness_type == HarnessType::Child {
            if exit_kind == &ExitKind::Crash {
                self.update_hash(collect_backtrace());
            } else {
                self.clear_hash();
            }
        }
        Ok(())
    }
}

impl<'a> Named for BacktraceObserver<'a> {
    fn name(&self) -> &str {
        &self.observer_name
    }
}

/// static variable of ASAN log path
pub static ASAN_LOG_PATH: &str = "./asanlog"; // TODO make it unique

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
pub struct AsanBacktraceObserver {
    observer_name: String,
    hash: Option<u64>,
}

impl AsanBacktraceObserver {
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
        let log_path = format!("{ASAN_LOG_PATH}.{pid}");
        let mut asan_output = File::open(Path::new(&log_path))?;

        let mut buf = String::new();
        asan_output.read_to_string(&mut buf)?;
        fs::remove_file(&log_path)?;

        self.parse_asan_output(&buf);
        Ok(())
    }

    /// parse ASAN error output emited by the target command and compute the hash
    pub fn parse_asan_output(&mut self, output: &str) {
        let mut hash = 0;
        let matcher = Regex::new("\\s*#[0-9]*\\s0x([0-9a-f]*)\\s.*").unwrap();
        matcher.captures_iter(output).for_each(|m| {
            let g = m.get(1).unwrap();
            hash ^= u64::from_str_radix(g.as_str(), 16).unwrap();
        });
        self.update_hash(hash);
    }

    /// Updates the hash value of this observer.
    fn update_hash(&mut self, hash: u64) {
        self.hash = Some(hash);
    }
}

impl ObserverWithHashField for AsanBacktraceObserver {
    /// Gets the hash value of this observer.
    #[must_use]
    fn hash(&self) -> Option<u64> {
        self.hash
    }
}

impl Default for AsanBacktraceObserver {
    fn default() -> Self {
        Self::new("AsanBacktraceObserver")
    }
}

impl<S> Observer<S> for AsanBacktraceObserver
where
    S: UsesInput,
{
    fn pre_exec(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        Ok(())
    }

    fn post_exec(
        &mut self,
        _state: &mut S,
        _input: &S::Input,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        Ok(())
    }

    /// Do nothing on new `stderr`
    #[inline]
    fn observes_stderr(&self) -> bool {
        true
    }

    /// Do nothing on new `stderr`
    fn observe_stderr(&mut self, stderr: &[u8]) {
        self.parse_asan_output(&String::from_utf8_lossy(stderr));
    }
}

impl Named for AsanBacktraceObserver {
    fn name(&self) -> &str {
        &self.observer_name
    }
}
