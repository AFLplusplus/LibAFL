//! The ``CasrStacktraceObserver`` looks up the stacktrace on the execution thread and computes a hash using `libCASR` for it for dedupe

use alloc::string::{String, ToString};
use std::{
    collections::hash_map::DefaultHasher,
    fmt::Debug,
    fs::{self, File},
    hash::{Hash, Hasher},
    io::Read,
    path::Path,
    process::ChildStderr,
    vec::Vec,
};

use libcasr::{asan::AsanStacktrace, stacktrace::ParseStacktrace};
use serde::{Deserialize, Serialize};

use super::{ObserverWithHashField, ASAN_LOG_PATH};
use crate::{
    bolts::tuples::Named, executors::ExitKind, inputs::UsesInput, observers::Observer, Error,
};

/// An observer looking at the backtrace of target command using ASAN output processed by libcasr
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CasrAsanBacktraceObserver {
    observer_name: String,
    hash: Option<u64>,
}

impl CasrAsanBacktraceObserver {
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
        let mut buf = Vec::new();
        stderr.read_to_end(&mut buf)?;
        self.parse_asan_output(&String::from_utf8_lossy(&buf));
        Ok(())
    }

    /// read ASAN output from the log file and parse it.
    pub fn parse_asan_output_from_asan_log_file(&mut self, pid: i32) -> Result<(), Error> {
        let log_path = format!("{ASAN_LOG_PATH}.{pid}");
        let mut asan_output = File::open(Path::new(&log_path))?;

        let mut buf = Vec::new();
        asan_output.read_to_end(&mut buf)?;
        fs::remove_file(&log_path)?;

        self.parse_asan_output(&String::from_utf8_lossy(&buf));
        Ok(())
    }

    /// parse ASAN error output emited by the target command and compute the hash
    pub fn parse_asan_output(&mut self, output: &str) {
        let mut hash = 0;
        if let Ok(st_vec) = AsanStacktrace::extract_stacktrace(output) {
            if let Ok(stacktrace) = AsanStacktrace::parse_stacktrace(&st_vec) {
                let mut s = DefaultHasher::new();
                stacktrace.hash(&mut s);
                hash = s.finish();
            }
        }
        self.update_hash(hash);
    }

    /// Updates the hash value of this observer.
    fn update_hash(&mut self, hash: u64) {
        self.hash = Some(hash);
    }
}

impl ObserverWithHashField for CasrAsanBacktraceObserver {
    /// Gets the hash value of this observer.
    #[must_use]
    fn hash(&self) -> Option<u64> {
        self.hash
    }
}

impl Default for CasrAsanBacktraceObserver {
    fn default() -> Self {
        Self::new("CasrAsanBacktraceObserver")
    }
}

impl<S> Observer<S> for CasrAsanBacktraceObserver
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

impl Named for CasrAsanBacktraceObserver {
    fn name(&self) -> &str {
        &self.observer_name
    }
}
