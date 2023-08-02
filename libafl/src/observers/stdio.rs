//! The [`StdOutObserver`] and [`StdErrObserver`] observers look at the stdout of a program
//! The executor must explicitly support these observers.
//! For example, they are supported on the [`crate::executors::CommandExecutor`].

use alloc::string::String;
use std::vec::Vec;

use libafl_bolts::Named;
use serde::{Deserialize, Serialize};

use crate::{inputs::UsesInput, observers::Observer};

/// An observer that captures stdout of a target.
/// Only works for supported executors.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StdOutObserver {
    /// The name of the observer.
    pub name: String,
    /// The stdout of the target during its last execution.
    pub stdout: Option<Vec<u8>>,
}

/// An observer that captures stdout of a target.
impl StdOutObserver {
    /// Create a new [`StdOutObserver`] with the given name.
    #[must_use]
    pub fn new(name: String) -> Self {
        Self { name, stdout: None }
    }
}

impl<S> Observer<S> for StdOutObserver
where
    S: UsesInput,
{
    #[inline]
    fn observes_stdout(&self) -> bool {
        true
    }

    /// React to new `stdout`
    fn observe_stdout(&mut self, stdout: &[u8]) {
        self.stdout = Some(stdout.into());
    }
}

impl Named for StdOutObserver {
    fn name(&self) -> &str {
        &self.name
    }
}

/// An observer that captures stderr of a target.
/// Only works for supported executors.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StdErrObserver {
    /// The name of the observer.
    pub name: String,
    /// The stderr of the target during its last execution.
    pub stderr: Option<Vec<u8>>,
}

/// An observer that captures stderr of a target.
impl StdErrObserver {
    /// Create a new [`StdErrObserver`] with the given name.
    #[must_use]
    pub fn new(name: String) -> Self {
        Self { name, stderr: None }
    }
}

impl<S> Observer<S> for StdErrObserver
where
    S: UsesInput,
{
    #[inline]
    fn observes_stderr(&self) -> bool {
        true
    }

    /// React to new `stderr`
    fn observe_stderr(&mut self, stderr: &[u8]) {
        self.stderr = Some(stderr.into());
    }
}

impl Named for StdErrObserver {
    fn name(&self) -> &str {
        &self.name
    }
}
