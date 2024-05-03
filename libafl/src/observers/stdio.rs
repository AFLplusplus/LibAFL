//! The [`StdOutObserver`] and [`StdErrObserver`] observers look at the stdout of a program
//! The executor must explicitly support these observers.
//! For example, they are supported on the [`crate::executors::CommandExecutor`].

use alloc::borrow::Cow;
use std::vec::Vec;

use libafl_bolts::Named;
use serde::{Deserialize, Serialize};

use crate::{inputs::UsesInput, observers::Observer};

/// An observer that captures stdout of a target.
/// Only works for supported executors.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StdOutObserver {
    /// The name of the observer.
    pub name: Cow<'static, str>,
    /// The stdout of the target during its last execution.
    pub stdout: Option<Vec<u8>>,
}

/// An observer that captures stdout of a target.
impl StdOutObserver {
    /// Create a new [`StdOutObserver`] with the given name.
    #[must_use]
    pub fn new(name: &'static str) -> Self {
        Self {
            name: Cow::from(name),
            stdout: None,
        }
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
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

/// An observer that captures stderr of a target.
/// Only works for supported executors.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StdErrObserver {
    /// The name of the observer.
    pub name: Cow<'static, str>,
    /// The stderr of the target during its last execution.
    pub stderr: Option<Vec<u8>>,
}

/// An observer that captures stderr of a target.
impl StdErrObserver {
    /// Create a new [`StdErrObserver`] with the given name.
    #[must_use]
    pub fn new(name: &'static str) -> Self {
        Self {
            name: Cow::from(name),
            stderr: None,
        }
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
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

/// An observer that captures the exit code of a target.
/// Only works for supported executors.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExitCodeObserver {
    /// The name of the observer.
    pub name: Cow<'static, str>,
    /// The exit code of the target during its last execution.
    pub exit_code: Option<i32>,
}

/// An observer that captures exit signal of a target.
impl ExitCodeObserver {
    /// Create a new [`ExitCodeObserver`] with the given name.
    #[must_use]
    pub fn new(name: &'static str) -> Self {
        Self {
            name: Cow::from(name),
            exit_code: None,
        }
    }
}

impl<S> Observer<S> for ExitCodeObserver
where
    S: UsesInput,
{
    #[inline]
    fn observes_exit_code(&self) -> bool {
        true
    }

    /// React to new exit code
    fn observe_exit_code(&mut self, exit_code: i32) {
        self.exit_code = Some(exit_code);
    }
}

impl Named for ExitCodeObserver {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

/// An observer that captures the exit code of a target.
/// Only works for supported executors.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExitSignalObserver {
    /// The name of the observer.
    pub name: Cow<'static, str>,
    /// The exit signal of the target during its last execution.
    pub exit_signal: Option<i32>,
}

/// An observer that captures the exit signal of a target.
impl ExitSignalObserver {
    /// Create a new [`ExitSignalObserver`] with the given name.
    #[must_use]
    pub fn new(name: &'static str) -> Self {
        Self {
            name: Cow::from(name),
            exit_signal: None,
        }
    }
}

impl<S> Observer<S> for ExitSignalObserver
where
    S: UsesInput,
{
    #[inline]
    fn observes_exit_signal(&self) -> bool {
        true
    }

    /// React to new exit signal
    fn observe_exit_signal(&mut self, exit_signal: i32) {
        self.exit_signal = Some(exit_signal);
    }
}

impl Named for ExitSignalObserver {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}
