//! The [`StdOutObserver`] and [`StdErrObserver`] observers look at the stdout of a program
//! The executor must explicitly support these observers.
//! For example, they are supported on the [`crate::executors::CommandExecutor`].

use alloc::borrow::Cow;
use std::vec::Vec;

use libafl_bolts::Named;
use serde::{Deserialize, Serialize};

use crate::{inputs::UsesInput, observers::Observer, state::State, Error};

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

    /// React to new `stdout`
    pub fn observe_stdout(&mut self, stdout: &[u8]) {
        self.stdout = Some(stdout.into());
    }
}

impl Named for StdOutObserver {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<S> Observer<S> for StdOutObserver
where
    S: State,
{
    fn pre_exec_child(
        &mut self,
        _state: &mut S,
        _input: &<S as UsesInput>::Input,
    ) -> Result<(), Error> {
        self.stdout = None;
        Ok(())
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

    /// React to new `stderr`
    pub fn observe_stderr(&mut self, stderr: &[u8]) {
        self.stderr = Some(stderr.into());
    }
}

impl Named for StdErrObserver {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<S> Observer<S> for StdErrObserver
where
    S: State,
{
    fn pre_exec_child(
        &mut self,
        _state: &mut S,
        _input: &<S as UsesInput>::Input,
    ) -> Result<(), Error> {
        self.stderr = None;
        Ok(())
    }
}
