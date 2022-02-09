//! The [`StdOutObserver`] and [`StdErrObserver`] observers look at the stdout of a program
//! The executor must explicitely support these observers.
//! For example, they are supported on the [`crate::executors::CommandExecutor`].

use crate::{bolts::tuples::Named, observers::Observer};

/// An observer that captures stdout of a target.
/// Only works for supported executors.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StdOutObserver {
    /// The name of the observer.
    pub name: String,
    /// The stdout of the target during its last execution.
    pub stdout: Option<String>,
}

/// An observer that captures stdout of a target.
impl StdOutObserver {
    /// Create a new [`StdOutObserver`] with the given name.
    #[must_use]
    pub fn new(name: String) -> Self {
        Self { name, stdout: None }
    }
}

impl<I, S> Observer<I, S> for StdOutObserver {}

impl Named for StdOutObserver {
    fn name(&self) -> &str {
        &self.name
    }
}

/// An observer that captures stderr of a target.
/// Only works for supported executors.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StdErrObserver {
    /// The name of the observer.
    pub name: String,
    /// The stderr of the target during its last execution.
    pub stderr: Option<String>,
}

/// An observer that captures stderr of a target.
impl StdErrObserver {
    /// Create a new [`StdErrObserver`] with the given name.
    #[must_use]
    pub fn new(name: String) -> Self {
        Self { name, stderr: None }
    }
}

impl<I, S> Observer<I, S> for StdErrObserver {}

impl Named for StdErrObserver {
    fn name(&self) -> &str {
        &self.name
    }
}
