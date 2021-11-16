//! the Stacktrace Observer looks up the stacktrace on the execution thread and computes a hash for it for dedupe

use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
};

use backtrace::Backtrace;
use serde::{Deserialize, Serialize};

use crate::{bolts::tuples::Named, observers::Observer, Error};

/// A simple observer, just overlooking the runtime of the target.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StacktraceObserver {
    hash: Option<u64>,
}

impl StacktraceObserver {
    /// Creates a new [`StacktraceObserver`] with the given name.
    #[must_use]
    pub fn new() -> Self {
        Self { hash: None }
    }

    /// Gets the runtime for the last execution of this target.
    #[must_use]
    pub fn hash(&self) -> &Option<u64> {
        &self.hash
    }
}

impl<I, S> Observer<I, S> for StacktraceObserver {
    fn pre_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        Ok(())
    }

    fn post_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        let bt = Backtrace::new();
        let mut hasher = DefaultHasher::new();
        format!("<START> {:?}", bt).hash(&mut hasher);
        self.hash = Some(hasher.finish());
        Ok(())
    }
}

impl Named for StacktraceObserver {
    fn name(&self) -> &str {
        "StacktraceObserver"
    }
}
