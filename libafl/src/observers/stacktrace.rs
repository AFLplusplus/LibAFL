//! the ``StacktraceObserver`` looks up the stacktrace on the execution thread and computes a hash for it for dedupe

use ahash::AHasher;
use core::hash::Hasher;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

use crate::{bolts::tuples::Named, observers::Observer, Error};

/// A simple observer, just overlooking the runtime of the target.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StacktraceObserver {
    observer_name: String,
    hash: Option<u64>,
}

impl StacktraceObserver {
    /// Creates a new [`StacktraceObserver`] with the given name.
    #[must_use]
    pub fn new(observer_name: String) -> Self {
        Self {
            observer_name,
            hash: None,
        }
    }

    /// Gets the runtime for the last execution of this target.
    #[must_use]
    pub fn hash(&self) -> &Option<u64> {
        &self.hash
    }
}

impl Default for StacktraceObserver {
    fn default() -> Self {
        Self::new("StacktraceObserver".to_string())
    }
}

impl<I, S> Observer<I, S> for StacktraceObserver
where
    I: Debug,
{
    fn pre_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        Ok(())
    }

    fn post_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        let mut hasher = AHasher::new_with_keys(0, 0);
        backtrace::trace(|frame| {
            let sp = frame.sp() as u64;
            hasher.write_u64(sp);
            true
        });
        let st_hash = hasher.finish();
        println!("hash={}", &st_hash);
        self.hash = Some(st_hash);
        Ok(())
    }
}

impl Named for StacktraceObserver {
    fn name(&self) -> &str {
        &self.observer_name
    }
}
