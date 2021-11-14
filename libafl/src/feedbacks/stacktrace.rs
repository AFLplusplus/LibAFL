//! The StacktraceFeedbacks uses the backtrace hash and a hashset to only keep novel cases

use hashbrown::HashSet;
use serde::{Deserialize, Serialize};

use crate::{
    bolts::tuples::Named,
    events::EventFirer,
    executors::ExitKind,
    feedbacks::Feedback,
    inputs::Input,
    observers::{ObserversTuple, StacktraceObserver},
    state::HasClientPerfMonitor,
    Error,
};

/// A [`StacktraceFeedback`] reduces the timeout value of a run.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StacktraceFeedback {
    hashset: HashSet<u64>,
}

impl<I, S> Feedback<I, S> for StacktraceFeedback
where
    I: Input,
    S: HasClientPerfMonitor,
{
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &I,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<I, S>,
        OT: ObserversTuple<I, S>,
    {
        let observer = observers
            .match_name::<StacktraceObserver>("StacktraceObserver")
            .expect("A StacktraceFeedback needs a StacktraceObserver");

        match observer.stacktrace_hash() {
            Some(hash) => Ok(self.hashset.contains(hash)),
            None => Ok(false),
        }
    }
}

impl Named for StacktraceFeedback {
    #[inline]
    fn name(&self) -> &str {
        "StacktraceFeedback"
    }
}

impl StacktraceFeedback {
    /// Returns a new [`StacktraceFeedback`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            hashset: HashSet::new(),
        }
    }
}

impl Default for StacktraceFeedback {
    fn default() -> Self {
        Self::new()
    }
}
