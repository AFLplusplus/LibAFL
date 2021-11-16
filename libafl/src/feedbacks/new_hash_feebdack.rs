//! The NewHashFeebdacks uses the backtrace hash and a hashset to only keep novel cases

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

/// A [`NewHashFeebdack`] maintains a hashset of already seen stacktraces and considers interesting unseen ones
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NewHashFeebdack {
    observer_name: String,
    hashset: HashSet<u64>,
}

impl<I, S> Feedback<I, S> for NewHashFeebdack
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
            .match_name::<StacktraceObserver>(&self.observer_name)
            .expect("A NewHashFeebdack needs a StacktraceObserver");

        match observer.hash() {
            Some(hash) => {
                if self.hashset.contains(hash) {
                    Ok(false)
                } else {
                    self.hashset.insert(*hash);
                    Ok(true)
                }
            }
            // Something's wrong if we get here
            None => Ok(false),
        }
    }
}

impl Named for NewHashFeebdack {
    #[inline]
    fn name(&self) -> &str {
        "NewHashFeebdack"
    }
}

impl NewHashFeebdack {
    /// Returns a new [`NewHashFeebdack`].
    #[must_use]
    pub fn new(observer_name: String) -> Self {
        Self {
            observer_name,
            hashset: HashSet::new(),
        }
    }
}

impl Default for NewHashFeebdack {
    fn default() -> Self {
        Self::new("StacktraceObserver".to_string())
    }
}
