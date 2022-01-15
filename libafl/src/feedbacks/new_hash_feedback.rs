//! The ``NewHashFeedback`` uses the backtrace hash and a hashset to only keep novel cases

use std::{fmt::Debug, hash::Hash};

use hashbrown::HashSet;
use num_traits::PrimInt;
use serde::{Deserialize, Serialize};

use crate::{
    bolts::tuples::{MatchName, Named},
    events::EventFirer,
    executors::ExitKind,
    feedbacks::{Feedback, FeedbackState},
    inputs::Input,
    observers::{BacktraceObserver, ObserverWithHashField, ObserversTuple},
    state::{HasClientPerfMonitor, HasFeedbackStates},
    Error,
};

/// A state that implements this trait has a hash set
pub trait HashSetState<T> {
    /// creates a new instance with a specific hashset
    fn with_hash_set(name: &'static str, hash_set: HashSet<T>) -> Self;
    /// updates the hash_set with the given value
    fn update_hash_set(&mut self, value: T) -> Result<bool, Error>;
}

/// The state of [`NewHashFeedback`]
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "T: serde::de::DeserializeOwned")]
pub struct NewHashFeedbackState<T>
where
    T: PrimInt + Default + Copy + 'static + Serialize + serde::de::DeserializeOwned + Hash + Debug,
{
    /// Contains information about untouched entries
    pub hash_set: HashSet<T>,
    /// Name identifier of this instance
    pub name: String,
}

impl<T> FeedbackState for NewHashFeedbackState<T>
where
    T: PrimInt + Default + Copy + 'static + Serialize + serde::de::DeserializeOwned + Hash + Debug,
{
    fn reset(&mut self) -> Result<(), Error> {
        self.hash_set.clear();
        Ok(())
    }
}

impl<T> Named for NewHashFeedbackState<T>
where
    T: PrimInt + Default + Copy + 'static + Serialize + serde::de::DeserializeOwned + Hash + Debug,
{
    #[inline]
    fn name(&self) -> &str {
        self.name.as_str()
    }
}

impl<T> NewHashFeedbackState<T>
where
    T: PrimInt + Default + Copy + 'static + Serialize + serde::de::DeserializeOwned + Hash + Debug,
{
    /// Create new `NewHashFeedbackState`
    #[must_use]
    pub fn new(name: &'static str) -> Self {
        Self {
            hash_set: HashSet::<T>::new(),
            name: name.to_string(),
        }
    }

    /// Create new `NewHashFeedbackState` for the observer type.
    pub fn with_observer(stacktrace_observer: &BacktraceObserver) -> Self {
        Self {
            hash_set: HashSet::<T>::new(),
            name: stacktrace_observer.name().to_string(),
        }
    }
}
impl<T> HashSetState<T> for NewHashFeedbackState<T>
where
    T: PrimInt + Default + Copy + 'static + Serialize + serde::de::DeserializeOwned + Hash + Debug,
{
    /// Create new `NewHashFeedbackState` using a name and a hash set.
    /// The map can be shared.
    #[must_use]
    fn with_hash_set(name: &'static str, hash_set: HashSet<T>) -> Self {
        Self {
            hash_set,
            name: name.to_string(),
        }
    }

    fn update_hash_set(&mut self, value: T) -> Result<bool, Error> {
        let r = self.hash_set.insert(value);
        println!("Got r={}, the hashset is {:?}", r, &self.hash_set);
        Ok(r)
    }
}

/// A [`NewHashFeedback`] maintains a hashset of already seen stacktraces and considers interesting unseen ones
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NewHashFeedback {
    feedback_name: String,
    observer_name: String,
}

impl<I, S> Feedback<I, S> for NewHashFeedback
where
    I: Input,
    S: HasClientPerfMonitor + HasFeedbackStates,
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
        EM: EventFirer<I>,
        OT: ObserversTuple<I, S>,
    {
        let observer = observers
            .match_name::<BacktraceObserver>(&self.observer_name)
            .expect("A NewHashFeedback needs a StacktraceObserver");

        let stacktrace_state = _state
            .feedback_states_mut()
            .match_name_mut::<NewHashFeedbackState<u64>>(&self.observer_name.to_string())
            .unwrap();

        match observer.hash() {
            Some(hash) => {
                let res = stacktrace_state
                    .update_hash_set(*hash)
                    .expect("Failed to update the hash state");
                Ok(res)
            }
            None => {
                // We get here if the hash was not updated, ie no crash happened
                Ok(false)
            }
        }
    }
}

impl Named for NewHashFeedback {
    #[inline]
    fn name(&self) -> &str {
        &self.feedback_name
    }
}

impl NewHashFeedback {
    /// Returns a new [`NewHashFeedback`].
    #[must_use]
    pub fn new(feedback_name: String, observer_name: String) -> Self {
        Self {
            feedback_name,
            observer_name,
        }
    }
}

impl Default for NewHashFeedback {
    fn default() -> Self {
        Self::new(
            "NewHashFeedback".to_string(),
            "StacktraceObserver".to_string(),
        )
    }
}
