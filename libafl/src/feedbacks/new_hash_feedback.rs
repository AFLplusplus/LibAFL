//! The ``NewHashFeedback`` uses the backtrace hash and a hashset to only keep novel cases

use std::{fmt::Debug, hash::Hash, marker::PhantomData};

use hashbrown::HashSet;
use num_traits::PrimInt;
use serde::{Deserialize, Serialize};

use crate::{
    bolts::tuples::Named,
    events::EventFirer,
    executors::ExitKind,
    feedbacks::{Feedback, FeedbackState},
    inputs::Input,
    observers::{ObserversTuple, StacktraceObserver},
    state::{HasClientPerfMonitor, HasFeedbackStates},
    Error,
};

use super::FeedbackStatesTuple;

pub trait HashSetState<T> {
    fn with_hash_set(name: &'static str, hash_set: HashSet<T>) -> Self;
    fn update_hash_set(&mut self, value: T) -> Result<bool, Error>;
}

/// The state of [`NewHashFeedback`]
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "T: serde::de::DeserializeOwned")]
pub struct NewHashFeedbackState<T>
where
    T: PrimInt + Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned + Hash,
{
    /// Contains information about untouched entries
    pub hash_set: HashSet<T>,
    /// Name identifier of this instance
    pub name: String,
}

impl<T> FeedbackState for NewHashFeedbackState<T>
where
    T: PrimInt + Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned + Hash,
{
    fn reset(&mut self) -> Result<(), Error> {
        self.hash_set.clear();
        Ok(())
    }
}

impl<T> Named for NewHashFeedbackState<T>
where
    T: PrimInt + Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned + Hash,
{
    #[inline]
    fn name(&self) -> &str {
        self.name.as_str()
    }
}

impl<T> NewHashFeedbackState<T>
where
    T: PrimInt + Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned + Hash,
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
    pub fn with_observer(stacktrace_observer: &StacktraceObserver) -> Self {
        Self {
            hash_set: HashSet::<T>::new(),
            name: stacktrace_observer.name().to_string(),
        }
    }
}
impl<T> HashSetState<T> for NewHashFeedbackState<T>
where
    T: PrimInt
        + Default
        + Copy
        + 'static
        + serde::Serialize
        + serde::de::DeserializeOwned
        + Hash
        + Debug,
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
pub struct NewHashFeedback<FT> {
    phantom_val: PhantomData<FT>,
    feedback_name: String,
    observer_name: String,
}

impl<FT, I, S> Feedback<I, S> for NewHashFeedback<FT>
where
    I: Input,
    FT: FeedbackStatesTuple,
    S: HasClientPerfMonitor + HasFeedbackStates<FT>,
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
            .match_name::<StacktraceObserver>(&self.observer_name)
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

impl<FT> Named for NewHashFeedback<FT> {
    #[inline]
    fn name(&self) -> &str {
        &self.feedback_name
    }
}

impl<FT> NewHashFeedback<FT> {
    /// Returns a new [`NewHashFeedback`].
    #[must_use]
    pub fn new(feedback_name: String, observer_name: String) -> Self {
        Self {
            phantom_val: PhantomData,
            feedback_name,
            observer_name,
        }
    }
}

impl<FT> Default for NewHashFeedback<FT> {
    fn default() -> Self {
        Self::new(
            "NewHashFeedback".to_string(),
            "StacktraceObserver".to_string(),
        )
    }
}
