//! The ``NewHashFeedback`` uses the backtrace hash and a hashset to only keep novel cases

use alloc::string::{String, ToString};
use std::{fmt::Debug, marker::PhantomData};

use hashbrown::HashSet;
use libafl_bolts::Named;
use serde::{Deserialize, Serialize};

use crate::{
    events::EventFirer,
    executors::ExitKind,
    feedbacks::{Feedback, HasObserverName},
    inputs::UsesInput,
    observers::{ObserverWithHashField, ObserversTuple},
    state::{HasNamedMetadata, State},
    Error,
};

/// The prefix of the metadata names
pub const NEWHASHFEEDBACK_PREFIX: &str = "newhashfeedback_metadata_";

/// A state that implements this trait has a hash set
pub trait HashSetState<T> {
    /// creates a new instance with a specific hashset
    fn with_hash_set(hash_set: HashSet<T>) -> Self;
    /// updates the `hash_set` with the given value
    fn update_hash_set(&mut self, value: T) -> Result<bool, Error>;
}

/// The state of [`NewHashFeedback`]
#[derive(Default, Serialize, Deserialize, Clone, Debug)]
#[allow(clippy::unsafe_derive_deserialize)]
pub struct NewHashFeedbackMetadata {
    /// Contains information about untouched entries
    pub hash_set: HashSet<u64>,
}

#[rustfmt::skip]
libafl_bolts::impl_serdeany!(NewHashFeedbackMetadata);

impl NewHashFeedbackMetadata {
    /// Create a new [`NewHashFeedbackMetadata`]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new [`NewHashFeedbackMetadata`] with the given initial capacity
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            hash_set: HashSet::with_capacity(capacity),
        }
    }

    /// Reset the internal state
    pub fn reset(&mut self) -> Result<(), Error> {
        self.hash_set.clear();
        Ok(())
    }
}

impl HashSetState<u64> for NewHashFeedbackMetadata {
    /// Create new [`NewHashFeedbackMetadata`] using a name and a hash set.
    #[must_use]
    fn with_hash_set(hash_set: HashSet<u64>) -> Self {
        Self { hash_set }
    }

    fn update_hash_set(&mut self, value: u64) -> Result<bool, Error> {
        let r = self.hash_set.insert(value);
        // log::trace!("Got r={}, the hashset is {:?}", r, &self.hash_set);
        Ok(r)
    }
}

/// A [`NewHashFeedback`] maintains a hashset of already seen stacktraces and considers interesting unseen ones
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NewHashFeedback<O, S> {
    name: String,
    observer_name: String,
    /// Initial capacity of hash set
    capacity: usize,
    o_type: PhantomData<(O, S)>,
}

impl<O, S> Feedback<S> for NewHashFeedback<O, S>
where
    O: ObserverWithHashField + Named,
    S: State + HasNamedMetadata,
{
    fn init_state(&mut self, state: &mut S) -> Result<(), Error> {
        state.add_named_metadata(
            &self.name,
            NewHashFeedbackMetadata::with_capacity(self.capacity),
        );
        Ok(())
    }

    #[allow(clippy::wrong_self_convention)]
    fn is_interesting<EM, OT>(
        &mut self,
        state: &mut S,
        _manager: &mut EM,
        _input: &<S as UsesInput>::Input,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        let observer = observers
            .match_name::<O>(&self.observer_name)
            .expect("A NewHashFeedback needs a BacktraceObserver");

        let backtrace_state = state
            .named_metadata_map_mut()
            .get_mut::<NewHashFeedbackMetadata>(&self.name)
            .unwrap();

        match observer.hash() {
            Some(hash) => {
                let res = backtrace_state
                    .update_hash_set(hash)
                    .expect("Failed to update the hash state");
                Ok(res)
            }
            None => {
                // We get here if the hash was not updated, i.e the first run or if no crash happens
                Ok(false)
            }
        }
    }
}

impl<O, S> Named for NewHashFeedback<O, S> {
    #[inline]
    fn name(&self) -> &str {
        &self.name
    }
}

impl<O, S> HasObserverName for NewHashFeedback<O, S> {
    #[inline]
    fn observer_name(&self) -> &str {
        &self.observer_name
    }
}

/// Default capacity for the [`HashSet`] in [`NewHashFeedback`].
///
/// This is reasonably large on the assumption that you expect there to be many
/// runs of the target, producing many different feedbacks.
const DEFAULT_CAPACITY: usize = 4096;

impl<O, S> NewHashFeedback<O, S>
where
    O: ObserverWithHashField + Named,
{
    /// Returns a new [`NewHashFeedback`].
    /// Setting an observer name that doesn't exist would eventually trigger a panic.
    #[must_use]
    pub fn with_names(name: &str, observer_name: &str) -> Self {
        Self {
            name: name.to_string(),
            observer_name: observer_name.to_string(),
            capacity: DEFAULT_CAPACITY,
            o_type: PhantomData,
        }
    }

    /// Returns a new [`NewHashFeedback`].
    #[must_use]
    pub fn new(observer: &O) -> Self {
        Self::with_capacity(observer, DEFAULT_CAPACITY)
    }

    /// Returns a new [`NewHashFeedback`] that will create a hash set with the
    /// given initial capacity.
    #[must_use]
    pub fn with_capacity(observer: &O, capacity: usize) -> Self {
        Self {
            name: NEWHASHFEEDBACK_PREFIX.to_string() + observer.name(),
            observer_name: observer.name().to_string(),
            capacity,
            o_type: PhantomData,
        }
    }
}
