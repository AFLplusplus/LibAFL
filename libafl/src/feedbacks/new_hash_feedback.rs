//! The ``NewHashFeedback`` uses the backtrace hash and a hashset to only keep novel cases

use alloc::{borrow::Cow, string::ToString};
use std::{fmt::Debug, marker::PhantomData};

use hashbrown::HashSet;
use libafl_bolts::{
    tuples::{Handle, Handled, MatchNameRef},
    Named,
};
use serde::{Deserialize, Serialize};

#[cfg(feature = "track_hit_feedbacks")]
use crate::feedbacks::premature_last_result_err;
use crate::{
    events::EventFirer,
    executors::ExitKind,
    feedbacks::{Feedback, HasObserverHandle},
    inputs::UsesInput,
    observers::{ObserverWithHashField, ObserversTuple},
    state::State,
    Error, HasNamedMetadata,
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
    name: Cow<'static, str>,
    o_ref: Handle<O>,
    /// Initial capacity of hash set
    capacity: usize,
    #[cfg(feature = "track_hit_feedbacks")]
    // The previous run's result of `Self::is_interesting`
    last_result: Option<bool>,
    phantom: PhantomData<S>,
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
            .get(&self.o_ref)
            .expect("A NewHashFeedback needs a BacktraceObserver");

        let backtrace_state = state
            .named_metadata_map_mut()
            .get_mut::<NewHashFeedbackMetadata>(&self.name)
            .unwrap();

        let res = match observer.hash() {
            Some(hash) => backtrace_state.update_hash_set(hash)?,
            None => {
                // We get here if the hash was not updated, i.e the first run or if no crash happens
                false
            }
        };
        #[cfg(feature = "track_hit_feedbacks")]
        {
            self.last_result = Some(res);
        }
        Ok(res)
    }
    #[cfg(feature = "track_hit_feedbacks")]
    fn last_result(&self) -> Result<bool, Error> {
        self.last_result.ok_or(premature_last_result_err())
    }
}

impl<O, S> Named for NewHashFeedback<O, S> {
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<O, S> HasObserverHandle for NewHashFeedback<O, S> {
    type Observer = O;

    #[inline]
    fn observer_handle(&self) -> &Handle<O> {
        &self.o_ref
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
    #[must_use]
    pub fn new(observer: &O) -> Self {
        Self::with_capacity(observer, DEFAULT_CAPACITY)
    }

    /// Returns a new [`NewHashFeedback`] that will create a hash set with the
    /// given initial capacity.
    #[must_use]
    pub fn with_capacity(observer: &O, capacity: usize) -> Self {
        Self {
            name: Cow::from(NEWHASHFEEDBACK_PREFIX.to_string() + observer.name()),
            o_ref: observer.handle(),
            capacity,
            #[cfg(feature = "track_hit_feedbacks")]
            last_result: None,
            phantom: PhantomData,
        }
    }
}
