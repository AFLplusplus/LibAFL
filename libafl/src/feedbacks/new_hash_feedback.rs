//! The ``NewHashFeedback`` uses the backtrace hash and a hashset to only keep novel cases

use std::{fmt::Debug, hash::Hash, marker::PhantomData};

use hashbrown::HashSet;
use num_traits::PrimInt;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{
    bolts::tuples::{MatchName, Named},
    events::EventFirer,
    executors::ExitKind,
    feedbacks::Feedback,
    inputs::Input,
    observers::{ObserverWithHashField, ObserversTuple},
    state::{HasClientPerfMonitor, HasNamedMetadata},
    Error,
};

/// The prefix of the metadata names
pub const NEWHASHFEEDBACK_PREFIX: &'static str = "newhashfeedback_metadata_";

/// A state that implements this trait has a hash set
pub trait HashSetState<T> {
    /// creates a new instance with a specific hashset
    fn with_hash_set(hash_set: HashSet<T>) -> Self;
    /// updates the `hash_set` with the given value
    fn update_hash_set(&mut self, value: T) -> Result<bool, Error>;
}

/// The state of [`NewHashFeedback`]
#[derive(Default, Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "T: DeserializeOwned")]
pub struct NewHashFeedbackMetadata<T>
where
    T: PrimInt + Default + Copy + 'static + Serialize + Hash + Debug,
{
    /// Contains information about untouched entries
    pub hash_set: HashSet<T>,
}

crate::impl_serdeany!(
    NewHashFeedbackMetadata<T: PrimInt + Default + Copy + 'static + Serialize + DeserializeOwned + Hash + Debug>
);

impl<T> NewHashFeedbackMetadata<T>
where
    T: PrimInt + Default + Copy + 'static + Serialize + DeserializeOwned + Hash + Debug,
{
    /// Create a new [`NewHashFeedbackMetadata`]
    #[must_use]
    pub fn new(name: &'static str) -> Self {
        Self::default()
    }

    /// Reset the internal state
    fn reset(&mut self) -> Result<(), Error> {
        self.hash_set.clear();
        Ok(())
    }
}

impl<T> HashSetState<T> for NewHashFeedbackMetadata<T>
where
    T: PrimInt + Default + Copy + 'static + Serialize + DeserializeOwned + Hash + Debug,
{
    /// Create new [`NewHashFeedbackMetadata`] using a name and a hash set.
    #[must_use]
    fn with_hash_set(hash_set: HashSet<T>) -> Self {
        Self { hash_set }
    }

    fn update_hash_set(&mut self, value: T) -> Result<bool, Error> {
        let r = self.hash_set.insert(value);
        // println!("Got r={}, the hashset is {:?}", r, &self.hash_set);
        Ok(r)
    }
}

/// A [`NewHashFeedback`] maintains a hashset of already seen stacktraces and considers interesting unseen ones
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NewHashFeedback<O> {
    name: String,
    observer_name: String,
    o_type: PhantomData<O>,
}

impl<I, S, O> Feedback<I, S> for NewHashFeedback<O>
where
    I: Input,
    S: HasClientPerfMonitor + HasNamedMetadata,
    O: ObserverWithHashField + Named + Debug,
{
    fn init_state(&mut self, state: &mut S) -> Result<(), Error> {
        state.add_named_metadata(NewHashFeedbackMetadata::<u64>::default(), &self.name)?;
        Ok(())
    }

    #[allow(clippy::wrong_self_convention)]
    fn is_interesting<EM, OT>(
        &mut self,
        state: &mut S,
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
            .match_name::<O>(&self.observer_name)
            .expect("A NewHashFeedback needs a BacktraceObserver");

        let backtrace_state = state
            .named_metadata_mut()
            .get_mut::<NewHashFeedbackMetadata<u64>>(&self.name)
            .unwrap();

        match observer.hash() {
            Some(hash) => {
                let res = backtrace_state
                    .update_hash_set(*hash)
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

impl<O> Named for NewHashFeedback<O> {
    #[inline]
    fn name(&self) -> &str {
        &self.name
    }
}

impl<O> NewHashFeedback<O>
where
    O: ObserverWithHashField + Named + Debug,
{
    /// Returns a new [`NewHashFeedback`].
    /// Setting an observer name that doesn't exist would eventually trigger a panic.
    #[must_use]
    pub fn with_names(name: &str, observer_name: &str) -> Self {
        Self {
            name: name.to_string(),
            observer_name: observer_name.to_string(),
            o_type: PhantomData,
        }
    }

    /// Returns a new [`NewHashFeedback`].
    #[must_use]
    pub fn new(observer: &O) -> Self {
        Self {
            name: NEWHASHFEEDBACK_PREFIX + observer.name().to_string(),
            observer_name: observer.name().to_string(),
            o_type: PhantomData,
        }
    }
}
