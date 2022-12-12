//! The queue corpus scheduler implements an AFL-like queue mechanism
//! The [`TuneableScheduler`] extends the queue scheduler with a method to
//! chose the next corpus entry manually

use alloc::borrow::ToOwned;
use core::marker::PhantomData;

use serde::{Deserialize, Serialize};

use crate::{
    corpus::Corpus,
    impl_serdeany,
    inputs::UsesInput,
    schedulers::Scheduler,
    state::{HasCorpus, HasMetadata, UsesState},
    Error,
};

#[derive(Default, Clone, Copy, Eq, PartialEq, Debug, Serialize, Deserialize)]
struct TuneableSchedulerMetadata {
    next: Option<usize>,
}

impl_serdeany!(TuneableSchedulerMetadata);

/// Walk the corpus in a queue-like fashion
/// With the specific `set_next` method, we can chose the next corpus entry manually
#[derive(Debug, Clone)]
pub struct TuneableScheduler<S> {
    phantom: PhantomData<S>,
}

impl<S> TuneableScheduler<S>
where
    S: HasMetadata + HasCorpus,
{
    /// Creates a new `TuneableScheduler`
    #[must_use]
    pub fn new(state: &mut S) -> Self {
        if !state.has_metadata::<TuneableSchedulerMetadata>() {
            state.add_metadata(TuneableSchedulerMetadata::default());
        }
        Self {
            phantom: PhantomData,
        }
    }

    fn metadata_mut(state: &mut S) -> &mut TuneableSchedulerMetadata {
        state
            .metadata_mut()
            .get_mut::<TuneableSchedulerMetadata>()
            .unwrap()
    }

    fn metadata(state: &S) -> &TuneableSchedulerMetadata {
        state.metadata().get::<TuneableSchedulerMetadata>().unwrap()
    }

    /// Sets the next corpus id to be used
    pub fn set_next(state: &mut S, next: usize) {
        Self::metadata_mut(state).next = Some(next);
    }

    /// Gets the next set corpus id
    pub fn get_next(state: &S) -> Option<usize> {
        Self::metadata(state).next
    }

    /// Resets this to a queue scheduler
    pub fn reset(state: &mut S) {
        let metadata = Self::metadata_mut(state);
        metadata.next = None;
    }

    /// Gets the current corpus entry id
    pub fn get_current(state: &S) -> usize {
        state.corpus().current().unwrap_or_default()
    }
}

impl<S> UsesState for TuneableScheduler<S>
where
    S: UsesInput,
{
    type State = S;
}

impl<S> Scheduler for TuneableScheduler<S>
where
    S: HasCorpus + HasMetadata,
{
    /// Gets the next entry in the queue
    fn next(&self, state: &mut Self::State) -> Result<usize, Error> {
        if state.corpus().count() == 0 {
            return Err(Error::empty("No entries in corpus".to_owned()));
        }
        let id = if let Some(next) = Self::get_next(state) {
            // next was set
            next
        } else if Self::get_current(state) + 1 >= state.corpus().count() {
            0
        } else {
            Self::get_current(state) + 1
        };
        *state.corpus_mut().current_mut() = Some(id);
        Ok(id)
    }
}
