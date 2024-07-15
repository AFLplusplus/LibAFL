//! The queue corpus scheduler implements an AFL-like queue mechanism

use alloc::borrow::ToOwned;
use core::marker::PhantomData;

use libafl_bolts::{
    tuples::{Handle, Handled},
    Named,
};

use crate::{
    corpus::{Corpus, CorpusId, HasTestcase},
    observers::MapObserver,
    prelude::HasRand,
    schedulers::{AflScheduler, RemovableScheduler, Scheduler},
    state::{HasCorpus, State, UsesState},
    Error, HasMetadata,
};

/// Walk the corpus in a queue-like fashion
#[derive(Debug, Clone)]
pub struct QueueScheduler<C, O, S> {
    queue_cycles: u64,
    runs_in_current_cycle: u64,
    last_hash: usize,
    map_observer_handle: Handle<C>,
    phantom: PhantomData<(O, S)>,
}

impl<C, O, S> UsesState for QueueScheduler<C, O, S>
where
    S: State,
{
    type State = S;
}

impl<C, O, S> RemovableScheduler for QueueScheduler<C, O, S> where S: HasCorpus + HasTestcase + State
{}

impl<C, O, S> Scheduler for QueueScheduler<C, O, S>
where
    S: HasCorpus + HasTestcase + State,
{
    fn on_add(&mut self, state: &mut Self::State, id: CorpusId) -> Result<(), Error> {
        // Set parent id
        let current_id = *state.corpus().current();
        state
            .corpus()
            .get(id)?
            .borrow_mut()
            .set_parent_id_optional(current_id);

        Ok(())
    }

    /// Gets the next entry in the queue
    fn next(&mut self, state: &mut Self::State) -> Result<CorpusId, Error> {
        if state.corpus().count() == 0 {
            Err(Error::empty(
                "No entries in corpus. This often implies the target is not properly instrumented."
                    .to_owned(),
            ))
        } else {
            let id = state
                .corpus()
                .current()
                .map(|id| state.corpus().next(id))
                .flatten()
                .unwrap_or_else(|| state.corpus().first().unwrap());

            self.runs_in_current_cycle += 1;
            // TODO deal with corpus_counts decreasing due to removals
            if self.runs_in_current_cycle >= state.corpus().count() as u64 {
                self.queue_cycles += 1;
            }
            self.set_current_scheduled(state, Some(id))?;
            Ok(id)
        }
    }
}

impl<C, O, S> QueueScheduler<C, O, S>
where
    C: AsRef<O> + Named,
{
    /// Creates a new `QueueScheduler`
    #[must_use]
    pub fn new(map_observer: &C) -> Self {
        Self {
            runs_in_current_cycle: 0,
            queue_cycles: 0,
            last_hash: 0,
            map_observer_handle: map_observer.handle(),
            phantom: PhantomData,
        }
    }
}

impl<C, O, S> AflScheduler<C, O, S> for QueueScheduler<C, O, S>
where
    O: MapObserver,
    S: HasCorpus + HasMetadata + HasTestcase + HasRand + State,
    C: AsRef<O> + Named,
{
    fn last_hash(&self) -> usize {
        self.last_hash
    }

    fn set_last_hash(&mut self, hash: usize) {
        self.last_hash = hash;
    }

    fn map_observer_handle(&self) -> &Handle<C> {
        &self.map_observer_handle
    }

    fn queue_cycles(&self) -> u64 {
        self.queue_cycles
    }
}

#[cfg(test)]
#[cfg(feature = "std")]
mod tests {

    use std::{fs, path::PathBuf};

    use libafl_bolts::rands::StdRand;

    use crate::{
        corpus::{Corpus, OnDiskCorpus, Testcase},
        feedbacks::ConstFeedback,
        inputs::bytes::BytesInput,
        schedulers::{QueueScheduler, Scheduler},
        state::{HasCorpus, StdState},
    };

    #[test]
    fn test_queuecorpus() {
        let rand = StdRand::with_seed(4);
        let mut scheduler = QueueScheduler::new();

        let mut q =
            OnDiskCorpus::<BytesInput>::new(PathBuf::from("target/.test/fancy/path")).unwrap();
        let t = Testcase::with_filename(BytesInput::new(vec![0_u8; 4]), "fancyfile".into());
        q.add(t).unwrap();

        let objective_q =
            OnDiskCorpus::<BytesInput>::new(PathBuf::from("target/.test/fancy/objective/path"))
                .unwrap();

        let mut feedback = ConstFeedback::new(false);
        let mut objective = ConstFeedback::new(false);

        let mut state = StdState::new(rand, q, objective_q, &mut feedback, &mut objective).unwrap();

        let next_id = scheduler.next(&mut state).unwrap();
        let filename = state
            .corpus()
            .get(next_id)
            .unwrap()
            .borrow()
            .filename()
            .as_ref()
            .unwrap()
            .clone();

        assert_eq!(filename, "fancyfile");

        fs::remove_dir_all("target/.test/fancy/path").unwrap();
    }
}
