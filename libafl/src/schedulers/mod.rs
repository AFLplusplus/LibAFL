//! Schedule the access to the Corpus.

pub mod queue;
use core::marker::PhantomData;

pub use queue::QueueScheduler;

pub mod probabilistic_sampling;
pub use probabilistic_sampling::ProbabilitySamplingScheduler;

pub mod accounting;
pub use accounting::CoverageAccountingScheduler;

pub mod testcase_score;
pub use testcase_score::{LenTimeMulTestcaseScore, TestcaseScore};

pub mod minimizer;
pub use minimizer::{
    IndexesLenTimeMinimizerScheduler, LenTimeMinimizerScheduler, MinimizerScheduler,
};

pub mod weighted;
pub use weighted::{StdWeightedScheduler, WeightedScheduler};

pub mod powersched;
use alloc::borrow::ToOwned;

pub use powersched::PowerQueueScheduler;

use crate::{
    bolts::rands::Rand,
    corpus::{Corpus, Testcase},
    inputs::UsesInput,
    state::{HasCorpus, HasRand, UsesState},
    Error,
};

/// The scheduler define how the fuzzer requests a testcase from the corpus.
/// It has hooks to corpus add/replace/remove to allow complex scheduling algorithms to collect data.
pub trait Scheduler: UsesState {
    /// Added an entry to the corpus at the given index
    fn on_add(&self, _state: &mut Self::State, _idx: usize) -> Result<(), Error> {
        Ok(())
    }

    /// Replaced the given testcase at the given idx
    fn on_replace(
        &self,
        _state: &mut Self::State,
        _idx: usize,
        _prev: &Testcase<<Self::State as UsesInput>::Input>,
    ) -> Result<(), Error> {
        Ok(())
    }

    /// Removed the given entry from the corpus at the given index
    fn on_remove(
        &self,
        _state: &mut Self::State,
        _idx: usize,
        _testcase: &Option<Testcase<<Self::State as UsesInput>::Input>>,
    ) -> Result<(), Error> {
        Ok(())
    }

    /// Gets the next entry
    fn next(&self, state: &mut Self::State) -> Result<usize, Error>;
}

/// Feed the fuzzer simply with a random testcase on request
#[derive(Debug, Clone)]
pub struct RandScheduler<S> {
    phantom: PhantomData<S>,
}

impl<S> UsesState for RandScheduler<S>
where
    S: UsesInput,
{
    type State = S;
}

impl<S> Scheduler for RandScheduler<S>
where
    S: HasCorpus + HasRand,
{
    /// Gets the next entry at random
    fn next(&self, state: &mut Self::State) -> Result<usize, Error> {
        if state.corpus().count() == 0 {
            Err(Error::empty("No entries in corpus".to_owned()))
        } else {
            let len = state.corpus().count();
            let id = state.rand_mut().below(len as u64) as usize;
            *state.corpus_mut().current_mut() = Some(id);
            Ok(id)
        }
    }
}

impl<S> RandScheduler<S> {
    /// Create a new [`RandScheduler`] that just schedules randomly.
    #[must_use]
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

impl<S> Default for RandScheduler<S> {
    fn default() -> Self {
        Self::new()
    }
}

/// A [`StdScheduler`] uses the default scheduler in `LibAFL` to schedule [`Testcase`]s.
/// The current `Std` is a [`RandScheduler`], although this may change in the future, if another [`Scheduler`] delivers better results.
pub type StdScheduler<S> = RandScheduler<S>;
