//! Schedule the access to the Corpus.

pub mod queue;
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
pub use powersched::PowerQueueScheduler;

use alloc::borrow::ToOwned;

use crate::{
    bolts::rands::Rand,
    corpus::{Corpus, Testcase},
    inputs::Input,
    state::{HasCorpus, HasRand},
    Error,
};

/// The scheduler define how the fuzzer requests a testcase from the corpus.
/// It has hooks to corpus add/replace/remove to allow complex scheduling algorithms to collect data.
pub trait Scheduler<I, S>
where
    I: Input,
{
    /// Add an entry to the corpus and return its index
    fn on_add(&self, _state: &mut S, _idx: usize) -> Result<(), Error> {
        Ok(())
    }

    /// Replaces the testcase at the given idx
    fn on_replace(
        &self,
        _state: &mut S,
        _idx: usize,
        _testcase: &Testcase<I>,
    ) -> Result<(), Error> {
        Ok(())
    }

    /// Removes an entry from the corpus, returning it if it was present.
    fn on_remove(
        &self,
        _state: &mut S,
        _idx: usize,
        _testcase: &Option<Testcase<I>>,
    ) -> Result<(), Error> {
        Ok(())
    }

    /// Gets the next entry
    fn next(&self, state: &mut S) -> Result<usize, Error>;
}

/// Feed the fuzzer simpply with a random testcase on request
#[derive(Debug, Clone)]
pub struct RandScheduler;

impl<I, S> Scheduler<I, S> for RandScheduler
where
    S: HasCorpus<I> + HasRand,
    I: Input,
{
    /// Gets the next entry at random
    fn next(&self, state: &mut S) -> Result<usize, Error> {
        if state.corpus().count() == 0 {
            Err(Error::Empty("No entries in corpus".to_owned()))
        } else {
            let len = state.corpus().count();
            let id = state.rand_mut().below(len as u64) as usize;
            *state.corpus_mut().current_mut() = Some(id);
            Ok(id)
        }
    }
}

impl RandScheduler {
    /// Create a new [`RandScheduler`] that just schedules randomly.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for RandScheduler {
    fn default() -> Self {
        Self::new()
    }
}

/// A [`StdScheduler`] uses the default scheduler in `LibAFL` to schedule [`Testcase`]s.
/// The current `Std` is a [`RandScheduler`], although this may change in the future, if another [`Scheduler`] delivers better results.
pub type StdScheduler = RandScheduler;
