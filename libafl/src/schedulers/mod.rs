//! Schedule the access to the Corpus.

use alloc::borrow::ToOwned;
use core::marker::PhantomData;

pub mod testcase_score;
pub use testcase_score::{LenTimeMulTestcaseScore, TestcaseScore};

pub mod queue;
pub use queue::QueueScheduler;

pub mod minimizer;
pub use minimizer::{
    IndexesLenTimeMinimizerScheduler, LenTimeMinimizerScheduler, MinimizerScheduler,
};

pub mod powersched;
pub use powersched::PowerQueueScheduler;

pub mod probabilistic_sampling;
pub use probabilistic_sampling::ProbabilitySamplingScheduler;

pub mod accounting;
pub use accounting::CoverageAccountingScheduler;

pub mod weighted;
pub use weighted::{StdWeightedScheduler, WeightedScheduler};

pub mod ecofuzz;
pub use ecofuzz::{EcoMetadata, EcoScheduler, EcoState, EcoTestcaseMetadata, EcoTestcaseScore};

pub mod tuneable;
pub use tuneable::*;

use crate::{
    bolts::rands::Rand,
    corpus::{Corpus, CorpusId, HasTestcase, Testcase},
    inputs::UsesInput,
    observers::ObserversTuple,
    random_corpus_id,
    state::{HasCorpus, HasRand, UsesState},
    Error,
};

/// The scheduler also implemnts `on_remove` and `on_replace` if it implements this stage.
pub trait RemovableScheduler: Scheduler
where
    Self::State: HasCorpus,
{
    /// Removed the given entry from the corpus at the given index
    fn on_remove(
        &mut self,
        _state: &mut Self::State,
        _idx: CorpusId,
        _testcase: &Option<Testcase<<Self::State as UsesInput>::Input>>,
    ) -> Result<(), Error> {
        Ok(())
    }

    /// Replaced the given testcase at the given idx
    fn on_replace(
        &mut self,
        _state: &mut Self::State,
        _idx: CorpusId,
        _prev: &Testcase<<Self::State as UsesInput>::Input>,
    ) -> Result<(), Error> {
        Ok(())
    }
}

/// The scheduler define how the fuzzer requests a testcase from the corpus.
/// It has hooks to corpus add/replace/remove to allow complex scheduling algorithms to collect data.
pub trait Scheduler: UsesState
where
    Self::State: HasCorpus,
{
    /// Added an entry to the corpus at the given index
    fn on_add(&mut self, _state: &mut Self::State, _idx: CorpusId) -> Result<(), Error>;
    // Add parent_id here if it has no inner

    /// An input has been evaluated
    fn on_evaluation<OT>(
        &mut self,
        _state: &mut Self::State,
        _input: &<Self::State as UsesInput>::Input,
        _observers: &OT,
    ) -> Result<(), Error>
    where
        OT: ObserversTuple<Self::State>,
    {
        Ok(())
    }

    /// Gets the next entry
    fn next(&mut self, state: &mut Self::State) -> Result<CorpusId, Error>;
    // Increment corpus.current() here if it has no inner

    /// Set current fuzzed corpus id and `scheduled_count`
    fn set_current_scheduled(
        &mut self,
        state: &mut Self::State,
        next_idx: Option<CorpusId>,
    ) -> Result<(), Error> {
        *state.corpus_mut().current_mut() = next_idx;
        Ok(())
    }
}

/// Feed the fuzzer simply with a random testcase on request
#[derive(Debug, Clone)]
pub struct RandScheduler<S> {
    phantom: PhantomData<S>,
}

impl<S> UsesState for RandScheduler<S>
where
    S: UsesInput + HasTestcase,
{
    type State = S;
}

impl<S> Scheduler for RandScheduler<S>
where
    S: HasCorpus + HasRand + HasTestcase,
{
    fn on_add(&mut self, state: &mut Self::State, idx: CorpusId) -> Result<(), Error> {
        // Set parent id
        let current_idx = *state.corpus().current();
        state
            .corpus()
            .get(idx)?
            .borrow_mut()
            .set_parent_id_optional(current_idx);

        Ok(())
    }

    /// Gets the next entry at random
    fn next(&mut self, state: &mut Self::State) -> Result<CorpusId, Error> {
        if state.corpus().count() == 0 {
            Err(Error::empty("No entries in corpus".to_owned()))
        } else {
            let id = random_corpus_id!(state.corpus(), state.rand_mut());
            self.set_current_scheduled(state, Some(id))?;
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
