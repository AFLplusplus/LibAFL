//! Schedule the access to the Corpus.

use alloc::{borrow::ToOwned, string::ToString};
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
pub use powersched::{PowerQueueScheduler, SchedulerMetadata};

pub mod probabilistic_sampling;
pub use probabilistic_sampling::ProbabilitySamplingScheduler;

pub mod accounting;
pub use accounting::CoverageAccountingScheduler;

pub mod weighted;
pub use weighted::{StdWeightedScheduler, WeightedScheduler};

pub mod tuneable;
use libafl_bolts::rands::Rand;
pub use tuneable::*;

use crate::{
    corpus::{Corpus, CorpusId, HasTestcase, SchedulerTestcaseMetadata, Testcase},
    inputs::UsesInput,
    observers::{MapObserver, ObserversTuple},
    random_corpus_id,
    state::{HasCorpus, HasMetadata, HasRand, State, UsesState},
    Error,
};

/// The scheduler also implements `on_remove` and `on_replace` if it implements this stage.
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

/// Define the metadata operations when removing testcase from AFL-style scheduler
pub trait HasAFLRemovableScheduler: RemovableScheduler
where
    Self::State: HasCorpus + HasMetadata + HasTestcase,
{
    #[allow(clippy::cast_precision_loss)]
    #[allow(clippy::cast_precision_loss)]
    /// Adjusting metadata when removing the testcase
    fn on_remove_metadata(
        &mut self,
        state: &mut Self::State,
        _idx: CorpusId,
        prev: &Option<Testcase<<Self::State as UsesInput>::Input>>,
    ) -> Result<(), Error> {
        let prev = prev.as_ref().ok_or_else(|| {
            Error::illegal_argument(
                "Power schedulers must be aware of the removed corpus entry for reweighting.",
            )
        })?;

        let prev_meta = prev.metadata::<SchedulerTestcaseMetadata>()?;

        // Use these to adjust `SchedulerMetadata`
        let (prev_total_time, prev_cycles) = prev_meta.cycle_and_time();
        let prev_bitmap_size = prev_meta.bitmap_size();
        let prev_bitmap_size_log = libm::log2(prev_bitmap_size as f64);

        let psmeta = state.metadata_mut::<SchedulerMetadata>()?;

        psmeta.set_exec_time(psmeta.exec_time() - prev_total_time);
        psmeta.set_cycles(psmeta.cycles() - (prev_cycles as u64));
        psmeta.set_bitmap_size(psmeta.bitmap_size() - prev_bitmap_size);
        psmeta.set_bitmap_size_log(psmeta.bitmap_size_log() - prev_bitmap_size_log);
        psmeta.set_bitmap_entries(psmeta.bitmap_entries() - 1);

        Ok(())
    }

    #[allow(clippy::cast_precision_loss)]
    /// Adjusting metadata when replacing the corpus
    fn on_replace_metadata(
        &mut self,
        state: &mut Self::State,
        idx: CorpusId,
        prev: &Testcase<<Self::State as UsesInput>::Input>,
    ) -> Result<(), Error> {
        let prev_meta = prev.metadata::<SchedulerTestcaseMetadata>()?;

        // Next depth is + 1
        let prev_depth = prev_meta.depth() + 1;

        // Use these to adjust `SchedulerMetadata`
        let (prev_total_time, prev_cycles) = prev_meta.cycle_and_time();
        let prev_bitmap_size = prev_meta.bitmap_size();
        let prev_bitmap_size_log = libm::log2(prev_bitmap_size as f64);

        let psmeta = state.metadata_mut::<SchedulerMetadata>()?;

        // We won't add new one because it'll get added when it gets executed in calirbation next time.
        psmeta.set_exec_time(psmeta.exec_time() - prev_total_time);
        psmeta.set_cycles(psmeta.cycles() - (prev_cycles as u64));
        psmeta.set_bitmap_size(psmeta.bitmap_size() - prev_bitmap_size);
        psmeta.set_bitmap_size_log(psmeta.bitmap_size_log() - prev_bitmap_size_log);
        psmeta.set_bitmap_entries(psmeta.bitmap_entries() - 1);

        state
            .corpus()
            .get(idx)?
            .borrow_mut()
            .add_metadata(SchedulerTestcaseMetadata::new(prev_depth));
        Ok(())
    }
}

/// Defines the common metadata operations for the AFL-style schedulers
pub trait HasAFLSchedulerMetadata<O, S>: Scheduler
where
    Self::State: HasCorpus + HasMetadata + HasTestcase,
    O: MapObserver,
{
    /// Return the last hash
    fn last_hash(&self) -> usize;

    /// Set the last hash
    fn set_last_hash(&mut self, value: usize);

    /// Get the observer map observer name
    fn map_observer_name(&self) -> &str;

    /// Called when a [`Testcase`] is added to the corpus
    fn on_add_metadata(&self, state: &mut Self::State, idx: CorpusId) -> Result<(), Error> {
        let current_idx = *state.corpus().current();

        let mut depth = match current_idx {
            Some(parent_idx) => state
                .testcase(parent_idx)?
                .metadata::<SchedulerTestcaseMetadata>()?
                .depth(),
            None => 0,
        };

        // TODO increase perf_score when finding new things like in AFL
        // https://github.com/google/AFL/blob/master/afl-fuzz.c#L6547

        // Attach a `SchedulerTestcaseMetadata` to the queue entry.
        depth += 1;
        let mut testcase = state.testcase_mut(idx)?;
        testcase.add_metadata(SchedulerTestcaseMetadata::with_n_fuzz_entry(
            depth,
            self.last_hash(),
        ));
        testcase.set_parent_id_optional(current_idx);
        Ok(())
    }

    /// Called when a [`Testcase`] is evaluated
    fn on_evaluation_metadata<OT>(
        &mut self,
        state: &mut Self::State,
        _input: &<Self::State as UsesInput>::Input,
        observers: &OT,
    ) -> Result<(), Error>
    where
        OT: ObserversTuple<Self::State>,
    {
        let observer = observers
            .match_name::<O>(self.map_observer_name())
            .ok_or_else(|| Error::key_not_found("MapObserver not found".to_string()))?;

        let mut hash = observer.hash() as usize;

        let psmeta = state.metadata_mut::<SchedulerMetadata>()?;

        hash %= psmeta.n_fuzz().len();
        // Update the path frequency
        psmeta.n_fuzz_mut()[hash] = psmeta.n_fuzz()[hash].saturating_add(1);

        self.set_last_hash(hash);

        Ok(())
    }

    /// Called when choosing the next [`Testcase`]
    fn on_next_metadata(
        &mut self,
        state: &mut Self::State,
        _next_idx: Option<CorpusId>,
    ) -> Result<(), Error> {
        let current_idx = *state.corpus().current();

        if let Some(idx) = current_idx {
            let mut testcase = state.testcase_mut(idx)?;
            let tcmeta = testcase.metadata_mut::<SchedulerTestcaseMetadata>()?;

            if tcmeta.handicap() >= 4 {
                tcmeta.set_handicap(tcmeta.handicap() - 4);
            } else if tcmeta.handicap() > 0 {
                tcmeta.set_handicap(tcmeta.handicap() - 1);
            }
        }

        Ok(())
    }
}

/// The scheduler define how the fuzzer requests a testcase from the corpus.
/// It has hooks to corpus add/replace/remove to allow complex scheduling algorithms to collect data.
pub trait Scheduler: UsesState
where
    Self::State: HasCorpus,
{
    /// Called when a [`Testcase`] is added to the corpus
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
    S: State + HasTestcase,
{
    type State = S;
}

impl<S> Scheduler for RandScheduler<S>
where
    S: HasCorpus + HasRand + HasTestcase + State,
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
            Err(Error::empty(
                "No entries in corpus. This often implies the target is not properly instrumented."
                    .to_owned(),
            ))
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
