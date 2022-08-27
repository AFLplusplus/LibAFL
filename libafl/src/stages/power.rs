//! The power schedules. This stage should be invoked after the calibration stage.

use alloc::string::{String, ToString};
use core::{fmt::Debug, marker::PhantomData};

use crate::{
    corpus::{Corpus, SchedulerTestcaseMetaData},
    executors::HasObservers,
    fuzzer::Evaluator,
    mutators::Mutator,
    observers::MapObserver,
    schedulers::{
        powersched::SchedulerMetadata, testcase_score::CorpusPowerTestcaseScore, TestcaseScore,
    },
    stages::{MutationalStage, Stage},
    state::{HasCorpus, HasMetadata},
    Error,
};
/// The mutational stage using power schedules
#[derive(Clone, Debug)]
pub struct PowerMutationalStage<F, O> {
    map_observer_name: String,
    mutator: <Self as MutationalStage>::Mutator,
    phantom: PhantomData<(F, O)>,
}

impl<F, O> MutationalStage for PowerMutationalStage<F, O>
where
    F: TestcaseScore,
    O: MapObserver,
{
    /// The mutator, added to this stage
    #[inline]
    fn mutator(&self) -> &Self::Mutator {
        &self.mutator
    }

    /// The list of mutators, added to this stage (as mutable ref)
    #[inline]
    fn mutator_mut(&mut self) -> &mut Self::Mutator {
        &mut self.mutator
    }

    /// Gets the number of iterations as a random number
    #[allow(clippy::cast_sign_loss)]
    fn iterations(&self, state: &mut Self::State, corpus_idx: usize) -> Result<usize, Error> {
        // Update handicap
        let mut testcase = state.corpus().get(corpus_idx)?.borrow_mut();
        let score = F::compute(&mut *testcase, state)? as usize;

        Ok(score)
    }

    #[allow(clippy::cast_possible_wrap)]
    fn perform_mutational(
        &mut self,
        fuzzer: &mut <Self as Stage>::Fuzzer,
        executor: &mut <Self as Stage>::Executor,
        state: &mut Self::State,
        manager: &mut <Self as Stage>::EventManager,
        corpus_idx: usize,
    ) -> Result<(), Error> {
        let num = self.iterations(state, corpus_idx)?;

        for i in 0..num {
            let mut input = state
                .corpus()
                .get(corpus_idx)?
                .borrow_mut()
                .load_input()?
                .clone();

            self.mutator_mut().mutate(state, &mut input, i as i32)?;

            let (_, corpus_idx) = fuzzer.evaluate_input(state, executor, manager, input)?;

            let observer = executor
                .observers()
                .match_name::<O>(&self.map_observer_name)
                .ok_or_else(|| Error::key_not_found("MapObserver not found".to_string()))?;

            let mut hash = observer.hash() as usize;

            let psmeta = state
                .metadata_mut()
                .get_mut::<SchedulerMetadata>()
                .ok_or_else(|| Error::key_not_found("SchedulerMetadata not found".to_string()))?;

            hash %= psmeta.n_fuzz().len();
            // Update the path frequency
            psmeta.n_fuzz_mut()[hash] = psmeta.n_fuzz()[hash].saturating_add(1);

            if let Some(idx) = corpus_idx {
                state
                    .corpus()
                    .get(idx)?
                    .borrow_mut()
                    .metadata_mut()
                    .get_mut::<SchedulerTestcaseMetaData>()
                    .ok_or_else(|| {
                        Error::key_not_found("SchedulerTestcaseMetaData not found".to_string())
                    })?
                    .set_n_fuzz_entry(hash);
            }

            self.mutator_mut().post_exec(state, i as i32, corpus_idx)?;
        }

        Ok(())
    }
}

impl<F, O> Stage for PowerMutationalStage<F, O> {
    #[inline]
    #[allow(clippy::let_and_return)]
    fn perform(
        &mut self,
        fuzzer: &mut Self::Fuzzer,
        executor: &mut Self::Executor,
        state: &mut Self::State,
        manager: &mut Self::EventManager,
        corpus_idx: usize,
    ) -> Result<(), Error> {
        let ret = self.perform_mutational(fuzzer, executor, state, manager, corpus_idx);
        ret
    }
}

impl<F, O> PowerMutationalStage<F, O>
where
    F: TestcaseScore,
    O: MapObserver,
{
    /// Creates a new [`PowerMutationalStage`]
    pub fn new(mutator: <Self as MutationalStage>::Mutator, map_observer_name: &O) -> Self {
        Self {
            map_observer_name: map_observer_name.name().to_string(),
            mutator,
            phantom: PhantomData,
        }
    }
}

/// The standard powerscheduling stage
pub type StdPowerMutationalStage<O> = PowerMutationalStage<CorpusPowerTestcaseScore, O>;
