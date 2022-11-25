//! The power schedules. This stage should be invoked after the calibration stage.
use alloc::string::{String, ToString};
#[cfg(feature = "async")]
use alloc::vec::Vec;
use core::{fmt::Debug, marker::PhantomData};

use crate::{
    bolts::tuples::MatchName,
    corpus::{Corpus, SchedulerTestcaseMetaData},
    executors::{Executor, HasObservers},
    fuzzer::Evaluator,
    mutators::Mutator,
    observers::MapObserver,
    schedulers::{
        powersched::SchedulerMetadata, testcase_score::CorpusPowerTestcaseScore, TestcaseScore,
    },
    stages::{MutationalStage, Stage},
    state::{HasClientPerfMonitor, HasCorpus, HasMetadata, HasRand, UsesState},
    Error,
};
#[cfg(feature = "async")]
use crate::{executors::AsyncExecutor, AsyncEvaluator, HasRuntime};

/// The mutational stage using power schedules
#[derive(Clone, Debug)]
pub struct PowerMutationalStage<E, F, EM, M, O, Z, const ASYNC: bool> {
    map_observer_name: String,
    mutator: M,
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(E, F, EM, O, Z)>,
}

impl<E, F, EM, M, O, Z, const ASYNC: bool> UsesState
    for PowerMutationalStage<E, F, EM, M, O, Z, ASYNC>
where
    E: UsesState,
{
    type State = E::State;
}

impl<E, F, EM, M, O, Z> MutationalStage<E, EM, M, Z>
    for PowerMutationalStage<E, F, EM, M, O, Z, false>
where
    E: Executor<EM, Z> + HasObservers,
    EM: UsesState<State = E::State>,
    F: TestcaseScore<E::State>,
    M: Mutator<E::State>,
    O: MapObserver,
    E::State: HasClientPerfMonitor + HasCorpus + HasMetadata + HasRand,
    Z: Evaluator<E, EM, State = E::State>,
{
    /// The mutator, added to this stage
    #[inline]
    fn mutator(&self) -> &M {
        &self.mutator
    }

    /// The list of mutators, added to this stage (as mutable ref)
    #[inline]
    fn mutator_mut(&mut self) -> &mut M {
        &mut self.mutator
    }

    /// Gets the number of iterations as a random number
    #[allow(clippy::cast_sign_loss)]
    fn iterations(&self, state: &mut E::State, corpus_idx: usize) -> Result<u64, Error> {
        // Update handicap
        let mut testcase = state.corpus().get(corpus_idx)?.borrow_mut();
        let score = F::compute(&mut *testcase, state)? as u64;

        Ok(score)
    }

    #[allow(clippy::cast_possible_wrap)]
    fn perform_mutational(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut E::State,
        manager: &mut EM,
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

impl<E, F, EM, M, O, Z> Stage<E, EM, Z> for PowerMutationalStage<E, F, EM, M, O, Z, false>
where
    E: Executor<EM, Z> + HasObservers,
    EM: UsesState<State = E::State>,
    F: TestcaseScore<E::State>,
    M: Mutator<E::State>,
    O: MapObserver,
    E::State: HasClientPerfMonitor + HasCorpus + HasMetadata + HasRand,
    Z: Evaluator<E, EM, State = E::State>,
{
    #[inline]
    #[allow(clippy::let_and_return)]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut E::State,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error> {
        let ret = self.perform_mutational(fuzzer, executor, state, manager, corpus_idx);
        ret
    }
}

#[cfg(feature = "async")]
impl<E, F, EM, M, O, Z> MutationalStage<E, EM, M, Z>
    for PowerMutationalStage<E, F, EM, M, O, Z, true>
where
    E: AsyncExecutor<EM, Z>,
    EM: UsesState,
    F: TestcaseScore<EM::State>,
    M: Mutator<EM::State>,
    O: MapObserver,
    Z: AsyncEvaluator<E, EM, State = EM::State> + HasRuntime,
    EM::State: HasClientPerfMonitor + HasCorpus + HasMetadata + HasRand,
{
    /// The mutator, added to this stage
    #[inline]
    fn mutator(&self) -> &M {
        &self.mutator
    }

    /// The list of mutators, added to this stage (as mutable ref)
    #[inline]
    fn mutator_mut(&mut self) -> &mut M {
        &mut self.mutator
    }

    /// Gets the number of iterations as a random number
    #[allow(clippy::cast_sign_loss)]
    fn iterations(&self, state: &mut E::State, corpus_idx: usize) -> Result<u64, Error> {
        // Update handicap
        let mut testcase = state.corpus().get(corpus_idx)?.borrow_mut();
        let score = F::compute(&mut *testcase, state)? as u64;

        Ok(score)
    }

    #[allow(clippy::cast_possible_wrap)]
    fn perform_mutational_async(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut E::State,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error> {
        let num = self.iterations(state, corpus_idx)?;
        let mut deferred = Vec::with_capacity(num as usize);

        for i in 0..num {
            let mut input = state
                .corpus()
                .get(corpus_idx)?
                .borrow_mut()
                .load_input()?
                .clone();

            self.mutator_mut().mutate(state, &mut input, i as i32)?;

            let current = fuzzer.start_evaluate_input(state, executor, manager, &input)?;

            deferred.push((input, current));
        }

        for (i, (input, current)) in deferred.into_iter().enumerate() {
            let (_, obs, corpus_idx) =
                fuzzer.complete_evaluation(state, executor, manager, input, current, true)?;

            let observer = obs
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

#[cfg(feature = "async")]
impl<E, F, EM, M, O, Z> Stage<E, EM, Z> for PowerMutationalStage<E, F, EM, M, O, Z, true>
where
    E: AsyncExecutor<EM, Z>,
    EM: UsesState,
    F: TestcaseScore<EM::State>,
    M: Mutator<EM::State>,
    O: MapObserver,
    EM::State: HasClientPerfMonitor + HasCorpus + HasMetadata + HasRand,
    Z: AsyncEvaluator<E, EM, State = EM::State> + HasRuntime,
{
    #[inline]
    #[allow(clippy::let_and_return)]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut E::State,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error> {
        let ret = self.perform_mutational_async(fuzzer, executor, state, manager, corpus_idx);
        ret
    }
}

impl<E, F, EM, M, O, Z> PowerMutationalStage<E, F, EM, M, O, Z, false>
where
    E: Executor<EM, Z> + HasObservers,
    EM: UsesState<State = E::State>,
    F: TestcaseScore<E::State>,
    M: Mutator<E::State>,
    O: MapObserver,
    E::State: HasClientPerfMonitor + HasCorpus + HasMetadata + HasRand,
    Z: Evaluator<E, EM, State = E::State>,
{
    /// Creates a new [`PowerMutationalStage`]
    pub fn new(mutator: M, map_observer_name: &O) -> Self {
        Self {
            map_observer_name: map_observer_name.name().to_string(),
            mutator,
            phantom: PhantomData,
        }
    }
}

#[cfg(feature = "async")]
impl<E, F, EM, M, O, Z> PowerMutationalStage<E, F, EM, M, O, Z, true>
where
    E: AsyncExecutor<EM, Z>,
    EM: UsesState,
    F: TestcaseScore<EM::State>,
    M: Mutator<EM::State>,
    O: MapObserver,
    EM::State: HasClientPerfMonitor + HasCorpus + HasMetadata + HasRand,
    Z: AsyncEvaluator<E, EM, State = EM::State> + HasRuntime,
{
    /// Creates a new [`PowerMutationalStage`]
    pub fn new_async(mutator: M, map_observer_name: &O) -> Self {
        Self {
            map_observer_name: map_observer_name.name().to_string(),
            mutator,
            phantom: PhantomData,
        }
    }
}

/// The standard powerscheduling stage
pub type StdPowerMutationalStage<E, EM, M, O, Z, const ASYNC: bool> =
    PowerMutationalStage<E, CorpusPowerTestcaseScore<<E as UsesState>::State>, EM, M, O, Z, ASYNC>;
