//! The power schedules. This stage should be invoked after the calibration stage.

use core::{fmt::Debug, marker::PhantomData};

use crate::{
    corpus::{Corpus, CorpusId},
    executors::{Executor, HasExecutorState, HasObservers},
    fuzzer::Evaluator,
    mutators::Mutator,
    schedulers::{testcase_score::CorpusPowerTestcaseScore, TestcaseScore},
    stages::{mutational::MutatedTransform, MutationalStage, Stage},
    state::{HasCorpus, HasMetadata, HasRand, UsesState},
    Error,
};

/// The mutational stage using power schedules
#[derive(Clone, Debug)]
pub struct PowerMutationalStage<E, F, EM, I, M, Z, ES> {
    mutator: M,
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(E, F, EM, I, Z, ES)>,
}

impl<E, F, EM, I, M, Z, ES> UsesState for PowerMutationalStage<E, F, EM, I, M, Z, ES>
where
    E: UsesState,
{
    type State = E::State;
}

impl<E, F, EM, I, M, Z, ES> MutationalStage<E, EM, I, M, Z>
    for PowerMutationalStage<E, F, EM, I, M, Z, ES>
where
    E: Executor<EM, Z, ES> + HasObservers,
    EM: UsesState<State = E::State>,
    F: TestcaseScore<E::State>,
    M: Mutator<I, E::State>,
    E::State: HasCorpus + HasMetadata + HasRand,
    Z: Evaluator<E, EM, State = E::State>,
    I: MutatedTransform<E::Input, E::State> + Clone,
    ES: HasExecutorState,
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
    fn iterations(&self, state: &mut E::State, corpus_idx: CorpusId) -> Result<u64, Error> {
        // Update handicap
        let mut testcase = state.corpus().get(corpus_idx)?.borrow_mut();
        let score = F::compute(state, &mut *testcase)? as u64;

        Ok(score)
    }
}

impl<E, F, EM, I, M, Z, ES> Stage<E, EM, Z> for PowerMutationalStage<E, F, EM, I, M, Z, ES>
where
    E: Executor<EM, Z, ES> + HasObservers,
    EM: UsesState<State = E::State>,
    F: TestcaseScore<E::State>,
    M: Mutator<I, E::State>,
    E::State: HasCorpus + HasMetadata + HasRand,
    Z: Evaluator<E, EM, State = E::State>,
    I: MutatedTransform<E::Input, E::State> + Clone,
    ES: HasExecutorState,
{
    type Progress = (); // TODO should we resume this stage?

    #[inline]
    #[allow(clippy::let_and_return)]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut E::State,
        manager: &mut EM,
    ) -> Result<(), Error> {
        let ret = self.perform_mutational(fuzzer, executor, state, manager);
        ret
    }
}

impl<E, F, EM, M, Z, ES> PowerMutationalStage<E, F, EM, E::Input, M, Z, ES>
where
    E: Executor<EM, Z, ES> + HasObservers,
    EM: UsesState<State = E::State>,
    F: TestcaseScore<E::State>,
    M: Mutator<E::Input, E::State>,
    E::State: HasCorpus + HasMetadata + HasRand,
    Z: Evaluator<E, EM, State = E::State>,
    ES: HasExecutorState,
{
    /// Creates a new [`PowerMutationalStage`]
    pub fn new(mutator: M) -> Self {
        Self::transforming(mutator)
    }
}

impl<E, F, EM, I, M, Z, ES> PowerMutationalStage<E, F, EM, I, M, Z, ES>
where
    E: Executor<EM, Z, ES> + HasObservers,
    EM: UsesState<State = E::State>,
    F: TestcaseScore<E::State>,
    M: Mutator<I, E::State>,
    E::State: HasCorpus + HasMetadata + HasRand,
    Z: Evaluator<E, EM, State = E::State>,
    ES: HasExecutorState,
{
    /// Creates a new transforming [`PowerMutationalStage`]
    pub fn transforming(mutator: M) -> Self {
        Self {
            mutator,
            phantom: PhantomData,
        }
    }
}

/// The standard powerscheduling stage
pub type StdPowerMutationalStage<E, EM, I, M, Z, ES> =
    PowerMutationalStage<E, CorpusPowerTestcaseScore<<E as UsesState>::State>, EM, I, M, Z, ES>;
