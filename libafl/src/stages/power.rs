//! The power schedules. This stage should be invoked after the calibration stage.

use core::{fmt::Debug, marker::PhantomData};

use crate::{
    executors::{Executor, HasObservers},
    fuzzer::Evaluator,
    mutators::Mutator,
    schedulers::{testcase_score::CorpusPowerTestcaseScore, TestcaseScore},
    stages::{mutational::MutatedTransform, ExecutionCountRestartHelper, MutationalStage, Stage},
    state::{HasCorpus, HasCurrentTestcase, HasExecutions, HasMetadata, HasRand, UsesState},
    Error,
};

/// The mutational stage using power schedules
#[derive(Clone, Debug)]
pub struct PowerMutationalStage<E, F, EM, I, M, Z> {
    /// The mutators we use
    mutator: M,
    /// Helper for restarts
    restart_helper: ExecutionCountRestartHelper,
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(E, F, EM, I, Z)>,
}

impl<E, F, EM, I, M, Z> UsesState for PowerMutationalStage<E, F, EM, I, M, Z>
where
    E: UsesState,
{
    type State = E::State;
}

impl<E, F, EM, I, M, Z> MutationalStage<E, EM, I, M, Z> for PowerMutationalStage<E, F, EM, I, M, Z>
where
    E: Executor<EM, Z> + HasObservers,
    EM: UsesState<State = E::State>,
    F: TestcaseScore<E::State>,
    M: Mutator<I, E::State>,
    E::State: HasCorpus + HasMetadata + HasRand + HasExecutions,
    Z: Evaluator<E, EM, State = E::State>,
    I: MutatedTransform<E::Input, E::State> + Clone,
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
    fn iterations(&self, state: &mut E::State) -> Result<u64, Error> {
        // Update handicap
        let mut testcase = state.current_testcase_mut()?;
        let score = F::compute(state, &mut testcase)? as u64;

        Ok(score)
    }

    fn execs_since_progress_start(&mut self, state: &mut <Z>::State) -> Result<u64, Error> {
        self.restart_helper.execs_since_progress_start(state)
    }
}

impl<E, F, EM, I, M, Z> Stage<E, EM, Z> for PowerMutationalStage<E, F, EM, I, M, Z>
where
    E: Executor<EM, Z> + HasObservers,
    EM: UsesState<State = E::State>,
    F: TestcaseScore<E::State>,
    M: Mutator<I, E::State>,
    E::State: HasCorpus + HasMetadata + HasRand + HasExecutions,
    Z: Evaluator<E, EM, State = E::State>,
    I: MutatedTransform<E::Input, E::State> + Clone,
{
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

    fn restart_progress_should_run(&mut self, state: &mut Self::State) -> Result<bool, Error> {
        self.restart_helper.restart_progress_should_run(state)
    }

    fn clear_restart_progress(&mut self, state: &mut Self::State) -> Result<(), Error> {
        self.restart_helper.clear_restart_progress(state)
    }
}

impl<E, F, EM, M, Z> PowerMutationalStage<E, F, EM, E::Input, M, Z>
where
    E: Executor<EM, Z> + HasObservers,
    EM: UsesState<State = E::State>,
    F: TestcaseScore<E::State>,
    M: Mutator<E::Input, E::State>,
    E::State: HasCorpus + HasMetadata + HasRand,
    Z: Evaluator<E, EM, State = E::State>,
{
    /// Creates a new [`PowerMutationalStage`]
    pub fn new(mutator: M) -> Self {
        Self::transforming(mutator)
    }
}

impl<E, F, EM, I, M, Z> PowerMutationalStage<E, F, EM, I, M, Z>
where
    E: Executor<EM, Z> + HasObservers,
    EM: UsesState<State = E::State>,
    F: TestcaseScore<E::State>,
    M: Mutator<I, E::State>,
    E::State: HasCorpus + HasMetadata + HasRand,
    Z: Evaluator<E, EM, State = E::State>,
{
    /// Creates a new transforming [`PowerMutationalStage`]
    pub fn transforming(mutator: M) -> Self {
        Self {
            mutator,
            phantom: PhantomData,
            restart_helper: ExecutionCountRestartHelper::default(),
        }
    }
}

/// The standard powerscheduling stage
pub type StdPowerMutationalStage<E, EM, I, M, Z> =
    PowerMutationalStage<E, CorpusPowerTestcaseScore<<E as UsesState>::State>, EM, I, M, Z>;
