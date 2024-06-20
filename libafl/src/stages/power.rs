//! The power schedules. This stage should be invoked after the calibration stage.

use alloc::{
    borrow::{Cow, ToOwned},
    string::ToString,
};
use core::{fmt::Debug, marker::PhantomData};

use libafl_bolts::Named;

use crate::{
    executors::{Executor, HasObservers},
    fuzzer::Evaluator,
    mutators::Mutator,
    schedulers::{testcase_score::CorpusPowerTestcaseScore, TestcaseScore},
    stages::{mutational::MutatedTransform, MutationalStage, Stage, StdRestartHelper},
    state::{HasCorpus, HasCurrentTestcase, HasExecutions, HasRand, UsesState},
    Error, HasMetadata, HasNamedMetadata,
};

/// The unique id for this stage
static mut POWER_MUTATIONAL_STAGE_ID: usize = 0;
/// Default name for `PowerMutationalStage`; derived from AFL++
pub const POWER_MUTATIONAL_STAGE_NAME: &str = "power";
/// The mutational stage using power schedules
#[derive(Clone, Debug)]
pub struct PowerMutationalStage<E, F, EM, I, M, Z> {
    name: Cow<'static, str>,
    /// The mutators we use
    mutator: M,
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(E, F, EM, I, Z)>,
}

impl<E, F, EM, I, M, Z> UsesState for PowerMutationalStage<E, F, EM, I, M, Z>
where
    E: UsesState,
{
    type State = E::State;
}

impl<E, F, EM, I, M, Z> Named for PowerMutationalStage<E, F, EM, I, M, Z> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<E, F, EM, I, M, Z> MutationalStage<E, EM, I, M, Z> for PowerMutationalStage<E, F, EM, I, M, Z>
where
    E: Executor<EM, Z> + HasObservers,
    EM: UsesState<State = Self::State>,
    F: TestcaseScore<Self::State>,
    M: Mutator<I, Self::State>,
    Self::State: HasCorpus + HasMetadata + HasRand + HasExecutions + HasNamedMetadata,
    Z: Evaluator<E, EM, State = Self::State>,
    I: MutatedTransform<E::Input, Self::State> + Clone,
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
    fn iterations(&self, state: &mut Self::State) -> Result<usize, Error> {
        // Update handicap
        let mut testcase = state.current_testcase_mut()?;
        let score = F::compute(state, &mut testcase)? as usize;

        Ok(score)
    }
}

impl<E, F, EM, I, M, Z> Stage<E, EM, Z> for PowerMutationalStage<E, F, EM, I, M, Z>
where
    E: Executor<EM, Z> + HasObservers,
    EM: UsesState<State = Self::State>,
    F: TestcaseScore<Self::State>,
    M: Mutator<I, Self::State>,
    Self::State: HasCorpus + HasMetadata + HasRand + HasExecutions + HasNamedMetadata,
    Z: Evaluator<E, EM, State = Self::State>,
    I: MutatedTransform<Self::Input, Self::State> + Clone,
{
    #[inline]
    #[allow(clippy::let_and_return)]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Self::State,
        manager: &mut EM,
    ) -> Result<(), Error> {
        let ret = self.perform_mutational(fuzzer, executor, state, manager);
        ret
    }

    fn should_restart(&mut self, state: &mut Self::State) -> Result<bool, Error> {
        // Make sure we don't get stuck crashing on a single testcase
        StdRestartHelper::should_restart(state, &self.name, 3)
    }

    fn clear_progress(&mut self, state: &mut Self::State) -> Result<(), Error> {
        StdRestartHelper::clear_progress(state, &self.name)
    }
}

impl<E, F, EM, M, Z> PowerMutationalStage<E, F, EM, E::Input, M, Z>
where
    E: Executor<EM, Z> + HasObservers,
    EM: UsesState<State = <Self as UsesState>::State>,
    F: TestcaseScore<<Self as UsesState>::State>,
    M: Mutator<E::Input, <Self as UsesState>::State>,
    <Self as UsesState>::State: HasCorpus + HasMetadata + HasRand,
    Z: Evaluator<E, EM, State = <Self as UsesState>::State>,
{
    /// Creates a new [`PowerMutationalStage`]
    pub fn new(mutator: M) -> Self {
        // unsafe but impossible that you create two threads both instantiating this instance
        let stage_id = unsafe {
            let ret = POWER_MUTATIONAL_STAGE_ID;
            POWER_MUTATIONAL_STAGE_ID += 1;
            ret
        };
        Self {
            name: Cow::Owned(
                POWER_MUTATIONAL_STAGE_NAME.to_owned() + ":" + stage_id.to_string().as_str(),
            ),
            mutator,
            phantom: PhantomData,
        }
    }
}

/// The standard powerscheduling stage
pub type StdPowerMutationalStage<E, EM, I, M, Z> =
    PowerMutationalStage<E, CorpusPowerTestcaseScore<<E as UsesState>::State>, EM, I, M, Z>;
