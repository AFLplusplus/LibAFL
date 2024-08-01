//! The power schedules. This stage should be invoked after the calibration stage.

use alloc::{
    borrow::{Cow, ToOwned},
    string::ToString,
};
use core::{fmt::Debug, marker::PhantomData};

use libafl_bolts::Named;

use crate::{
    schedulers::{testcase_score::CorpusPowerTestcaseScore, TestcaseScore},
    stages::{MutationalStage, RetryCountRestartHelper, Stage},
    state::{HasCurrentTestcase, HasRand},
    Error,
};

/// The unique id for this stage
static mut POWER_MUTATIONAL_STAGE_ID: usize = 0;
/// Default name for `PowerMutationalStage`; derived from AFL++
pub const POWER_MUTATIONAL_STAGE_NAME: &str = "power";
/// The mutational stage using power schedules
#[derive(Clone, Debug)]
pub struct PowerMutationalStage<F, I, M> {
    name: Cow<'static, str>,
    /// The mutators we use
    mutator: M,
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(F, I)>,
}

impl<F, I, M> Named for PowerMutationalStage<F, I, M> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<F, I, M, S> MutationalStage<S> for PowerMutationalStage<F, I, M>
where
    S: HasRand,
{
    type M = Self::M;
    type I = Self::I;

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
    fn iterations(&self, state: &mut S) -> Result<usize, Error> {
        // Update handicap
        let mut testcase = state.current_testcase_mut()?;
        let score = F::compute(state, &mut testcase)? as usize;

        Ok(score)
    }
}

impl<E, F, EM, I, M, S, Z> Stage<E, EM, S, Z> for PowerMutationalStage<F, I, M> {
    #[inline]
    #[allow(clippy::let_and_return)]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<(), Error> {
        let ret = self.perform_mutational(fuzzer, executor, state, manager);
        ret
    }

    fn should_restart(&mut self, state: &mut S) -> Result<bool, Error> {
        // Make sure we don't get stuck crashing on a single testcase
        RetryCountRestartHelper::should_restart(state, &self.name, 3)
    }

    fn clear_progress(&mut self, state: &mut S) -> Result<(), Error> {
        RetryCountRestartHelper::clear_progress(state, &self.name)
    }
}

impl<F, I, M> PowerMutationalStage<F, I, M> {
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
pub type StdPowerMutationalStage<I, M> = PowerMutationalStage<CorpusPowerTestcaseScore, I, M>;
