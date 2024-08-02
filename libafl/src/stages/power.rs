//! The power schedules. This stage should be invoked after the calibration stage.

use alloc::{
    borrow::{Cow, ToOwned},
    string::ToString,
};
use core::{fmt::Debug, marker::PhantomData};

use libafl_bolts::Named;

use crate::{
    corpus::{Corpus, HasCorpus, HasCurrentCorpusId},
    mutators::Mutator,
    schedulers::{testcase_score::CorpusPowerTestcaseScore, TestcaseScore},
    stages::{perform_mutational, MutationalStage, RetryCountRestartHelper, Stage},
    state::HasCurrentTestcase,
    Error, Evaluator, HasNamedMetadata,
};

/// The unique id for this stage
static mut POWER_MUTATIONAL_STAGE_ID: usize = 0;
/// Default name for `PowerMutationalStage`; derived from AFL++
pub const POWER_MUTATIONAL_STAGE_NAME: &str = "power";
/// The mutational stage using power schedules
#[derive(Clone, Debug)]
pub struct PowerMutationalStage<F, M> {
    name: Cow<'static, str>,
    /// The mutators we use
    mutator: M,
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<F>,
}

impl<F, M> Named for PowerMutationalStage<F, M> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<F, M> MutationalStage for PowerMutationalStage<F, M> {
    type M = M;

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
}

impl<E, F, EM, M, S, Z> Stage<E, EM, S, Z> for PowerMutationalStage<F, M>
where
    S: HasCorpus + HasCurrentCorpusId + HasNamedMetadata,
    F: TestcaseScore<S>,
    Z: Evaluator<E, EM, <S::Corpus as Corpus>::Input, S>,
    <S::Corpus as Corpus>::Input: Clone,
    M: Mutator<<S::Corpus as Corpus>::Input, S>,
{
    #[inline]
    #[allow(clippy::let_and_return)]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<(), Error> {
        let iter = self.iterations(state)?;
        let mutator = self.mutator_mut();
        let ret = perform_mutational(fuzzer, executor, state, manager, mutator, iter);
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

impl<F, M> PowerMutationalStage<F, M> {
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

    /// Gets the number of iterations as a random number
    #[allow(clippy::cast_sign_loss)]
    fn iterations<S>(&self, state: &mut S) -> Result<usize, Error>
    where
        S: HasCorpus + HasCurrentCorpusId,
        F: TestcaseScore<S>,
    {
        // Update handicap
        let mut testcase = state.current_testcase_mut()?;
        let score = F::compute(state, &mut testcase)? as usize;

        Ok(score)
    }
}

/// The standard powerscheduling stage
pub type StdPowerMutationalStage<M> = PowerMutationalStage<CorpusPowerTestcaseScore, M>;
