//! The power schedules. This stage should be invoked after the calibration stage.

use alloc::{
    borrow::{Cow, ToOwned},
    string::ToString,
};
use core::{fmt::Debug, marker::PhantomData};

use libafl_bolts::Named;

#[cfg(feature = "introspection")]
use crate::monitors::PerfFeature;
use crate::{
    corpus::{Corpus, HasCurrentCorpusId},
    executors::{Executor, HasObservers},
    fuzzer::Evaluator,
    inputs::{Input, UsesInput},
    mark_feature_time,
    mutators::{MutationResult, Mutator},
    schedulers::{testcase_score::CorpusPowerTestcaseScore, TestcaseScore},
    stages::{
        mutational::{MutatedTransform, MutatedTransformPost},
        MutationalStage, RetryCountRestartHelper, Stage,
    },
    start_timer,
    state::{
        HasCorpus, HasCurrentTestcase, HasExecutions, HasRand, MaybeHasClientPerfMonitor, UsesState,
    },
    Error, HasMetadata, HasNamedMetadata,
};

/// The unique id for this stage
static mut POWER_MUTATIONAL_STAGE_ID: usize = 0;
/// Default name for `PowerMutationalStage`; derived from AFL++
pub const POWER_MUTATIONAL_STAGE_NAME: &str = "power";
/// The mutational stage using power schedules
#[derive(Clone, Debug)]
pub struct PowerMutationalStage<E, F, EM, I, M, S, Z> {
    name: Cow<'static, str>,
    /// The mutators we use
    mutator: M,
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(E, F, EM, I, S, Z)>,
}

impl<E, F, EM, I, M, S, Z> Named for PowerMutationalStage<E, F, EM, I, M, S, Z> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<E, F, EM, I, M, S, Z> MutationalStage<S> for PowerMutationalStage<E, F, EM, I, M, S, Z>
where
    S: HasCurrentTestcase,
    F: TestcaseScore<S>,
{
    type Mutator = M;
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
    fn iterations(&self, state: &mut S) -> Result<usize, Error> {
        // Update handicap
        let mut testcase = state.current_testcase_mut()?;
        let score = F::compute(state, &mut testcase)? as usize;

        Ok(score)
    }
}

impl<E, F, EM, I, M, S, Z> Stage<E, EM, S, Z> for PowerMutationalStage<E, F, EM, I, M, S, Z>
where
    E: Executor<EM, Z, State = S> + HasObservers,
    EM: UsesState<State = S>,
    F: TestcaseScore<S>,
    M: Mutator<I, S>,
    S: HasCorpus
        + HasMetadata
        + HasRand
        + HasExecutions
        + HasNamedMetadata
        + HasCurrentTestcase
        + HasCurrentCorpusId
        + MaybeHasClientPerfMonitor
        + UsesInput<Input = <S::Corpus as Corpus>::Input>,
    Z: Evaluator<E, EM, State = S>,
    I: MutatedTransform<<S::Corpus as Corpus>::Input, S> + Clone + Input,
    <S::Corpus as Corpus>::Input: Input,
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

impl<E, F, EM, I, M, S, Z> PowerMutationalStage<E, F, EM, I, M, S, Z>
where
    E: Executor<EM, Z, State = S> + HasObservers,
    EM: UsesState<State = S>,
    F: TestcaseScore<S>,
    I: Input,
    M: Mutator<I, S>,
    S: HasCorpus
        + HasMetadata
        + HasRand
        + HasCurrentTestcase
        + MaybeHasClientPerfMonitor
        + UsesInput<Input = <S::Corpus as Corpus>::Input>,
    I: MutatedTransform<<S::Corpus as Corpus>::Input, S> + Clone + Input,
    Z: Evaluator<E, EM, State = S>,
    <S::Corpus as Corpus>::Input: Input,
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

    /// Runs this (mutational) stage for the given testcase
    #[allow(clippy::cast_possible_wrap)] // more than i32 stages on 32 bit system - highly unlikely...
    fn perform_mutational(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<(), Error> {
        start_timer!(state);

        // Here saturating_sub is needed as self.iterations() might be actually smaller than the previous value before reset.
        /*
        let num = self
            .iterations(state)?
            .saturating_sub(self.execs_since_progress_start(state)?);
        */
        let num = self.iterations(state)?;
        let mut testcase = state.current_testcase_mut()?;

        let Ok(input) = I::try_transform_from(&mut testcase, state) else {
            return Ok(());
        };
        drop(testcase);
        mark_feature_time!(state, PerfFeature::GetInputFromCorpus);

        for _ in 0..num {
            let mut input = input.clone();

            start_timer!(state);
            let mutated = self.mutator_mut().mutate(state, &mut input)?;
            mark_feature_time!(state, PerfFeature::Mutate);

            if mutated == MutationResult::Skipped {
                continue;
            }

            // Time is measured directly the `evaluate_input` function
            let (untransformed, post) = input.try_transform_into(state)?;
            let (_, corpus_id) = fuzzer.evaluate_input(state, executor, manager, untransformed)?;

            start_timer!(state);
            self.mutator_mut().post_exec(state, corpus_id)?;
            post.post_exec(state, corpus_id)?;
            mark_feature_time!(state, PerfFeature::MutatePostExec);
        }

        Ok(())
    }
}

/// The standard powerscheduling stage
pub type StdPowerMutationalStage<E, EM, I, M, S, Z> =
    PowerMutationalStage<E, CorpusPowerTestcaseScore, EM, I, M, S, Z>;
