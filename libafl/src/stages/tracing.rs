//! The tracing stage can trace the target and enrich a testcase with metadata, for example for `CmpLog`.

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
    executors::{Executor, HasObservers, ShadowExecutor},
    inputs::{Input, UsesInput},
    mark_feature_time,
    observers::ObserversTuple,
    stages::{RetryCountRestartHelper, Stage},
    start_timer,
    state::{HasCorpus, HasCurrentTestcase, HasExecutions, MaybeHasClientPerfMonitor, UsesState},
    Error, HasNamedMetadata,
};

/// A stage that runs a tracer executor
#[derive(Clone, Debug)]
pub struct TracingStage<EM, TE, S, Z> {
    name: Cow<'static, str>,
    tracer_executor: TE,
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(EM, TE, S, Z)>,
}

impl<EM, TE, S, Z> TracingStage<EM, TE, S, Z>
where
    TE: Executor<EM, Z, State = S> + HasObservers,
    TE::Observers: ObserversTuple<<S::Corpus as Corpus>::Input, S>,
    S: HasExecutions
        + HasCorpus
        + HasNamedMetadata
        + HasCurrentTestcase
        + MaybeHasClientPerfMonitor
        + UsesInput<Input = <S::Corpus as Corpus>::Input>,
    EM: UsesState<State = S>, //delete me
    Z: UsesState<State = S>,  //delete me
{
    #[allow(rustdoc::broken_intra_doc_links)]
    /// Perform tracing on the given `CorpusId`. Useful for if wrapping [`TracingStage`] with your
    /// own stage and you need to manage [`super::NestedStageRetryCountRestartHelper`] differently
    /// see [`super::ConcolicTracingStage`]'s implementation as an example of usage.
    pub fn trace(&mut self, fuzzer: &mut Z, state: &mut S, manager: &mut EM) -> Result<(), Error> {
        start_timer!(state);
        let input = state.current_input_cloned()?;

        mark_feature_time!(state, PerfFeature::GetInputFromCorpus);

        start_timer!(state);
        self.tracer_executor
            .observers_mut()
            .pre_exec_all(state, &input)?;
        mark_feature_time!(state, PerfFeature::PreExecObservers);

        start_timer!(state);
        let exit_kind = self
            .tracer_executor
            .run_target(fuzzer, state, manager, &input)?;
        mark_feature_time!(state, PerfFeature::TargetExecution);

        start_timer!(state);
        self.tracer_executor
            .observers_mut()
            .post_exec_all(state, &input, &exit_kind)?;
        mark_feature_time!(state, PerfFeature::PostExecObservers);

        Ok(())
    }
}

impl<E, EM, TE, S, Z> Stage<E, EM, S, Z> for TracingStage<EM, TE, S, Z>
where
    TE: Executor<EM, Z, State = S> + HasObservers,
    TE::Observers: ObserversTuple<<S::Corpus as Corpus>::Input, S>,
    S: HasExecutions
        + HasCorpus
        + HasNamedMetadata
        + HasCurrentCorpusId
        + MaybeHasClientPerfMonitor
        + UsesInput<Input = <S::Corpus as Corpus>::Input>,
    EM: UsesState<State = S>,
    Z: UsesState<State = S>,
    <S::Corpus as Corpus>::Input: Input,
{
    #[inline]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        _executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<(), Error> {
        self.trace(fuzzer, state, manager)
    }

    fn should_restart(&mut self, state: &mut S) -> Result<bool, Error> {
        RetryCountRestartHelper::no_retry(state, &self.name)
    }

    fn clear_progress(&mut self, state: &mut S) -> Result<(), Error> {
        RetryCountRestartHelper::clear_progress(state, &self.name)
    }
}

impl<EM, TE, S, Z> Named for TracingStage<EM, TE, S, Z> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

/// The counter for giving this stage unique id
static mut TRACING_STAGE_ID: usize = 0;
/// The name for tracing stage
pub static TRACING_STAGE_NAME: &str = "tracing";

impl<EM, TE, S, Z> TracingStage<EM, TE, S, Z> {
    /// Creates a new default stage
    pub fn new(tracer_executor: TE) -> Self {
        // unsafe but impossible that you create two threads both instantiating this instance
        let stage_id = unsafe {
            let ret = TRACING_STAGE_ID;
            TRACING_STAGE_ID += 1;
            ret
        };

        Self {
            name: Cow::Owned(TRACING_STAGE_NAME.to_owned() + ":" + stage_id.to_string().as_ref()),
            tracer_executor,
            phantom: PhantomData,
        }
    }

    /// Gets the underlying tracer executor
    pub fn executor(&self) -> &TE {
        &self.tracer_executor
    }

    /// Gets the underlying tracer executor (mut)
    pub fn executor_mut(&mut self) -> &mut TE {
        &mut self.tracer_executor
    }
}

/// A stage that runs the shadow executor using also the shadow observers
#[derive(Clone, Debug)]
pub struct ShadowTracingStage<E, EM, SOT, S, Z> {
    name: Cow<'static, str>,
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(E, EM, SOT, S, Z)>,
}

/// The counter for giving this stage unique id
static mut SHADOW_TRACING_STAGE_ID: usize = 0;
/// Name for shadow tracing stage
pub static SHADOW_TRACING_STAGE_NAME: &str = "shadow";

impl<E, EM, SOT, S, Z> Named for ShadowTracingStage<E, EM, SOT, S, Z> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<E, EM, SOT, S, Z> Stage<ShadowExecutor<E, SOT>, EM, S, Z>
    for ShadowTracingStage<E, EM, SOT, S, Z>
where
    E: Executor<EM, Z, State = S> + HasObservers,
    E::Observers: ObserversTuple<<S::Corpus as Corpus>::Input, S>,
    SOT: ObserversTuple<<S::Corpus as Corpus>::Input, S>,
    S: HasExecutions
        + HasCorpus
        + HasNamedMetadata
        + Debug
        + HasCurrentTestcase
        + HasCurrentCorpusId
        + MaybeHasClientPerfMonitor
        + UsesInput<Input = <S::Corpus as Corpus>::Input>,
    EM: UsesState<State = S>,
    Z: UsesState<State = S>,
{
    #[inline]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut ShadowExecutor<E, SOT>,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<(), Error> {
        start_timer!(state);
        let input = state.current_input_cloned()?;

        mark_feature_time!(state, PerfFeature::GetInputFromCorpus);

        start_timer!(state);
        executor
            .shadow_observers_mut()
            .pre_exec_all(state, &input)?;
        executor.observers_mut().pre_exec_all(state, &input)?;
        mark_feature_time!(state, PerfFeature::PreExecObservers);

        start_timer!(state);
        let exit_kind = executor.run_target(fuzzer, state, manager, &input)?;
        mark_feature_time!(state, PerfFeature::TargetExecution);

        start_timer!(state);
        executor
            .shadow_observers_mut()
            .post_exec_all(state, &input, &exit_kind)?;
        executor
            .observers_mut()
            .post_exec_all(state, &input, &exit_kind)?;
        mark_feature_time!(state, PerfFeature::PostExecObservers);

        Ok(())
    }

    fn should_restart(&mut self, state: &mut S) -> Result<bool, Error> {
        RetryCountRestartHelper::no_retry(state, &self.name)
    }

    fn clear_progress(&mut self, state: &mut S) -> Result<(), Error> {
        RetryCountRestartHelper::clear_progress(state, &self.name)
    }
}

impl<E, EM, SOT, S, Z> ShadowTracingStage<E, EM, SOT, S, Z>
where
    E: Executor<EM, Z, State = Z::State> + HasObservers,
    S: HasExecutions + HasCorpus,
    SOT: ObserversTuple<<S::Corpus as Corpus>::Input, S>,
    EM: UsesState<State = Z::State>,
    Z: UsesState,
{
    /// Creates a new default stage
    pub fn new(_executor: &mut ShadowExecutor<E, SOT>) -> Self {
        // unsafe but impossible that you create two threads both instantiating this instance
        let stage_id = unsafe {
            let ret = SHADOW_TRACING_STAGE_ID;
            SHADOW_TRACING_STAGE_ID += 1;
            ret
        };
        Self {
            name: Cow::Owned(
                SHADOW_TRACING_STAGE_NAME.to_owned() + ":" + stage_id.to_string().as_str(),
            ),
            phantom: PhantomData,
        }
    }
}
