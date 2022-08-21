//! The tracing stage can trace the target and enrich a testcase with metadata, for example for `CmpLog`.

use core::{fmt::Debug, marker::PhantomData};

#[cfg(feature = "introspection")]
use crate::monitors::PerfFeature;
use crate::{
    corpus::Corpus,
    executors::{Executor, HasObservers, ShadowExecutor},
    mark_feature_time,
    observers::ObserversTuple,
    stages::Stage,
    start_timer,
    state::{HasClientPerfMonitor, HasCorpus, HasExecutions},
    Error,
};

/// A stage that runs a tracer executor
#[derive(Clone, Debug)]
pub struct TracingStage<TE>
where
    TE: Executor + HasObservers,
{
    tracer_executor: TE,
}

impl<TE> Stage for TracingStage<TE>
where
    TE: Executor + HasObservers,
    Self::State: HasClientPerfMonitor + HasExecutions + HasCorpus,
{
    #[inline]
    fn perform(
        &mut self,
        fuzzer: &mut Self::Fuzzer,
        _executor: &mut Self::Executor,
        state: &mut Self::State,
        manager: &mut Self::EventManager,
        corpus_idx: usize,
    ) -> Result<(), Error> {
        start_timer!(state);
        let input = state
            .corpus()
            .get(corpus_idx)?
            .borrow_mut()
            .load_input()?
            .clone();
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

        *state.executions_mut() += 1;

        start_timer!(state);
        self.tracer_executor
            .observers_mut()
            .post_exec_all(state, &input, &exit_kind)?;
        mark_feature_time!(state, PerfFeature::PostExecObservers);

        Ok(())
    }
}

impl<TE> TracingStage<TE>
where
    TE: Executor + HasObservers,
    <Self as Stage>::State: HasClientPerfMonitor + HasExecutions + HasCorpus,
{
    /// Creates a new default stage
    pub fn new(tracer_executor: TE) -> Self {
        Self { tracer_executor }
    }

    /// Gets the underlying tracer executor
    pub fn executor(&self) -> &TE {
        &self.tracer_executor
    }
}

/// A stage that runs the shadow executor using also the shadow observers
#[derive(Clone, Debug)]
pub struct ShadowTracingStage<OT, SOT> {
    phantom: PhantomData<(OT, SOT)>,
}

impl<OT, SOT> Stage for ShadowTracingStage<OT, SOT>
where
    Self: Stage<Executor = ShadowExecutor<Self::Executor, SOT>>,
    Self::Executor: Executor<Input = Self::Input, State = Self::State>,
    Self::Executor: Executor + HasObservers,
    OT: ObserversTuple,
    SOT: ObserversTuple,
    Self::State: HasClientPerfMonitor + HasExecutions + HasCorpus + Debug,
{
    #[inline]
    fn perform(
        &mut self,
        fuzzer: &mut Self::Fuzzer,
        executor: &mut ShadowExecutor<Self::Executor, SOT>,
        state: &mut Self::State,
        manager: &mut Self::EventManager,
        corpus_idx: usize,
    ) -> Result<(), Error> {
        start_timer!(state);
        let input = state
            .corpus()
            .get(corpus_idx)?
            .borrow_mut()
            .load_input()?
            .clone();
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

        *state.executions_mut() += 1;

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
}

impl<OT, SOT> ShadowTracingStage<OT, SOT>
where
    OT: ObserversTuple,
    SOT: ObserversTuple,
    <Self as Stage>::State: HasClientPerfMonitor + HasExecutions + HasCorpus,
{
    /// Creates a new default stage
    pub fn new(_executor: &mut ShadowExecutor<<Self as Stage>::Executor, SOT>) -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}
