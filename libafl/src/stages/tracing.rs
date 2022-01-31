//! The tracing stage can trace the target and enrich a testcase with metadata, for example for `CmpLog`.

use core::{fmt::Debug, marker::PhantomData};

use crate::{
    corpus::Corpus,
    executors::{Executor, HasObservers, ShadowExecutor},
    inputs::Input,
    mark_feature_time,
    observers::ObserversTuple,
    stages::Stage,
    start_timer,
    state::{HasClientPerfMonitor, HasCorpus, HasExecutions},
    Error,
};

#[cfg(feature = "introspection")]
use crate::monitors::PerfFeature;

/// A stage that runs a tracer executor
#[derive(Clone, Debug)]
pub struct TracingStage<EM, I, OT, S, TE, Z>
where
    I: Input,
    TE: Executor<EM, I, S, Z> + HasObservers<I, OT, S>,
    OT: ObserversTuple<I, S>,
    S: HasClientPerfMonitor + HasExecutions + HasCorpus<I>,
{
    tracer_executor: TE,
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(EM, I, OT, S, TE, Z)>,
}

impl<E, EM, I, OT, S, TE, Z> Stage<E, EM, S, Z> for TracingStage<EM, I, OT, S, TE, Z>
where
    I: Input,
    TE: Executor<EM, I, S, Z> + HasObservers<I, OT, S>,
    OT: ObserversTuple<I, S>,
    S: HasClientPerfMonitor + HasExecutions + HasCorpus<I>,
{
    #[inline]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        _executor: &mut E,
        state: &mut S,
        manager: &mut EM,
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

impl<EM, I, OT, S, TE, Z> TracingStage<EM, I, OT, S, TE, Z>
where
    I: Input,
    TE: Executor<EM, I, S, Z> + HasObservers<I, OT, S>,
    OT: ObserversTuple<I, S>,
    S: HasClientPerfMonitor + HasExecutions + HasCorpus<I>,
{
    /// Creates a new default stage
    pub fn new(tracer_executor: TE) -> Self {
        Self {
            tracer_executor,
            phantom: PhantomData,
        }
    }

    /// Gets the underlying tracer executor
    pub fn executor(&self) -> &TE {
        &self.tracer_executor
    }
}

/// A stage that runs the shadow executor using also the shadow observers
#[derive(Clone, Debug)]
pub struct ShadowTracingStage<E, EM, I, OT, S, SOT, Z> {
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(E, EM, I, OT, S, SOT, Z)>,
}

impl<E, EM, I, OT, S, SOT, Z> Stage<ShadowExecutor<E, I, S, SOT>, EM, S, Z>
    for ShadowTracingStage<E, EM, I, OT, S, SOT, Z>
where
    I: Input,
    E: Executor<EM, I, S, Z> + HasObservers<I, OT, S>,
    OT: ObserversTuple<I, S>,
    SOT: ObserversTuple<I, S>,
    S: HasClientPerfMonitor + HasExecutions + HasCorpus<I> + Debug,
{
    #[inline]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut ShadowExecutor<E, I, S, SOT>,
        state: &mut S,
        manager: &mut EM,
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

impl<E, EM, I, OT, S, SOT, Z> ShadowTracingStage<E, EM, I, OT, S, SOT, Z>
where
    I: Input,
    E: Executor<EM, I, S, Z> + HasObservers<I, OT, S>,
    OT: ObserversTuple<I, S>,
    SOT: ObserversTuple<I, S>,
    S: HasClientPerfMonitor + HasExecutions + HasCorpus<I>,
{
    /// Creates a new default stage
    pub fn new(_executor: &mut ShadowExecutor<E, I, S, SOT>) -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}
