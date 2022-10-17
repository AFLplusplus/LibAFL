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
    state::{HasClientPerfMonitor, HasCorpus, HasExecutions, State},
    Error,
};

/// A stage that runs a tracer executor
#[derive(Clone, Debug)]
pub struct TracingStage<EM, OT, TE, Z>
where
    TE: Executor<EM, TE::State, Z> + HasObservers<Observers = OT>,
    OT: ObserversTuple<TE::State>,
    TE::State: HasClientPerfMonitor + HasExecutions + HasCorpus,
{
    tracer_executor: TE,
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(EM, OT, TE, Z)>,
}

impl<E, EM, OT, TE, Z> Stage<E, EM, TE::State, Z> for TracingStage<EM, OT, TE, Z>
where
    TE: Executor<EM, TE::State, Z> + HasObservers<Observers = OT>,
    OT: ObserversTuple<TE::State>,
    TE::State: HasClientPerfMonitor + HasExecutions + HasCorpus,
{
    #[inline]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        _executor: &mut E,
        state: &mut TE::State,
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

impl<EM, OT, TE, Z> TracingStage<EM, OT, TE, Z>
where
    TE: Executor<EM, TE::State, Z> + HasObservers<Observers = OT>,
    OT: ObserversTuple<TE::State>,
    TE::State: HasClientPerfMonitor + HasExecutions + HasCorpus,
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
pub struct ShadowTracingStage<E, EM, OT, SOT, Z> {
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(E, EM, OT, SOT, Z)>,
}

impl<E, EM, OT, SOT, Z> Stage<ShadowExecutor<E, SOT>, EM, E::State, Z>
    for ShadowTracingStage<E, EM, OT, SOT, Z>
where
    E: Executor<EM, E::State, Z> + HasObservers<Observers = OT>,
    OT: ObserversTuple<E::State>,
    SOT: ObserversTuple<E::State>,
    E::State: State + HasClientPerfMonitor + HasExecutions + HasCorpus + Debug,
{
    #[inline]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut ShadowExecutor<E, SOT>,
        state: &mut E::State,
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

impl<E, EM, OT, SOT, Z> ShadowTracingStage<E, EM, OT, SOT, Z>
where
    E: Executor<EM, E::State, Z> + HasObservers<Observers = OT>,
    OT: ObserversTuple<E::State>,
    E::State: State + HasClientPerfMonitor + HasExecutions + HasCorpus,
    SOT: ObserversTuple<E::State>,
{
    /// Creates a new default stage
    pub fn new(_executor: &mut ShadowExecutor<E, SOT>) -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}
