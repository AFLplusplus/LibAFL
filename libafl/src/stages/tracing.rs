//! The tracing stage can trace the target and enrich a testcase with metadata, for example for `CmpLog`.

use alloc::string::{String, ToString};
use core::{fmt::Debug, marker::PhantomData};

#[cfg(feature = "introspection")]
use crate::monitors::PerfFeature;
use crate::{
    bolts::tuples::MatchName,
    corpus::{Corpus, CorpusId},
    executors::{Executor, HasObservers, ShadowExecutor},
    inputs::{BytesInput, UsesInput},
    mark_feature_time,
    observers::{AFLppStdCmpObserver, ObserversTuple},
    stages::{colorization::TaintMetadata, Stage},
    start_timer,
    state::{HasClientPerfMonitor, HasCorpus, HasExecutions, HasMetadata, State, UsesState},
    Error,
};

/// A stage that runs a tracer executor
#[derive(Clone, Debug)]
pub struct TracingStage<EM, TE, Z> {
    tracer_executor: TE,
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(EM, TE, Z)>,
}

impl<EM, TE, Z> UsesState for TracingStage<EM, TE, Z>
where
    TE: UsesState,
{
    type State = TE::State;
}

impl<E, EM, TE, Z> Stage<E, EM, Z> for TracingStage<EM, TE, Z>
where
    E: UsesState<State = TE::State>,
    TE: Executor<EM, Z> + HasObservers,
    TE::State: HasClientPerfMonitor + HasExecutions + HasCorpus,
    EM: UsesState<State = TE::State>,
    Z: UsesState<State = TE::State>,
{
    #[inline]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        _executor: &mut E,
        state: &mut TE::State,
        manager: &mut EM,
        corpus_idx: CorpusId,
    ) -> Result<(), Error> {
        start_timer!(state);
        let input = state.corpus().cloned_input_for_id(corpus_idx)?;

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

impl<EM, TE, Z> TracingStage<EM, TE, Z> {
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

    /// Gets the underlying tracer executor (mut)
    pub fn executor_mut(&mut self) -> &mut TE {
        &mut self.tracer_executor
    }
}

/// Trace with tainted input
#[derive(Clone, Debug)]
pub struct AFLppCmplogTracingStage<EM, TE, Z> {
    tracer_executor: TE,
    cmplog_observer_name: Option<String>,
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(EM, TE, Z)>,
}

impl<EM, TE, Z> UsesState for AFLppCmplogTracingStage<EM, TE, Z>
where
    TE: UsesState,
{
    type State = TE::State;
}

impl<E, EM, TE, Z> Stage<E, EM, Z> for AFLppCmplogTracingStage<EM, TE, Z>
where
    E: UsesState<State = TE::State>,
    TE: Executor<EM, Z> + HasObservers,
    TE::State: HasClientPerfMonitor
        + HasExecutions
        + HasCorpus
        + HasMetadata
        + UsesInput<Input = BytesInput>,
    EM: UsesState<State = TE::State>,
    Z: UsesState<State = TE::State>,
{
    #[inline]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        _executor: &mut E,
        state: &mut TE::State,
        manager: &mut EM,
        corpus_idx: CorpusId,
    ) -> Result<(), Error> {
        // First run with the un-mutated input

        let unmutated_input = state.corpus().cloned_input_for_id(corpus_idx)?;

        if let Some(name) = &self.cmplog_observer_name {
            if let Some(ob) = self
                .tracer_executor
                .observers_mut()
                .match_name_mut::<AFLppStdCmpObserver<TE::State>>(name)
            {
                // This is not the original input,
                // Set it to false
                ob.set_original(true);
            }
            // I can't think of any use of this stage if you don't use AFLStdCmpObserver
            // but do nothing ofcourse
        }

        self.tracer_executor
            .observers_mut()
            .pre_exec_all(state, &unmutated_input)?;

        let exit_kind =
            self.tracer_executor
                .run_target(fuzzer, state, manager, &unmutated_input)?;

        *state.executions_mut() += 1;

        self.tracer_executor
            .observers_mut()
            .post_exec_all(state, &unmutated_input, &exit_kind)?;

        // Second run with the mutated input
        let mutated_input = match state.metadata_map().get::<TaintMetadata>() {
            Some(meta) => BytesInput::from(meta.input_vec().as_ref()),
            None => return Err(Error::unknown("No metadata found")),
        };

        if let Some(name) = &self.cmplog_observer_name {
            if let Some(ob) = self
                .tracer_executor
                .observers_mut()
                .match_name_mut::<AFLppStdCmpObserver<TE::State>>(name)
            {
                // This is not the original input,
                // Set it to false
                ob.set_original(false);
            }
            // I can't think of any use of this stage if you don't use AFLStdCmpObserver
            // but do nothing ofcourse
        }

        self.tracer_executor
            .observers_mut()
            .pre_exec_all(state, &mutated_input)?;

        let exit_kind = self
            .tracer_executor
            .run_target(fuzzer, state, manager, &mutated_input)?;

        *state.executions_mut() += 1;

        self.tracer_executor
            .observers_mut()
            .post_exec_all(state, &mutated_input, &exit_kind)?;

        Ok(())
    }
}

impl<EM, TE, Z> AFLppCmplogTracingStage<EM, TE, Z> {
    /// Creates a new default stage
    pub fn new(tracer_executor: TE) -> Self {
        Self {
            cmplog_observer_name: None,
            tracer_executor,
            phantom: PhantomData,
        }
    }

    /// With cmplog observer
    pub fn with_cmplog_observer_name(tracer_executor: TE, name: &'static str) -> Self {
        Self {
            cmplog_observer_name: Some(name.to_string()),
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
pub struct ShadowTracingStage<E, EM, SOT, Z> {
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(E, EM, SOT, Z)>,
}

impl<E, EM, SOT, Z> UsesState for ShadowTracingStage<E, EM, SOT, Z>
where
    E: UsesState,
{
    type State = E::State;
}

impl<E, EM, SOT, Z> Stage<ShadowExecutor<E, SOT>, EM, Z> for ShadowTracingStage<E, EM, SOT, Z>
where
    E: Executor<EM, Z> + HasObservers,
    EM: UsesState<State = E::State>,
    SOT: ObserversTuple<E::State>,
    Z: UsesState<State = E::State>,
    E::State: State + HasClientPerfMonitor + HasExecutions + HasCorpus + Debug,
{
    #[inline]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut ShadowExecutor<E, SOT>,
        state: &mut E::State,
        manager: &mut EM,
        corpus_idx: CorpusId,
    ) -> Result<(), Error> {
        start_timer!(state);
        let input = state.corpus().cloned_input_for_id(corpus_idx)?;

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

impl<E, EM, SOT, Z> ShadowTracingStage<E, EM, SOT, Z>
where
    E: Executor<EM, Z> + HasObservers,
    E::State: State + HasClientPerfMonitor + HasExecutions + HasCorpus,
    EM: UsesState<State = E::State>,
    SOT: ObserversTuple<E::State>,
    Z: UsesState<State = E::State>,
{
    /// Creates a new default stage
    pub fn new(_executor: &mut ShadowExecutor<E, SOT>) -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}
