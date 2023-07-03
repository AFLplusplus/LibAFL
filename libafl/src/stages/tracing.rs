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
    state::{
        HasClientPerfMonitor, HasCorpus, HasCurrentStageInfo, HasExecutions, HasMetadata, State,
        UsesState,
    },
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
    TE::State: HasClientPerfMonitor + HasExecutions + HasCurrentStageInfo + HasCorpus,
    EM: UsesState<State = TE::State>,
    Z: UsesState<State = TE::State>,
{
    type Context = Self::Input;

    #[inline]
    fn init(
        &mut self,
        _fuzzer: &mut Z,
        _executor: &mut E,
        state: &mut Self::State,
        _manager: &mut EM,
        corpus_idx: CorpusId,
    ) -> Result<E::Input, Error> {
        start_timer!(state);
        let input = state.corpus().cloned_input_for_id(corpus_idx)?;

        mark_feature_time!(state, PerfFeature::GetInputFromCorpus);
        Ok(input)
    }

    #[inline]
    fn limit(&self) -> Result<usize, Error> {
        Ok(1)
    }

    #[inline]
    fn pre_exec(
        &mut self,
        _fuzzer: &mut Z,
        _executor: &mut E,
        state: &mut Self::State,
        _manager: &mut EM,
        input: E::Input,
        _index: usize,
    ) -> Result<(E::Input, bool), Error> {
        start_timer!(state);
        self.tracer_executor
            .observers_mut()
            .pre_exec_all(state, &input)?;
        mark_feature_time!(state, PerfFeature::PreExecObservers);
        Ok((input, true))
    }

    #[inline]
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        _executor: &mut E,
        state: &mut Self::State,
        manager: &mut EM,
        input: E::Input,
        _index: usize,
    ) -> Result<(E::Input, crate::executors::ExitKind), Error> {
        start_timer!(state);
        self.tracer_executor
            .pre_exec(fuzzer, state, manager, &input)?;
        let exit_kind = self
            .tracer_executor
            .run_target(fuzzer, state, manager, &input)?;
        self.tracer_executor
            .post_exec(fuzzer, state, manager, &input)?;
        mark_feature_time!(state, PerfFeature::TargetExecution);

        Ok((input, exit_kind))
    }

    #[inline]
    fn post_exec(
        &mut self,
        _fuzzer: &mut Z,
        _executor: &mut E,
        state: &mut Self::State,
        _manager: &mut EM,
        input: E::Input,
        _index: usize,
        exit_kind: crate::executors::ExitKind,
    ) -> Result<(E::Input, Option<usize>), Error> {
        *state.executions_mut() += 1;

        start_timer!(state);
        self.tracer_executor
            .observers_mut()
            .post_exec_all(state, &input, &exit_kind)?;
        mark_feature_time!(state, PerfFeature::PostExecObservers);
        Ok((input, None))
    }

    #[inline]
    fn deinit(
        &mut self,
        _fuzzer: &mut Z,
        _executor: &mut E,
        _state: &mut Self::State,
        _manager: &mut EM,
    ) -> Result<(), Error> {
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
        + HasCurrentStageInfo
        + HasCorpus
        + HasMetadata
        + UsesInput<Input = BytesInput>,
    EM: UsesState<State = TE::State>,
    Z: UsesState<State = TE::State>,
{
    type Context = Self::Input;

    #[inline]
    fn init(
        &mut self,
        _fuzzer: &mut Z,
        _executor: &mut E,
        state: &mut Self::State,
        _manager: &mut EM,
        corpus_idx: CorpusId,
    ) -> Result<E::Input, Error> {
        // First run with the un-mutated input

        let unmutated_input = state.corpus().cloned_input_for_id(corpus_idx)?;

        Ok(unmutated_input)
    }

    #[inline]
    fn limit(&self) -> Result<usize, Error> {
        Ok(2)
    }

    #[inline]
    fn pre_exec(
        &mut self,
        _fuzzer: &mut Z,
        _executor: &mut E,
        state: &mut Self::State,
        _manager: &mut EM,
        input: E::Input,
        index: usize,
    ) -> Result<(E::Input, bool), Error> {
        let input = if index == 1 {
            // Second run with the mutated input
            match state.metadata_map().get::<TaintMetadata>() {
                Some(meta) => BytesInput::from(meta.input_vec().as_ref()),
                None => return Err(Error::unknown("No metadata found")),
            }
        } else {
            input
        };
        if let Some(name) = &self.cmplog_observer_name {
            if let Some(ob) = self
                .tracer_executor
                .observers_mut()
                .match_name_mut::<AFLppStdCmpObserver<TE::State>>(name)
            {
                // This is not the original input,
                // Set it to false
                ob.set_original(index == 0);
            }
            // I can't think of any use of this stage if you don't use AFLStdCmpObserver
            // but do nothing ofcourse
        }
        self.tracer_executor
            .observers_mut()
            .pre_exec_all(state, &input)?;

        Ok((input, true))
    }

    #[inline]
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        _executor: &mut E,
        state: &mut Self::State,
        manager: &mut EM,
        input: E::Input,
        _index: usize,
    ) -> Result<(E::Input, crate::executors::ExitKind), Error> {
        self.tracer_executor
            .pre_exec(fuzzer, state, manager, &input)?;
        let exit_kind = self
            .tracer_executor
            .run_target(fuzzer, state, manager, &input)?;
        self.tracer_executor
            .post_exec(fuzzer, state, manager, &input)?;

        Ok((input, exit_kind))
    }

    #[inline]
    fn post_exec(
        &mut self,
        _fuzzer: &mut Z,
        _executor: &mut E,
        state: &mut Self::State,
        _manager: &mut EM,
        input: E::Input,
        _index: usize,
        exit_kind: crate::executors::ExitKind,
    ) -> Result<(E::Input, Option<usize>), Error> {
        *state.executions_mut() += 1;

        self.tracer_executor
            .observers_mut()
            .post_exec_all(state, &input, &exit_kind)?;

        Ok((input, None))
    }

    #[inline]
    fn deinit(
        &mut self,
        _fuzzer: &mut Z,
        _executor: &mut E,
        _state: &mut Self::State,
        _manager: &mut EM,
    ) -> Result<(), Error> {
        todo!()
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
    E::State:
        State + HasClientPerfMonitor + HasExecutions + HasCurrentStageInfo + HasCorpus + Debug,
{
    type Context = Self::Input;

    #[inline]
    fn init(
        &mut self,
        _fuzzer: &mut Z,
        _executor: &mut ShadowExecutor<E, SOT>,
        state: &mut Self::State,
        _manager: &mut EM,
        corpus_idx: CorpusId,
    ) -> Result<E::Input, Error> {
        start_timer!(state);
        let input = state.corpus().cloned_input_for_id(corpus_idx)?;
        mark_feature_time!(state, PerfFeature::GetInputFromCorpus);
        Ok(input)
    }

    #[inline]
    fn limit(&self) -> Result<usize, Error> {
        Ok(1)
    }

    #[inline]
    fn pre_exec(
        &mut self,
        _fuzzer: &mut Z,
        executor: &mut ShadowExecutor<E, SOT>,
        state: &mut Self::State,
        _manager: &mut EM,
        input: E::Input,
        _index: usize,
    ) -> Result<(E::Input, bool), Error> {
        start_timer!(state);
        executor
            .shadow_observers_mut()
            .pre_exec_all(state, &input)?;
        executor.observers_mut().pre_exec_all(state, &input)?;
        mark_feature_time!(state, PerfFeature::PreExecObservers);
        Ok((input, true))
    }

    #[inline]
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut ShadowExecutor<E, SOT>,
        state: &mut Self::State,
        manager: &mut EM,
        input: E::Input,
        _index: usize,
    ) -> Result<(E::Input, crate::executors::ExitKind), Error> {
        start_timer!(state);
        executor.pre_exec(fuzzer, state, manager, &input)?;
        let exit_kind = executor.run_target(fuzzer, state, manager, &input)?;
        executor.post_exec(fuzzer, state, manager, &input)?;
        mark_feature_time!(state, PerfFeature::TargetExecution);
        Ok((input, exit_kind))
    }

    #[inline]
    fn post_exec(
        &mut self,
        _fuzzer: &mut Z,
        executor: &mut ShadowExecutor<E, SOT>,
        state: &mut Self::State,
        _manager: &mut EM,
        input: E::Input,
        _index: usize,
        exit_kind: crate::executors::ExitKind,
    ) -> Result<(E::Input, Option<usize>), Error> {
        *state.executions_mut() += 1;

        start_timer!(state);
        executor
            .shadow_observers_mut()
            .post_exec_all(state, &input, &exit_kind)?;
        executor
            .observers_mut()
            .post_exec_all(state, &input, &exit_kind)?;
        mark_feature_time!(state, PerfFeature::PostExecObservers);

        Ok((input, None))
    }

    #[inline]
    fn deinit(
        &mut self,
        _fuzzer: &mut Z,
        _executor: &mut ShadowExecutor<E, SOT>,
        _state: &mut Self::State,
        _manager: &mut EM,
    ) -> Result<(), Error> {
        Ok(())
    }
}

impl<E, EM, SOT, Z> ShadowTracingStage<E, EM, SOT, Z>
where
    E: Executor<EM, Z> + HasObservers,
    E::State: State + HasClientPerfMonitor + HasExecutions + HasCurrentStageInfo + HasCorpus,
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
