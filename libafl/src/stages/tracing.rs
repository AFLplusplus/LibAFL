//! The tracing stage can trace the target and enrich a testcase with metadata, for example for `CmpLog`.

use core::{fmt::Debug, marker::PhantomData};

use crate::{
    corpus::{Corpus, HasCurrentCorpusIdx},
    executors::{Executor, HasObservers, ShadowExecutor},
    mark_feature_time,
    observers::ObserversTuple,
    stages::{LimitedTriesProgress, RetryingStage, Stage},
    start_timer,
    state::{HasCorpus, HasExecutions, HasNamedMetadata, State, UsesState},
    Error,
};
#[cfg(feature = "introspection")]
use crate::{monitors::PerfFeature, state::HasClientPerfMonitor};

/// A stage that runs a tracer executor
#[derive(Clone, Debug)]
pub struct TracingStage<EM, TE, Z> {
    tracer_executor: TE,
    initial_tries: usize,
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
    TE::State: HasExecutions + HasCorpus + HasNamedMetadata,
    EM: UsesState<State = TE::State>,
    Z: UsesState<State = TE::State>,
{
    type Progress = LimitedTriesProgress;

    #[inline]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        _executor: &mut E,
        state: &mut TE::State,
        manager: &mut EM,
    ) -> Result<(), Error> {
        let Some(corpus_idx) = state.current_corpus_idx()? else {
            return Err(Error::illegal_state(
                "state is not currently processing a corpus index",
            ));
        };
        if Self::Progress::should_skip(state, self, corpus_idx)? {
            return Ok(());
        }

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

impl<EM, TE, Z> RetryingStage for TracingStage<EM, TE, Z> {
    fn initial_tries(&self) -> usize {
        self.initial_tries
    }
}

impl<EM, TE, Z> TracingStage<EM, TE, Z> {
    /// Creates a new default stage
    pub fn new(tracer_executor: TE) -> Self {
        Self {
            tracer_executor,
            initial_tries: 10,
            phantom: PhantomData,
        }
    }

    /// Apply a certain amount of tries that this stage will attempt to trace the input before
    /// giving up and not processing the input again.
    pub fn with_tries(mut self, initial_tries: usize) -> Self {
        self.initial_tries = initial_tries;
        self
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
    initial_tries: usize,
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
    E::State: State + HasExecutions + HasCorpus + HasNamedMetadata + Debug,
{
    type Progress = LimitedTriesProgress;

    #[inline]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut ShadowExecutor<E, SOT>,
        state: &mut E::State,
        manager: &mut EM,
    ) -> Result<(), Error> {
        let Some(corpus_idx) = state.current_corpus_idx()? else {
            return Err(Error::illegal_state(
                "state is not currently processing a corpus index",
            ));
        };
        if Self::Progress::should_skip(state, self, corpus_idx)? {
            return Ok(());
        }

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

impl<E, EM, SOT, Z> RetryingStage for ShadowTracingStage<E, EM, SOT, Z> {
    fn initial_tries(&self) -> usize {
        self.initial_tries
    }
}

impl<E, EM, SOT, Z> ShadowTracingStage<E, EM, SOT, Z>
where
    E: Executor<EM, Z> + HasObservers,
    E::State: State + HasExecutions + HasCorpus,
    EM: UsesState<State = E::State>,
    SOT: ObserversTuple<E::State>,
    Z: UsesState<State = E::State>,
{
    /// Creates a new default stage
    pub fn new(_executor: &mut ShadowExecutor<E, SOT>) -> Self {
        Self {
            initial_tries: 10,
            phantom: PhantomData,
        }
    }

    /// Apply a certain amount of tries that this stage will attempt to trace the input before
    /// giving up and not processing the input again.
    pub fn with_tries(mut self, initial_tries: usize) -> Self {
        self.initial_tries = initial_tries;
        self
    }
}
