use alloc::borrow::Cow;
use core::marker::PhantomData;

use libafl::{
    executors::{Executor, HasObservers},
    inputs::{BytesInput, UsesInput},
    observers::ObserversTuple,
    stages::{colorization::TaintMetadata, RetryRestartHelper, Stage},
    state::{HasCorpus, HasCurrentTestcase, HasExecutions, UsesState},
    Error, HasMetadata, HasNamedMetadata,
};
use libafl_bolts::{
    tuples::{Handle, MatchNameRef},
    Named,
};

use crate::cmps::observers::AFLppCmpLogObserver;

/// Trace with tainted input
#[derive(Clone, Debug)]
pub struct AFLppCmplogTracingStage<'a, EM, TE, Z>
where
    TE: UsesState,
{
    tracer_executor: TE,
    cmplog_observer_handle: Option<Handle<AFLppCmpLogObserver<'a, TE::State>>>,
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(EM, TE, Z)>,
}

impl<EM, TE, Z> UsesState for AFLppCmplogTracingStage<'_, EM, TE, Z>
where
    TE: UsesState,
{
    type State = TE::State;
}

impl<EM, TE, Z> Named for AFLppCmplogTracingStage<'_, EM, TE, Z>
where
    TE: UsesState,
{
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("AFLppCmplogTracingStage");
        &NAME
    }
}

impl<E, EM, TE, Z> Stage<E, EM, Z> for AFLppCmplogTracingStage<'_, EM, TE, Z>
where
    E: UsesState<State = TE::State>,
    TE: Executor<EM, Z> + HasObservers,
    TE::State:
        HasExecutions + HasCorpus + HasMetadata + UsesInput<Input = BytesInput> + HasNamedMetadata,
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
    ) -> Result<(), Error> {
        // First run with the un-mutated input
        let unmutated_input = state.current_input_cloned()?;

        if let Some(observer_handle) = &self.cmplog_observer_handle {
            if let Some(ob) = self
                .tracer_executor
                .observers_mut()
                .get_mut(observer_handle)
            {
                // This is not the original input,
                // Set it to false
                ob.set_original(true);
            }
            // I can't think of any use of this stage if you don't use AFLppCmpLogObserver
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

        if let Some(observer_handle) = &self.cmplog_observer_handle {
            if let Some(ob) = self
                .tracer_executor
                .observers_mut()
                .get_mut(observer_handle)
            {
                // This is not the original input,
                // Set it to false
                ob.set_original(false);
            }
            // I can't think of any use of this stage if you don't use AFLppCmpLogObserver
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

    fn restart_progress_should_run(&mut self, state: &mut Self::State) -> Result<bool, Error> {
        // TODO: this may need better resumption? (Or is it always used with a forkserver?)
        RetryRestartHelper::restart_progress_should_run(state, self, 3)
    }

    fn clear_restart_progress(&mut self, state: &mut Self::State) -> Result<(), Error> {
        // TODO: this may need better resumption? (Or is it always used with a forkserver?)
        RetryRestartHelper::clear_restart_progress(state, self)
    }
}

impl<'a, EM, TE, Z> AFLppCmplogTracingStage<'a, EM, TE, Z>
where
    TE: UsesState,
{
    /// Creates a new default stage
    pub fn new(tracer_executor: TE) -> Self {
        Self {
            cmplog_observer_handle: None,
            tracer_executor,
            phantom: PhantomData,
        }
    }

    /// With cmplog observer
    pub fn with_cmplog_observer(
        tracer_executor: TE,
        observer_handle: Handle<AFLppCmpLogObserver<'a, TE::State>>,
    ) -> Self {
        Self {
            cmplog_observer_handle: Some(observer_handle),
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
