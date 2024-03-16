use alloc::string::{String, ToString};
use core::marker::PhantomData;

#[cfg(feature = "introspection")]
use libafl::state::HasClientPerfMonitor;
use libafl::{
    executors::{Executor, HasObservers},
    inputs::{BytesInput, UsesInput},
    observers::ObserversTuple,
    stages::{colorization::TaintMetadata, RetryRestartHelper, Stage},
    state::{
        HasCorpus, HasCurrentTestcase, HasExecutions, HasMetadata, HasNamedMetadata, UsesState,
    },
    Error,
};
use libafl_bolts::{tuples::MatchName, Named};

use crate::cmps::observers::AFLppCmpLogObserver;

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

impl<EM, TE, Z> Named for AFLppCmplogTracingStage<EM, TE, Z> {
    fn name(&self) -> &str {
        "AFLppCmplogTracingStage"
    }
}

impl<E, EM, TE, Z> Stage<E, EM, Z> for AFLppCmplogTracingStage<EM, TE, Z>
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

        if let Some(name) = &self.cmplog_observer_name {
            if let Some(ob) = self
                .tracer_executor
                .observers_mut()
                .match_name_mut::<AFLppCmpLogObserver<TE::State>>(name)
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

        if let Some(name) = &self.cmplog_observer_name {
            if let Some(ob) = self
                .tracer_executor
                .observers_mut()
                .match_name_mut::<AFLppCmpLogObserver<TE::State>>(name)
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
