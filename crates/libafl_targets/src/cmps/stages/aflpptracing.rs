use alloc::borrow::{Cow, ToOwned};
use core::marker::PhantomData;

use libafl::{
    Error, HasMetadata, HasNamedMetadata,
    corpus::HasCurrentCorpusId,
    executors::{Executor, HasObservers},
    fuzzer::{ExecutionMode, ExecutionRequest},
    inputs::BytesInput,
    observers::ObserversTuple,
    stages::{Restartable, RetryCountRestartHelper, colorization::TaintMetadata, pull::Stage},
    state::{HasCorpus, HasCurrentTestcase},
};
use libafl_bolts::{
    Named,
    tuples::{Handle, MatchNameRef},
};

use crate::cmps::observers::AflppCmpLogObserver;

/// Trace with tainted input
#[derive(Debug, Clone)]
pub struct AflppCmplogTracingStage<'a, EM, TE, S, Z = ()> {
    name: Cow<'static, str>,
    tracer_executor: TE,
    cmplog_observer_handle: Handle<AflppCmpLogObserver<'a>>,
    done: bool,
    phantom: PhantomData<(EM, TE, S, Z)>,
}
/// The name for aflpp tracing stage
pub static AFLPP_CMPLOG_TRACING_STAGE_NAME: &str = "aflpptracing";

impl<EM, TE, S, Z> Named for AflppCmplogTracingStage<'_, EM, TE, S, Z> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<E, EM, TE, S, Z> Stage<E, EM, S, Z> for AflppCmplogTracingStage<'_, EM, TE, S, Z>
where
    TE: HasObservers + Executor<EM, BytesInput, S, Z>,
    TE::Observers: MatchNameRef + ObserversTuple<BytesInput, S>,
    S: HasCorpus<BytesInput>
        + HasCurrentTestcase<BytesInput>
        + HasMetadata
        + HasNamedMetadata
        + HasCurrentCorpusId,
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
}

impl<EM, TE, S, Z> Restartable<S> for AflppCmplogTracingStage<'_, EM, TE, S, Z>
where
    S: HasMetadata + HasNamedMetadata + HasCurrentCorpusId,
{
    fn should_restart(&mut self, state: &mut S) -> Result<bool, Error> {
        // Tracing stage is always deterministic
        // don't restart
        RetryCountRestartHelper::no_retry(state, &self.name)
    }

    fn clear_progress(&mut self, state: &mut S) -> Result<(), Error> {
        // TODO: this may need better resumption? (Or is it always used with a forkserver?)
        RetryCountRestartHelper::clear_progress(state, &self.name)
    }
}

impl<'a, EM, TE, S, Z> AflppCmplogTracingStage<'a, EM, TE, S, Z> {
    /// With cmplog observer
    pub fn new(tracer_executor: TE, observer_handle: Handle<AflppCmpLogObserver<'a>>) -> Self {
        let observer_name = observer_handle.name().clone();
        Self {
            name: Cow::Owned(
                AFLPP_CMPLOG_TRACING_STAGE_NAME.to_owned()
                    + ":"
                    + observer_name.into_owned().as_str(),
            ),
            cmplog_observer_handle: observer_handle,
            tracer_executor,
            done: false,
            phantom: PhantomData,
        }
    }

    /// Perform cmplog tracing on the current testcase
    pub fn trace(&mut self, fuzzer: &mut Z, state: &mut S, manager: &mut EM) -> Result<(), Error>
    where
        TE: HasObservers + Executor<EM, BytesInput, S, Z>,
        TE::Observers: MatchNameRef + ObserversTuple<BytesInput, S>,
        S: HasCorpus<BytesInput>
            + HasCurrentTestcase<BytesInput>
            + HasMetadata
            + HasNamedMetadata
            + HasCurrentCorpusId,
    {
        // First run with the un-mutated input
        let unmutated_input = state.current_input_cloned()?;

        if let Some(ob) = self
            .tracer_executor
            .observers_mut()
            .get_mut(&self.cmplog_observer_handle)
        {
            // This is not the original input,
            // Set it to false
            ob.set_original(true);
        }

        self.tracer_executor
            .observers_mut()
            .pre_exec_all(state, &unmutated_input)?;

        let exit_kind =
            self.tracer_executor
                .run_target(fuzzer, state, manager, &unmutated_input)?;

        self.tracer_executor
            .observers_mut()
            .post_exec_all(state, &unmutated_input, &exit_kind)?;

        // Second run with the mutated input
        let mutated_input = match state.metadata_map().get::<TaintMetadata>() {
            Some(meta) => BytesInput::from(meta.input_vec().as_ref()),
            None => return Err(Error::unknown("No metadata found")),
        };

        if let Some(ob) = self
            .tracer_executor
            .observers_mut()
            .get_mut(&self.cmplog_observer_handle)
        {
            // This is not the original input,
            // Set it to false
            ob.set_original(false);
        }

        self.tracer_executor
            .observers_mut()
            .pre_exec_all(state, &mutated_input)?;

        let exit_kind = self
            .tracer_executor
            .run_target(fuzzer, state, manager, &mutated_input)?;

        self.tracer_executor
            .observers_mut()
            .post_exec_all(state, &mutated_input, &exit_kind)?;

        Ok(())
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

impl<EM, OT, S, TE> libafl::stages::push::PushStage<EM, BytesInput, OT, S>
    for AflppCmplogTracingStage<'_, EM, TE, S, ()>
where
    TE: HasObservers + Executor<EM, BytesInput, S, ()>,
    TE::Observers: MatchNameRef + ObserversTuple<BytesInput, S>,
    S: HasCorpus<BytesInput>
        + HasCurrentTestcase<BytesInput>
        + HasMetadata
        + HasNamedMetadata
        + HasCurrentCorpusId,
{
    fn init(&mut self, _state: &mut S, _manager: &mut EM) -> Result<(), Error> {
        self.done = false;
        Ok(())
    }

    fn step(
        &mut self,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<libafl::stages::push::StageStep<BytesInput>, Error> {
        if self.done {
            return Ok(libafl::stages::push::StageStep::Done);
        }
        self.done = true;
        let mut fuzzer = ();
        self.trace(&mut fuzzer, state, manager)?;
        Ok(libafl::stages::push::StageStep::Done)
    }

    fn deinit(&mut self, _state: &mut S, _manager: &mut EM) -> Result<(), Error> {
        self.done = false;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TracingPhase {
    Original,
    Colorized,
    Done,
}

/// Push stage for tracing comparisons in `CmpLog` mode.
#[derive(Debug, Clone)]
pub struct AflppCmplogTracingPushStage {
    name: Cow<'static, str>,
    phase: TracingPhase,
}

impl AflppCmplogTracingPushStage {
    /// Create a new cmplog tracing push stage.
    #[must_use]
    pub fn new() -> Self {
        Self {
            name: Cow::Borrowed("AflppCmplogTracingPushStage"),
            phase: TracingPhase::Original,
        }
    }
}

impl Default for AflppCmplogTracingPushStage {
    fn default() -> Self {
        Self::new()
    }
}

impl Named for AflppCmplogTracingPushStage {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<S> Restartable<S> for AflppCmplogTracingPushStage
where
    S: HasNamedMetadata + HasCurrentCorpusId,
{
    fn should_restart(&mut self, state: &mut S) -> Result<bool, Error> {
        RetryCountRestartHelper::no_retry(state, &self.name)
    }

    fn clear_progress(&mut self, state: &mut S) -> Result<(), Error> {
        RetryCountRestartHelper::clear_progress(state, &self.name)
    }
}

impl<EM, OT, S> libafl::stages::push::PushStage<EM, BytesInput, OT, S>
    for AflppCmplogTracingPushStage
where
    S: HasCorpus<BytesInput>
        + HasCurrentTestcase<BytesInput>
        + HasMetadata
        + libafl::state::HasExecutionMode,
{
    fn init(&mut self, state: &mut S, _manager: &mut EM) -> Result<(), Error> {
        self.phase = TracingPhase::Original;
        state.set_execution_mode(ExecutionMode::CmpLog);
        Ok(())
    }

    fn step(
        &mut self,
        state: &mut S,
        _manager: &mut EM,
    ) -> Result<libafl::stages::push::StageStep<BytesInput>, Error> {
        match self.phase {
            TracingPhase::Original => {
                let unmutated = state.current_input_cloned()?;
                self.phase = if state.metadata_map().get::<TaintMetadata>().is_some() {
                    TracingPhase::Colorized
                } else {
                    TracingPhase::Done
                };
                Ok(libafl::stages::push::StageStep::Execute(
                    ExecutionRequest::single(unmutated).with_mode(ExecutionMode::CmpLog),
                ))
            }
            TracingPhase::Colorized => {
                self.phase = TracingPhase::Done;
                if let Some(meta) = state.metadata_map().get::<TaintMetadata>() {
                    let colorized = BytesInput::from(meta.input_vec().as_ref());
                    Ok(libafl::stages::push::StageStep::Execute(
                        ExecutionRequest::single(colorized).with_mode(ExecutionMode::CmpLog),
                    ))
                } else {
                    state.set_execution_mode(ExecutionMode::Normal);
                    Ok(libafl::stages::push::StageStep::Done)
                }
            }
            TracingPhase::Done => {
                state.set_execution_mode(ExecutionMode::Normal);
                Ok(libafl::stages::push::StageStep::Done)
            }
        }
    }

    fn deinit(&mut self, state: &mut S, _manager: &mut EM) -> Result<(), Error> {
        self.phase = TracingPhase::Original;
        state.set_execution_mode(ExecutionMode::Normal);
        Ok(())
    }
}
