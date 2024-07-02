use alloc::borrow::{Cow, ToOwned};
use core::marker::PhantomData;

use libafl::{
    executors::{Executor, HasObservers},
    inputs::{BytesInput, UsesInput},
    observers::ObserversTuple,
    stages::{colorization::TaintMetadata, Stage, StdRestartHelper},
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
    name: Cow<'static, str>,
    tracer_executor: TE,
    cmplog_observer_handle: Handle<AFLppCmpLogObserver<'a, <Self as UsesState>::State>>,
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(EM, TE, Z)>,
}
/// The name for aflpp tracing stage
pub static AFLPP_CMPLOG_TRACING_STAGE_NAME: &str = "aflpptracing";

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
        &self.name
    }
}

impl<E, EM, TE, Z> Stage<E, EM, Z> for AFLppCmplogTracingStage<'_, EM, TE, Z>
where
    E: UsesState<State = Self::State>,
    TE: Executor<EM, Z> + HasObservers,
    Self::State:
        HasExecutions + HasCorpus + HasMetadata + UsesInput<Input = BytesInput> + HasNamedMetadata,
    EM: UsesState<State = Self::State>,
    Z: UsesState<State = Self::State>,
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

        if let Some(ob) = self
            .tracer_executor
            .observers_mut()
            .get_mut(&self.cmplog_observer_handle)
        {
            // This is not the original input,
            // Set it to false
            ob.set_original(true);
        }
        // I can't think of any use of this stage if you don't use AFLppCmpLogObserver
        // but do nothing ofcourse

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
        // I can't think of any use of this stage if you don't use AFLppCmpLogObserver
        // but do nothing ofcourse

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

    fn should_restart(&mut self, state: &mut Self::State) -> Result<bool, Error> {
        // Tracing stage is always deterministic
        // don't restart
        StdRestartHelper::no_retry(state, &self.name)
    }

    fn clear_progress(&mut self, state: &mut Self::State) -> Result<(), Error> {
        // TODO: this may need better resumption? (Or is it always used with a forkserver?)
        StdRestartHelper::clear_progress(state, &self.name)
    }
}

impl<'a, EM, TE, Z> AFLppCmplogTracingStage<'a, EM, TE, Z>
where
    TE: UsesState,
{
    /// With cmplog observer
    pub fn new(
        tracer_executor: TE,
        observer_handle: Handle<AFLppCmpLogObserver<'a, TE::State>>,
    ) -> Self {
        let observer_name = observer_handle.name().clone();
        Self {
            name: Cow::Owned(
                AFLPP_CMPLOG_TRACING_STAGE_NAME.to_owned()
                    + ":"
                    + observer_name.into_owned().as_str(),
            ),
            cmplog_observer_handle: observer_handle,
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
