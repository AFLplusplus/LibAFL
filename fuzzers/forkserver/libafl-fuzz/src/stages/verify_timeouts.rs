//! Stage that re-runs inputs deemed as timeouts with double the timeout to assert that they are
//! not false positives. AFL++ style
use core::time::Duration;
use std::{collections::VecDeque, fmt::Debug, marker::PhantomData};

use libafl::{
    corpus::Corpus,
    executors::{Executor, ExitKind, HasObservers, HasTimeout},
    inputs::{BytesInput, UsesInput},
    observers::ObserversTuple,
    stages::Stage,
    state::{HasCorpus, State, UsesState},
    HasMetadata,
};
use libafl_bolts::Error;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::feedback::capture_timeout::CaptureTimeoutFeedback;
#[derive(Debug)]
pub struct VerifyTimeoutsStage<'a, E, S> {
    doubled_timeout: Duration,
    original_timeout: Duration,
    capture_feedback: &'a mut CaptureTimeoutFeedback,
    phantom: PhantomData<(E, S)>,
}

impl<'a, E, S> VerifyTimeoutsStage<'a, E, S> {
    /// Create a `VerifyTimeoutsStage`
    pub fn new(
        capture_feedback: &'a mut CaptureTimeoutFeedback,
        configured_timeout: Duration,
    ) -> Self {
        Self {
            capture_feedback,
            doubled_timeout: configured_timeout * 2,
            original_timeout: configured_timeout,
            phantom: PhantomData,
        }
    }
}

impl<E, S> UsesState for VerifyTimeoutsStage<'_, E, S>
where
    S: State,
{
    type State = S;
}

#[derive(Default, Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "I: for<'a> Deserialize<'a> + Serialize")]
pub struct TimeoutsToVerify<I> {
    inputs: VecDeque<I>,
}

libafl_bolts::impl_serdeany!(
    TimeoutsToVerify<I: Debug + 'static + Serialize + DeserializeOwned + Clone>,
    <BytesInput>
);

impl<I> TimeoutsToVerify<I> {
    pub fn new() -> Self {
        Self {
            inputs: VecDeque::new(),
        }
    }
    pub fn push(&mut self, input: I) {
        self.inputs.push_back(input);
    }
    pub fn pop(&mut self) -> Option<I> {
        self.inputs.pop_front()
    }
    pub fn count(&self) -> usize {
        self.inputs.len()
    }
}

impl<E, EM, Z, S> Stage<E, EM, Z> for VerifyTimeoutsStage<'_, E, S>
where
    E::Observers: ObserversTuple<<Self as UsesInput>::Input, <Self as UsesState>::State>,
    E: Executor<EM, Z, State = S> + HasObservers + HasTimeout,
    EM: UsesState<State = S>,
    Z: UsesState<State = S>,
    S: HasCorpus + State + HasMetadata,
    Self::Input: Debug + Serialize + DeserializeOwned + Default + 'static + Clone,
    <<E as UsesState>::State as HasCorpus>::Corpus: Corpus<Input = Self::Input>, //delete me
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Self::State,
        manager: &mut EM,
    ) -> Result<(), Error> {
        let mut timeouts = state
            .metadata_or_insert_with(TimeoutsToVerify::<<S::Corpus as Corpus>::Input>::new)
            .clone();
        if timeouts.count() == 0 {
            return Ok(());
        }
        executor.set_timeout(self.doubled_timeout);
        self.capture_feedback.disable();
        while let Some(input) = timeouts.pop() {
            let exit_kind = executor.run_target(fuzzer, state, manager, &input)?;
            if matches!(exit_kind, ExitKind::Timeout) {}
        }
        executor.set_timeout(self.original_timeout);
        self.capture_feedback.enable();
        let res = state.metadata_mut::<TimeoutsToVerify<E::Input>>().unwrap();
        *res = TimeoutsToVerify::<E::Input>::new();
        Ok(())
    }
    fn should_restart(&mut self, _state: &mut Self::State) -> Result<bool, Error> {
        Ok(true)
    }

    fn clear_progress(&mut self, _state: &mut Self::State) -> Result<(), Error> {
        Ok(())
    }
}
