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
#[derive(Debug)]
pub struct VerifyTimeoutsStage<E, S> {
    doubled_timeout: Duration,
    original_timeout: Duration,
    // The handle to our time observer
    phantom: PhantomData<(E, S)>,
}

impl<E, S> VerifyTimeoutsStage<E, S> {
    /// Create a `VerifyTimeoutsStage`
    pub fn new(configured_timeout: Duration) -> Self {
        Self {
            doubled_timeout: configured_timeout * 2,
            original_timeout: configured_timeout,
            phantom: PhantomData,
        }
    }
}

impl<E, S> UsesState for VerifyTimeoutsStage<E, S>
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
}

impl<E, EM, Z, S> Stage<E, EM, Z> for VerifyTimeoutsStage<E, S>
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
        executor.set_timeout(self.doubled_timeout);
        while let Some(input) = timeouts.pop() {
            let exit_kind = executor.run_target(fuzzer, state, manager, &input)?;
            if matches!(exit_kind, ExitKind::Timeout) {}
        }
        executor.set_timeout(self.original_timeout);
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
