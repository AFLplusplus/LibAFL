//! Stage that re-runs captured Timeouts with double the timeout to verify
//! Note: To capture the timeouts, use in conjunction with `CaptureTimeoutFeedback`
use core::time::Duration;
use std::{cell::RefCell, collections::VecDeque, fmt::Debug, marker::PhantomData, rc::Rc};

use crate::{
    corpus::Corpus,
    executors::{Executor, HasObservers, HasTimeout},
    inputs::{BytesInput, UsesInput},
    observers::ObserversTuple,
    stages::Stage,
    state::{HasCorpus, State, UsesState},
    Evaluator, HasMetadata,
};
use libafl_bolts::Error;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// Stage that re-runs inputs deemed as timeouts with double the timeout to assert that they are
/// not false positives. AFL++ style.
#[derive(Debug)]
pub struct VerifyTimeoutsStage<E, S> {
    doubled_timeout: Duration,
    original_timeout: Duration,
    capture_timeouts: Rc<RefCell<bool>>,
    phantom: PhantomData<(E, S)>,
}

impl<E, S> VerifyTimeoutsStage<E, S> {
    /// Create a `VerifyTimeoutsStage`
    pub fn new(capture_timeouts: Rc<RefCell<bool>>, configured_timeout: Duration) -> Self {
        Self {
            capture_timeouts,
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

/// Timeouts that `VerifyTimeoutsStage` will read from
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
    /// Create a new `TimeoutsToVerify`
    #[must_use] pub fn new() -> Self {
        Self {
            inputs: VecDeque::new(),
        }
    }
    
    /// Add a `TimeoutsToVerify` to queue
    pub fn push(&mut self, input: I) {
        self.inputs.push_back(input);
    }
    
    /// Pop a `TimeoutsToVerify` to queue
    pub fn pop(&mut self) -> Option<I> {
        self.inputs.pop_front()
    }
    
    /// Count `TimeoutsToVerify` in queue
    #[must_use] pub fn count(&self) -> usize {
        self.inputs.len()
    }
}

impl<E, EM, Z, S> Stage<E, EM, Z> for VerifyTimeoutsStage<E, S>
where
    E::Observers: ObserversTuple<<Self as UsesInput>::Input, <Self as UsesState>::State>,
    E: Executor<EM, Z, State = S> + HasObservers + HasTimeout,
    EM: UsesState<State = S>,
    Z: UsesState<State = S> + Evaluator<E, EM>,
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
        *self.capture_timeouts.borrow_mut() = false;
        while let Some(input) = timeouts.pop() {
            fuzzer.evaluate_input(state, executor, manager, input)?;
        }
        executor.set_timeout(self.original_timeout);
        *self.capture_timeouts.borrow_mut() = true;
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
