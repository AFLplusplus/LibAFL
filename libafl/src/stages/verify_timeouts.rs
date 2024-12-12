#![allow(clippy::too_long_first_doc_paragraph)]
//! Stage that re-runs captured Timeouts with double the timeout to verify
//! Note: To capture the timeouts, use in conjunction with `CaptureTimeoutFeedback`
//! Note: Will NOT work with in process executors due to the potential for restarts/crashes when
//! running inputs.
use core::time::Duration;
use std::{cell::RefCell, collections::VecDeque, fmt::Debug, marker::PhantomData, rc::Rc};

use libafl_bolts::Error;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{
    corpus::Corpus,
    executors::{Executor, HasObservers, HasTimeout},
    inputs::{BytesInput, UsesInput},
    observers::ObserversTuple,
    stages::Stage,
    state::{HasCorpus, UsesState},
    Evaluator, HasMetadata,
};

/// Stage that re-runs inputs deemed as timeouts with double the timeout to assert that they are
/// not false positives. AFL++ style.
/// Note: Will NOT work with in process executors due to the potential for restarts/crashes when
/// running inputs.
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
    #[must_use]
    pub fn new() -> Self {
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
    #[must_use]
    pub fn count(&self) -> usize {
        self.inputs.len()
    }
}

impl<E, EM, S, Z> Stage<E, EM, S, Z> for VerifyTimeoutsStage<E, S>
where
    E::Observers: ObserversTuple<<S::Corpus as Corpus>::Input, S>,
    E: Executor<EM, Z, State = S> + HasObservers + HasTimeout,
    EM: UsesState<State = S>,
    Z: Evaluator<E, EM, State = S>,
    S: HasCorpus + HasMetadata + UsesInput<Input = <S::Corpus as Corpus>::Input>,
    <S::Corpus as Corpus>::Input: Debug + Serialize + DeserializeOwned + Default + 'static + Clone,
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
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
        let res = state
            .metadata_mut::<TimeoutsToVerify<<S::Corpus as Corpus>::Input>>()
            .unwrap();
        *res = TimeoutsToVerify::<<S::Corpus as Corpus>::Input>::new();
        Ok(())
    }
    fn should_restart(&mut self, _state: &mut S) -> Result<bool, Error> {
        Ok(true)
    }

    fn clear_progress(&mut self, _state: &mut S) -> Result<(), Error> {
        Ok(())
    }
}
