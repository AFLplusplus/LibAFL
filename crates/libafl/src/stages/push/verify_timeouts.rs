//! Verify timeouts push stage for re-running captured timeouts.

use alloc::borrow::Cow;
use core::fmt::Debug;

use libafl_bolts::{Error, Named};
use serde::{Serialize, de::DeserializeOwned};

use super::{PushStage, StageStep};
use crate::{
    common::HasMetadata,
    fuzzer::{ExecutionMode, ExecutionRequest},
    inputs::Input,
    stages::{Restartable, verify_timeouts::TimeoutsToVerify},
    state::HasExecutionMode,
};

/// A stage that drains and re-evaluates inputs from [`TimeoutsToVerify`].
#[derive(Debug, Clone)]
pub struct VerifyTimeoutsStage {
    name: Cow<'static, str>,
}

/// Backwards compatibility alias for [`VerifyTimeoutsStage`].
pub type VerifyTimeoutsPushStage = VerifyTimeoutsStage;

impl VerifyTimeoutsStage {
    /// Create a new verify timeouts stage.
    #[must_use]
    pub fn new() -> Self {
        Self::with_name("VerifyTimeoutsStage")
    }

    /// Create a new verify timeouts stage with a custom name.
    #[must_use]
    pub fn with_name<N: Into<Cow<'static, str>>>(name: N) -> Self {
        Self { name: name.into() }
    }
}

impl Default for VerifyTimeoutsStage {
    fn default() -> Self {
        Self::new()
    }
}

impl Named for VerifyTimeoutsStage {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<S> Restartable<S> for VerifyTimeoutsPushStage {
    fn should_restart(&mut self, _state: &mut S) -> Result<bool, Error> {
        Ok(true)
    }

    fn clear_progress(&mut self, _state: &mut S) -> Result<(), Error> {
        Ok(())
    }
}

impl<EM, I, OT, S> PushStage<EM, I, OT, S> for VerifyTimeoutsPushStage
where
    I: Input + Debug + Serialize + DeserializeOwned + Clone + 'static,
    S: HasMetadata + HasExecutionMode,
{
    fn init(&mut self, state: &mut S, _manager: &mut EM) -> Result<(), Error> {
        state.set_execution_mode(ExecutionMode::VerifyTimeouts);
        Ok(())
    }

    fn step(&mut self, state: &mut S, _manager: &mut EM) -> Result<StageStep<I>, Error> {
        let input_opt = if let Ok(meta) = state.metadata_mut::<TimeoutsToVerify<I>>() {
            meta.pop()
        } else {
            None
        };

        if let Some(input) = input_opt {
            state.set_execution_mode(ExecutionMode::VerifyTimeouts);
            Ok(StageStep::Execute(
                ExecutionRequest::single(input).with_mode(ExecutionMode::VerifyTimeouts),
            ))
        } else {
            state.set_execution_mode(ExecutionMode::Normal);
            Ok(StageStep::Done)
        }
    }

    fn post_exec(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _obs: crate::fuzzer::BorrowedObservation<'_, I, OT>,
    ) -> Result<(), Error> {
        Ok(())
    }

    fn deinit(&mut self, state: &mut S, _manager: &mut EM) -> Result<(), Error> {
        state.set_execution_mode(ExecutionMode::Normal);
        Ok(())
    }
}

#[cfg(test)]
#[cfg(feature = "std")]
#[allow(
    clippy::type_complexity,
    clippy::match_wildcard_for_single_variants,
    clippy::duration_suboptimal_units
)]
mod tests {
    use alloc::vec;

    use libafl_bolts::rands::StdRand;

    use super::*;
    use crate::{
        corpus::{Corpus, HasCurrentCorpusId, InMemoryCorpus, Testcase},
        events::NopEventManager,
        feedbacks::ConstFeedback,
        inputs::BytesInput,
        observers::StdMapObserver,
        state::StdState,
    };

    #[test]
    fn test_verify_timeouts_push_stage() {
        let rand = StdRand::with_seed(1234);
        let mut corpus = InMemoryCorpus::<BytesInput>::new();
        let testcase = Testcase::new(BytesInput::new(vec![1, 2, 3, 4]));
        let id = corpus.add(testcase).unwrap();

        let mut feedback = ConstFeedback::new(true);
        let mut objective = ConstFeedback::new(false);
        let mut state = StdState::new(
            rand,
            corpus,
            InMemoryCorpus::new(),
            &mut feedback,
            &mut objective,
        )
        .unwrap();
        state.set_corpus_id(id).unwrap();

        let mut timeouts = TimeoutsToVerify::<BytesInput>::new();
        timeouts.push(BytesInput::new(vec![0xAA, 0xBB]));
        state.add_metadata(timeouts);

        let mut stage = VerifyTimeoutsPushStage::new();
        let mut mgr = NopEventManager::new();

        PushStage::<NopEventManager, BytesInput, (StdMapObserver<'static, u8, false>, ()), _>::init(&mut stage, &mut state, &mut mgr).unwrap();

        let step1: StageStep<BytesInput> = PushStage::<
            NopEventManager,
            BytesInput,
            (StdMapObserver<'static, u8, false>, ()),
            _,
        >::step(&mut stage, &mut state, &mut mgr)
        .unwrap();
        match step1 {
            StageStep::Execute(req) => {
                assert_eq!(req.inputs.len(), 1);
            }
            _ => panic!("Expected Execute step for timeout"),
        }

        let step2: StageStep<BytesInput> = PushStage::<
            NopEventManager,
            BytesInput,
            (StdMapObserver<'static, u8, false>, ()),
            _,
        >::step(&mut stage, &mut state, &mut mgr)
        .unwrap();
        assert!(matches!(step2, StageStep::Done));

        PushStage::<NopEventManager, BytesInput, (StdMapObserver<'static, u8, false>, ()), _>::deinit(&mut stage, &mut state, &mut mgr).unwrap();
    }
}
