//! Shadow tracing push stage.

use alloc::borrow::Cow;
use core::fmt::Debug;

use libafl_bolts::{Error, Named};

use super::{PushStage, StageStep};
use crate::{
    common::HasNamedMetadata,
    corpus::HasCurrentCorpusId,
    fuzzer::ExecutionRequest,
    inputs::Input,
    stages::{Restartable, RetryCountRestartHelper, shadow::SHADOW_TRACING_STAGE_NAME},
    state::{HasCorpus, HasCurrentTestcase},
};

/// A stage that executes the current input against shadow/secondary observers.
#[derive(Debug, Clone)]
pub struct ShadowStage {
    name: Cow<'static, str>,
}

/// Backwards compatibility alias for [`ShadowStage`].
pub type ShadowPushStage = ShadowStage;

impl ShadowStage {
    /// Create a new shadow stage.
    #[must_use]
    pub fn new() -> Self {
        Self::with_name(SHADOW_TRACING_STAGE_NAME)
    }

    /// Create a new shadow stage with custom name.
    #[must_use]
    pub fn with_name<N: Into<Cow<'static, str>>>(name: N) -> Self {
        Self { name: name.into() }
    }
}

impl Default for ShadowStage {
    fn default() -> Self {
        Self::new()
    }
}

impl Named for ShadowStage {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<S> Restartable<S> for ShadowStage
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

impl<EM, I, OT, S> PushStage<EM, I, OT, S> for ShadowStage
where
    I: Input + Clone,
    S: HasCorpus<I> + HasCurrentTestcase<I> + HasNamedMetadata,
{
    fn init(&mut self, state: &mut S, _manager: &mut EM) -> Result<(), Error> {
        if state
            .named_metadata_map()
            .get::<super::StageProgressMetadata>(&self.name)
            .is_none()
        {
            state.add_named_metadata(
                &self.name,
                super::StageProgressMetadata {
                    testcases_to_do: 1,
                    testcases_done: 0,
                },
            );
        }
        Ok(())
    }

    fn step(&mut self, state: &mut S, _manager: &mut EM) -> Result<StageStep<I>, Error> {
        let done = state
            .named_metadata_map()
            .get::<super::StageProgressMetadata>(&self.name)
            .is_some_and(|m| m.testcases_done >= m.testcases_to_do);

        if done {
            return Ok(StageStep::Done);
        }

        let input = state.current_input_cloned()?;
        if let Ok(meta) = state.named_metadata_mut::<super::StageProgressMetadata>(&self.name) {
            meta.testcases_done = 1;
        } else {
            state.add_named_metadata(
                &self.name,
                super::StageProgressMetadata {
                    testcases_to_do: 1,
                    testcases_done: 1,
                },
            );
        }

        Ok(StageStep::Execute(ExecutionRequest::single(input)))
    }

    fn deinit(&mut self, state: &mut S, _manager: &mut EM) -> Result<(), Error> {
        let _ = state
            .named_metadata_map_mut()
            .remove::<super::StageProgressMetadata>(&self.name);
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
        corpus::{Corpus, InMemoryCorpus, Testcase},
        events::NopEventManager,
        feedbacks::ConstFeedback,
        inputs::BytesInput,
        observers::StdMapObserver,
        state::StdState,
    };

    #[test]
    fn test_shadow_push_stage() {
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

        let mut stage = ShadowPushStage::new();
        let mut mgr = NopEventManager::new();

        PushStage::<NopEventManager, BytesInput, (StdMapObserver<'static, u8, false>, ()), _>::init(&mut stage, &mut state, &mut mgr).unwrap();

        let step1 = PushStage::<
            NopEventManager,
            BytesInput,
            (StdMapObserver<'static, u8, false>, ()),
            _,
        >::step(&mut stage, &mut state, &mut mgr)
        .unwrap();
        assert!(matches!(step1, StageStep::Execute(_)));

        let step2 = PushStage::<
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
