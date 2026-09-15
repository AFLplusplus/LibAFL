//! Replay push stage for scanning and re-executing corpus inputs.

use alloc::borrow::Cow;
use core::{fmt::Debug, marker::PhantomData};

use libafl_bolts::{Error, Named};

use super::{PushStage, StageStep};
use crate::{
    common::HasMetadata,
    corpus::{Corpus, CorpusId},
    fuzzer::ExecutionRequest,
    inputs::Input,
    stages::{
        Restartable,
        replay::{REPLAY_STAGE_NAME, ReplayHook, ReplayRestarterMetadata},
    },
    state::HasCorpus,
};

/// Metadata tracking progress of a [`ReplayStage`] in state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct ReplayStageMetadata {
    /// Corpus ID currently being replayed.
    pub current_id: Option<CorpusId>,
    /// Whether an input execution is currently in flight for `current_id`.
    pub in_flight: bool,
}

libafl_bolts::impl_serdeany!(ReplayStageMetadata);

/// A stage that replays entries from the corpus.
#[derive(Debug, Clone)]
pub struct ReplayStage<H, I> {
    name: Cow<'static, str>,
    hook: H,
    phantom: PhantomData<I>,
}

/// Backwards compatibility alias for [`ReplayStage`].
pub type ReplayPushStage<H, I> = ReplayStage<H, I>;

impl<I> Default for ReplayStage<(), I> {
    fn default() -> Self {
        Self::new()
    }
}

impl<I> ReplayStage<(), I> {
    /// Create a new replay stage.
    #[must_use]
    pub fn new() -> Self {
        Self::with_name(REPLAY_STAGE_NAME)
    }

    /// Create a new replay stage with custom name.
    #[must_use]
    pub fn with_name<N: Into<Cow<'static, str>>>(name: N) -> Self {
        Self {
            name: name.into(),
            hook: (),
            phantom: PhantomData,
        }
    }
}

impl<H, I> ReplayStage<H, I> {
    /// Create a new replay stage with a hook.
    pub fn with_hook(hook: H) -> Self {
        Self::with_hook_and_name(hook, REPLAY_STAGE_NAME)
    }

    /// Create a new replay stage with a hook and custom name.
    pub fn with_hook_and_name<N: Into<Cow<'static, str>>>(hook: H, name: N) -> Self {
        Self {
            name: name.into(),
            hook,
            phantom: PhantomData,
        }
    }

    /// Access the hook.
    pub fn hook(&self) -> &H {
        &self.hook
    }

    /// Access the hook (mutable).
    pub fn hook_mut(&mut self) -> &mut H {
        &mut self.hook
    }
}

impl<H, I> Named for ReplayStage<H, I> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<H, I, S> Restartable<S> for ReplayStage<H, I> {
    fn should_restart(&mut self, _state: &mut S) -> Result<bool, Error> {
        Ok(true)
    }

    fn clear_progress(&mut self, _state: &mut S) -> Result<(), Error> {
        Ok(())
    }
}

impl<EM, H, I, OT, S> PushStage<EM, I, OT, S> for ReplayStage<H, I>
where
    H: ReplayHook<I, S>,
    I: Input + Clone,
    S: HasCorpus<I> + HasMetadata + crate::common::HasNamedMetadata,
{
    fn init(&mut self, state: &mut S, _manager: &mut EM) -> Result<(), Error> {
        if state
            .named_metadata_map()
            .get::<ReplayStageMetadata>(&self.name)
            .is_none()
        {
            state.add_named_metadata(
                &self.name,
                ReplayStageMetadata {
                    current_id: state.corpus().first(),
                    in_flight: false,
                },
            );
        }
        Ok(())
    }

    fn step(&mut self, state: &mut S, _manager: &mut EM) -> Result<StageStep<I>, Error> {
        let meta = state
            .named_metadata_map()
            .get::<ReplayStageMetadata>(&self.name)
            .copied()
            .unwrap_or_else(|| ReplayStageMetadata {
                current_id: state.corpus().first(),
                in_flight: false,
            });

        let mut current_id = meta.current_id;
        if meta.in_flight
            && let Some(id) = current_id
        {
            let input = {
                let testcase = state.corpus().get(id)?;
                let mut testcase_mut = testcase.borrow_mut();
                state.corpus().load_input_into(&mut testcase_mut)?;
                testcase_mut.input().as_ref().unwrap().clone()
            };
            self.hook.post_exec(state, &input, id)?;
            let rmeta = state.metadata_or_insert_with(ReplayRestarterMetadata::new);
            rmeta.corpus_finish(id);
            current_id = state.corpus().next(id);
            if let Ok(m) = state.named_metadata_mut::<ReplayStageMetadata>(&self.name) {
                m.current_id = current_id;
                m.in_flight = false;
            }
        }

        while let Some(id) = current_id {
            let rmeta = state.metadata_or_insert_with(ReplayRestarterMetadata::new);
            if rmeta.corpus_probe(&id) {
                current_id = state.corpus().next(id);
                if let Ok(m) = state.named_metadata_mut::<ReplayStageMetadata>(&self.name) {
                    m.current_id = current_id;
                }
                continue;
            }

            let input = {
                let testcase = state.corpus().get(id)?;
                let mut testcase_mut = testcase.borrow_mut();
                state.corpus().load_input_into(&mut testcase_mut)?;
                testcase_mut.input().as_ref().unwrap().clone()
            };

            self.hook.pre_exec(state, &input, id)?;
            if let Ok(m) = state.named_metadata_mut::<ReplayStageMetadata>(&self.name) {
                m.current_id = Some(id);
                m.in_flight = true;
            } else {
                state.add_named_metadata(
                    &self.name,
                    ReplayStageMetadata {
                        current_id: Some(id),
                        in_flight: true,
                    },
                );
            }

            return Ok(StageStep::Execute(ExecutionRequest::single(input)));
        }

        Ok(StageStep::Done)
    }

    fn deinit(&mut self, state: &mut S, _manager: &mut EM) -> Result<(), Error> {
        let _ = state
            .named_metadata_map_mut()
            .remove::<ReplayStageMetadata>(&self.name);
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
    fn test_replay_push_stage() {
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

        let mut stage = ReplayPushStage::new();
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

        PushStage::<NopEventManager, BytesInput, (StdMapObserver<'static, u8, false>, ()), _>::deinit(&mut stage, &mut state, &mut mgr).unwrap();
    }
}
