//! Unicode-aware mutational push stage.

use alloc::borrow::Cow;
use core::fmt::Debug;

use libafl_bolts::{Error, Named, nonzero, rands::Rand};

use super::{PushStage, StageStep};
use crate::{
    common::{HasMetadata, HasNamedMetadata},
    fuzzer::ExecutionRequest,
    inputs::{HasTargetBytes, Input},
    mutators::Mutator,
    stages::{
        push::mutational::DEFAULT_MUTATIONAL_MAX_ITERATIONS, unicode::UnicodeIdentificationMetadata,
    },
    state::{HasCorpus, HasCurrentTestcase, HasRand},
};

/// A mutational stage that identifies unicode/string regions and applies mutations.
#[derive(Debug, Clone)]
pub struct UnicodeMutationalStage<M> {
    name: Cow<'static, str>,
    mutator: M,
}

/// Backwards compatibility alias for [`UnicodeMutationalStage`].
pub type UnicodeMutationalPushStage<M> = UnicodeMutationalStage<M>;

impl<M> UnicodeMutationalStage<M> {
    /// Create a new unicode mutational stage.
    #[must_use]
    pub fn new(mutator: M) -> Self {
        Self::with_name(mutator, "UnicodeMutationalStage")
    }

    /// Create a new unicode mutational stage with custom name.
    #[must_use]
    pub fn with_name<N: Into<Cow<'static, str>>>(mutator: M, name: N) -> Self {
        Self {
            name: name.into(),
            mutator,
        }
    }

    /// Access the mutator.
    pub fn mutator(&self) -> &M {
        &self.mutator
    }

    /// Access the mutator (mutable).
    pub fn mutator_mut(&mut self) -> &mut M {
        &mut self.mutator
    }
}

impl<M> Named for UnicodeMutationalPushStage<M> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<EM, I, M, OT, S> PushStage<EM, I, OT, S> for UnicodeMutationalPushStage<M>
where
    I: Input + HasTargetBytes + Clone,
    M: Mutator<(I, UnicodeIdentificationMetadata), S>,
    S: HasCorpus<I> + HasRand + HasCurrentTestcase<I> + HasNamedMetadata,
{
    fn init(&mut self, state: &mut S, _manager: &mut EM) -> Result<(), Error> {
        {
            let mut tc = state.current_testcase_mut()?;
            if !tc.has_metadata::<UnicodeIdentificationMetadata>()
                && let Some(input) = tc.input()
            {
                let bytes = input.target_bytes();
                let metadata = UnicodeIdentificationMetadata::new(&bytes);
                tc.add_metadata(metadata);
            }
        }

        if state
            .named_metadata_map()
            .get::<super::StageProgressMetadata>(&self.name)
            .is_none()
        {
            let iters = 1 + state
                .rand_mut()
                .below(nonzero!(DEFAULT_MUTATIONAL_MAX_ITERATIONS));
            state.add_named_metadata(
                &self.name,
                super::StageProgressMetadata {
                    testcases_to_do: iters,
                    testcases_done: 0,
                },
            );
        }
        Ok(())
    }

    fn step(&mut self, state: &mut S, _manager: &mut EM) -> Result<StageStep<I>, Error> {
        let (to_do, mut done) = state
            .named_metadata_map()
            .get::<super::StageProgressMetadata>(&self.name)
            .map_or((0, 0), |m| (m.testcases_to_do, m.testcases_done));

        if done >= to_do {
            return Ok(StageStep::Done);
        }

        let base_input = state.current_input_cloned()?;
        let base_meta = {
            let tc = state.current_testcase()?;
            tc.metadata::<UnicodeIdentificationMetadata>()?.clone()
        };
        while done < to_do {
            let mut wrapped = (base_input.clone(), base_meta.clone());
            done += 1;
            if self.mutator.mutate(state, &mut wrapped)? == crate::mutators::MutationResult::Mutated
            {
                if let Ok(meta) =
                    state.named_metadata_mut::<super::StageProgressMetadata>(&self.name)
                {
                    meta.testcases_done = done;
                }
                return Ok(StageStep::Execute(ExecutionRequest::single(wrapped.0)));
            }
        }

        if let Ok(meta) = state.named_metadata_mut::<super::StageProgressMetadata>(&self.name) {
            meta.testcases_done = done;
        }

        Ok(StageStep::Done)
    }

    fn post_exec(
        &mut self,
        state: &mut S,
        _manager: &mut EM,
        obs: crate::fuzzer::BorrowedObservation<'_, I, OT>,
    ) -> Result<(), Error> {
        let corpus_id = obs.tag.and_then(|t| t.corpus_id);
        self.mutator.post_exec(state, corpus_id)
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
    fn test_unicode_mutational_push_stage() {
        let rand = StdRand::with_seed(1234);
        let mut corpus = InMemoryCorpus::<BytesInput>::new();
        let testcase = Testcase::new(BytesInput::new(vec![0xE2, 0x82, 0xAC])); // € in UTF-8
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

        let mut stage =
            UnicodeMutationalPushStage::new(crate::mutators::UnicodeCategoryRandMutator);
        let mut mgr = NopEventManager::new();

        PushStage::<NopEventManager, BytesInput, (StdMapObserver<'static, u8, false>, ()), _>::init(&mut stage, &mut state, &mut mgr).unwrap();

        let mut steps = 0;
        while let StageStep::Execute(req) = PushStage::<
            NopEventManager,
            BytesInput,
            (StdMapObserver<'static, u8, false>, ()),
            _,
        >::step(&mut stage, &mut state, &mut mgr)
        .unwrap()
        {
            assert_eq!(req.inputs.len(), 1);
            steps += 1;
        }

        assert!(steps > 0);
        PushStage::<NopEventManager, BytesInput, (StdMapObserver<'static, u8, false>, ()), _>::deinit(&mut stage, &mut state, &mut mgr).unwrap();
    }
}
