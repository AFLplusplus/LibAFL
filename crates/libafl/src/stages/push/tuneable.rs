//! A [`PushStage`] where the mutator iteration can be tuned at runtime.

use alloc::borrow::Cow;
use core::fmt::Debug;

use libafl_bolts::{Error, Named, nonzero, rands::Rand};

use super::{PushStage, StageStep};
use crate::{
    common::HasNamedMetadata,
    fuzzer::ExecutionRequest,
    inputs::Input,
    mutators::Mutator,
    stages::{
        push::mutational::DEFAULT_MUTATIONAL_MAX_ITERATIONS,
        tuneable::{
            STD_TUNEABLE_MUTATIONAL_STAGE_NAME, TuneableMutationalStageMetadata, get_iters_by_name,
        },
    },
    state::{HasCorpus, HasCurrentTestcase, HasRand},
};

/// A mutational stage where iterations can be tuned at runtime.
#[derive(Debug, Clone)]
pub struct TuneableMutationalStage<M> {
    name: Cow<'static, str>,
    mutator: M,
}

/// Backwards compatibility alias for [`TuneableMutationalStage`].
pub type TuneableMutationalPushStage<M> = TuneableMutationalStage<M>;

impl<M> TuneableMutationalStage<M> {
    /// Create a new tuneable mutational stage.
    #[must_use]
    pub fn new(mutator: M) -> Self {
        Self::with_name(mutator, STD_TUNEABLE_MUTATIONAL_STAGE_NAME)
    }

    /// Create a new tuneable mutational stage with a custom name.
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

impl<M> Named for TuneableMutationalPushStage<M> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<EM, I, M, OT, S> PushStage<EM, I, OT, S> for TuneableMutationalPushStage<M>
where
    I: Input + Clone,
    M: Mutator<I, S>,
    S: HasCorpus<I> + HasRand + HasNamedMetadata + HasCurrentTestcase<I>,
{
    fn init(&mut self, state: &mut S, _manager: &mut EM) -> Result<(), Error> {
        if state
            .named_metadata_map()
            .get::<TuneableMutationalStageMetadata>(&self.name)
            .is_none()
        {
            state.add_named_metadata(&self.name, TuneableMutationalStageMetadata::default());
        }

        let tuned_iters = get_iters_by_name(state, &self.name)
            .ok()
            .flatten()
            .map(|n| n as usize);

        if let Some(meta) = state
            .named_metadata_map()
            .get::<super::StageProgressMetadata>(&self.name)
            .copied()
        {
            if let Some(tuned) = tuned_iters
                && meta.testcases_done == 0
                && meta.testcases_to_do != tuned
                && let Ok(meta_mut) =
                    state.named_metadata_mut::<super::StageProgressMetadata>(&self.name)
            {
                meta_mut.testcases_to_do = tuned;
            }
        } else {
            let iters = if let Some(tuned) = tuned_iters {
                tuned
            } else {
                1 + state
                    .rand_mut()
                    .below(nonzero!(DEFAULT_MUTATIONAL_MAX_ITERATIONS))
            };
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

        let mut input = state.current_input_cloned()?;
        done += 1;
        if self.mutator.mutate(state, &mut input)? == crate::mutators::MutationResult::Mutated {
            if let Ok(meta) = state.named_metadata_mut::<super::StageProgressMetadata>(&self.name) {
                meta.testcases_done = done;
            }
            return Ok(StageStep::Execute(ExecutionRequest::single(input)));
        }

        if done < to_do {
            let base_input = state.current_input_cloned()?;
            while done < to_do {
                let mut input = base_input.clone();
                done += 1;
                if self.mutator.mutate(state, &mut input)?
                    == crate::mutators::MutationResult::Mutated
                {
                    if let Ok(meta) =
                        state.named_metadata_mut::<super::StageProgressMetadata>(&self.name)
                    {
                        meta.testcases_done = done;
                    }
                    return Ok(StageStep::Execute(ExecutionRequest::single(input)));
                }
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
        mutators::mutations::BitFlipMutator,
        observers::StdMapObserver,
        state::StdState,
    };

    #[test]
    fn test_tuneable_mutational_push_stage() {
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

        let mut stage = TuneableMutationalPushStage::new(BitFlipMutator::new());
        let mut mgr = NopEventManager::new();

        PushStage::<NopEventManager, BytesInput, (StdMapObserver<'static, u8, false>, ()), _>::init(&mut stage, &mut state, &mut mgr).unwrap();

        // Tune to exactly 5 iterations and re-init
        crate::stages::tuneable::set_iters_by_name(&mut state, 5, stage.name()).unwrap();
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

        assert_eq!(steps, 5);
        PushStage::<NopEventManager, BytesInput, (StdMapObserver<'static, u8, false>, ()), _>::deinit(&mut stage, &mut state, &mut mgr).unwrap();
    }
}
