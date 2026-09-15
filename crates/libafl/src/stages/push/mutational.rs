//! Mutational push stages for pure fuzzing engines.

use alloc::{borrow::Cow, vec::Vec};
use core::{fmt::Debug, marker::PhantomData};

use libafl_bolts::{Error, Named, nonzero, rands::Rand};

use super::{PushStage, StageStep};
use crate::{
    common::HasNamedMetadata,
    corpus::HasCurrentCorpusId,
    fuzzer::ExecutionRequest,
    inputs::Input,
    mutators::{MultiMutator, MutationResult, Mutator},
    stages::{
        Restartable, RetryCountRestartHelper,
        mutational::{MutatedTransform, MutatedTransformPost},
    },
    state::{HasCorpus, HasCurrentTestcase, HasRand},
};

/// Default maximum iterations per corpus item in mutational stage.
pub const DEFAULT_MUTATIONAL_MAX_ITERATIONS: usize = 128;

/// A mutational stage that applies mutations and yields single inputs or batches.
#[derive(Debug, Clone)]
pub struct StdMutationalStage<M> {
    name: Cow<'static, str>,
    mutator: M,
    batch_size: usize,
}

/// Backwards compatibility alias for [`StdMutationalStage`].
pub type StdMutationalPushStage<M> = StdMutationalStage<M>;

impl<M> StdMutationalStage<M> {
    /// Create a new mutational stage.
    #[must_use]
    pub fn new(mutator: M) -> Self {
        Self::with_name(mutator, "StdMutationalStage")
    }

    /// Create a new mutational stage with a custom name.
    #[must_use]
    pub fn with_name<N: Into<Cow<'static, str>>>(mutator: M, name: N) -> Self {
        Self {
            name: name.into(),
            mutator,
            batch_size: 1,
        }
    }

    /// Create a new mutational stage with a configurable batch size.
    #[must_use]
    pub fn with_batch_size(mutator: M, batch_size: usize) -> Self {
        Self::with_batch_size_and_name(mutator, batch_size, "StdMutationalStage")
    }

    /// Create a new mutational stage with a custom batch size and name.
    #[must_use]
    pub fn with_batch_size_and_name<N: Into<Cow<'static, str>>>(
        mutator: M,
        batch_size: usize,
        name: N,
    ) -> Self {
        Self {
            name: name.into(),
            mutator,
            batch_size: batch_size.max(1),
        }
    }

    /// Access the batch size.
    #[must_use]
    pub fn batch_size(&self) -> usize {
        self.batch_size
    }

    /// Set the batch size.
    pub fn set_batch_size(&mut self, batch_size: usize) {
        self.batch_size = batch_size.max(1);
    }

    /// Access the mutator.
    pub fn mutator(&self) -> &M {
        &self.mutator
    }

    /// Access the mutator (mutable).
    pub fn mutator_mut(&mut self) -> &mut M {
        &mut self.mutator
    }

    /// Create a new transforming mutational stage
    pub fn transforming<I1, I2, P>(mutator: M) -> StdTransformingMutationalStage<I1, I2, M, P> {
        StdTransformingMutationalStage::new(mutator)
    }
}

impl<M> Named for StdMutationalStage<M> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<EM, I, M, OT, S> PushStage<EM, I, OT, S> for StdMutationalStage<M>
where
    I: Input + Clone,
    M: Mutator<I, S>,
    S: HasCorpus<I> + HasRand + HasCurrentTestcase<I> + HasNamedMetadata,
{
    fn init(&mut self, state: &mut S, _manager: &mut EM) -> Result<(), Error> {
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

        let remaining = to_do - done;
        let count = remaining.min(self.batch_size);

        if count == 1 {
            let mut input = state.current_input_cloned()?;
            done += 1;
            if self.mutator.mutate(state, &mut input)? == MutationResult::Mutated {
                if let Ok(meta) =
                    state.named_metadata_mut::<super::StageProgressMetadata>(&self.name)
                {
                    meta.testcases_done = done;
                }
                return Ok(StageStep::Execute(ExecutionRequest::single(input)));
            }

            if done < to_do {
                let base_input = state.current_input_cloned()?;
                while done < to_do {
                    let mut input = base_input.clone();
                    done += 1;
                    if self.mutator.mutate(state, &mut input)? == MutationResult::Mutated {
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
        } else {
            let base_input = state.current_input_cloned()?;
            let mut inputs = Vec::with_capacity(count);
            while done < to_do && inputs.len() < count {
                let mut input = base_input.clone();
                done += 1;
                if self.mutator.mutate(state, &mut input)? == MutationResult::Mutated {
                    inputs.push(input);
                }
            }

            if let Ok(meta) = state.named_metadata_mut::<super::StageProgressMetadata>(&self.name) {
                meta.testcases_done = done;
            }

            if inputs.is_empty() {
                Ok(StageStep::Done)
            } else {
                Ok(StageStep::Execute(ExecutionRequest::batch(inputs)))
            }
        }
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

/// A multi-mutational stage that applies [`MultiMutator`]s (e.g. `RedQueen`) and yields batches of generated inputs.
#[derive(Debug, Clone)]
pub struct MultiMutationalStage<M, I> {
    name: Cow<'static, str>,
    mutator: M,
    generated_inputs: Vec<I>,
    batch_size: Option<usize>,
}

/// Backwards compatibility alias for [`MultiMutationalStage`].
pub type MultiMutationalPushStage<M, I> = MultiMutationalStage<M, I>;

impl<M, I> MultiMutationalStage<M, I> {
    /// Create a new multi-mutational stage.
    #[must_use]
    pub fn new(mutator: M) -> Self {
        Self::with_name(mutator, "MultiMutationalStage")
    }

    /// Create a new multi-mutational stage with a custom name.
    #[must_use]
    pub fn with_name<N: Into<Cow<'static, str>>>(mutator: M, name: N) -> Self {
        Self {
            name: name.into(),
            mutator,
            generated_inputs: Vec::new(),
            batch_size: None,
        }
    }

    /// Set a custom batch size for yielding inputs.
    #[must_use]
    pub fn with_batch_size(mut self, batch_size: usize) -> Self {
        self.batch_size = Some(batch_size);
        self
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

impl<M, I> Named for MultiMutationalStage<M, I> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<EM, I, M, OT, S> PushStage<EM, I, OT, S> for MultiMutationalStage<M, I>
where
    I: Input + Clone,
    M: MultiMutator<I, S>,
    S: HasCorpus<I> + HasCurrentTestcase<I> + HasNamedMetadata,
{
    fn init(&mut self, state: &mut S, _manager: &mut EM) -> Result<(), Error> {
        let input = state.current_input_cloned()?;
        self.generated_inputs = self.mutator.multi_mutate(state, &input, None)?;
        if state
            .named_metadata_map()
            .get::<super::StageProgressMetadata>(&self.name)
            .is_none()
        {
            state.add_named_metadata(
                &self.name,
                super::StageProgressMetadata {
                    testcases_to_do: self.generated_inputs.len(),
                    testcases_done: 0,
                },
            );
        }
        Ok(())
    }

    fn step(&mut self, state: &mut S, _manager: &mut EM) -> Result<StageStep<I>, Error> {
        let (to_do, current_index) = state
            .named_metadata_map()
            .get::<super::StageProgressMetadata>(&self.name)
            .map_or((0, 0), |m| (m.testcases_to_do, m.testcases_done));

        if current_index >= to_do {
            return Ok(StageStep::Done);
        }

        if self.generated_inputs.is_empty() {
            let input = state.current_input_cloned()?;
            self.generated_inputs = self.mutator.multi_mutate(state, &input, None)?;
        }

        if current_index >= self.generated_inputs.len() {
            return Ok(StageStep::Done);
        }

        let chunk_size = self
            .batch_size
            .unwrap_or_else(|| self.generated_inputs.len() - current_index);
        let end = (current_index + chunk_size).min(self.generated_inputs.len());
        let chunk = if current_index == 0 && end == self.generated_inputs.len() {
            core::mem::take(&mut self.generated_inputs)
        } else {
            self.generated_inputs[current_index..end].to_vec()
        };

        if let Ok(meta) = state.named_metadata_mut::<super::StageProgressMetadata>(&self.name) {
            meta.testcases_done = end;
        }

        Ok(StageStep::Execute(ExecutionRequest::batch(chunk)))
    }

    fn post_exec(
        &mut self,
        state: &mut S,
        _manager: &mut EM,
        obs: crate::fuzzer::BorrowedObservation<'_, I, OT>,
    ) -> Result<(), Error> {
        let corpus_id = obs.tag.and_then(|t| t.corpus_id);
        self.mutator.multi_post_exec(state, corpus_id)
    }

    fn deinit(&mut self, state: &mut S, _manager: &mut EM) -> Result<(), Error> {
        self.generated_inputs.clear();
        let _ = state
            .named_metadata_map_mut()
            .remove::<super::StageProgressMetadata>(&self.name);
        Ok(())
    }
}

/// A transforming mutational push stage that transforms an input to a target representation,
/// mutates it, and converts it back before execution.
#[derive(Debug, Clone)]
pub struct StdTransformingMutationalStage<I1, I2, M, P = ()> {
    name: Cow<'static, str>,
    mutator: M,
    base_transformed: Option<I1>,
    last_post: Option<P>,
    phantom: PhantomData<(I2, P)>,
}

/// Backwards compatibility alias for [`StdTransformingMutationalStage`].
pub type StdTransformingMutationalPushStage<I1, I2, M, P = ()> =
    StdTransformingMutationalStage<I1, I2, M, P>;

impl<I1, I2, M, P> StdTransformingMutationalStage<I1, I2, M, P> {
    /// Create a new transforming mutational stage.
    #[must_use]
    pub fn new(mutator: M) -> Self {
        Self::with_name(mutator, "StdTransformingMutationalStage")
    }

    /// Create a new transforming mutational stage (alias for [`Self::new`]).
    #[must_use]
    pub fn transforming(mutator: M) -> Self {
        Self::new(mutator)
    }

    /// Create a new transforming mutational stage with a custom name.
    #[must_use]
    pub fn with_name<N: Into<Cow<'static, str>>>(mutator: M, name: N) -> Self {
        Self {
            name: name.into(),
            mutator,
            base_transformed: None,
            last_post: None,
            phantom: PhantomData,
        }
    }

    /// Access the mutator.
    #[must_use]
    pub fn mutator(&self) -> &M {
        &self.mutator
    }

    /// Access the mutator (mutable).
    pub fn mutator_mut(&mut self) -> &mut M {
        &mut self.mutator
    }
}

impl<I1, I2, M, P> Named for StdTransformingMutationalStage<I1, I2, M, P> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<I1, I2, M, P, S> Restartable<S> for StdTransformingMutationalStage<I1, I2, M, P>
where
    S: HasNamedMetadata + HasCurrentCorpusId,
{
    fn should_restart(&mut self, state: &mut S) -> Result<bool, Error> {
        RetryCountRestartHelper::should_restart(state, &self.name, 3)
    }

    fn clear_progress(&mut self, state: &mut S) -> Result<(), Error> {
        RetryCountRestartHelper::clear_progress(state, &self.name)
    }
}

impl<EM, I1, I2, M, OT, P, S> PushStage<EM, I2, OT, S>
    for StdTransformingMutationalStage<I1, I2, M, P>
where
    I1: MutatedTransform<I2, S, Post = P> + Clone,
    I2: Input,
    M: Mutator<I1, S>,
    P: MutatedTransformPost<S>,
    S: HasCorpus<I2> + HasCurrentTestcase<I2> + HasRand + HasNamedMetadata,
{
    fn init(&mut self, state: &mut S, _manager: &mut EM) -> Result<(), Error> {
        let mut testcase = state.current_testcase_mut()?;
        if let Ok(transformed) = I1::try_transform_from(&mut testcase, state) {
            self.base_transformed = Some(transformed);
        } else {
            self.base_transformed = None;
        }
        drop(testcase);

        if state
            .named_metadata_map()
            .get::<super::StageProgressMetadata>(&self.name)
            .is_none()
        {
            let iters = state
                .rand_mut()
                .below(nonzero!(DEFAULT_MUTATIONAL_MAX_ITERATIONS))
                + 1;
            state.add_named_metadata(
                &self.name,
                super::StageProgressMetadata {
                    testcases_to_do: iters,
                    testcases_done: 0,
                },
            );
        }
        self.last_post = None;
        Ok(())
    }

    fn step(&mut self, state: &mut S, _manager: &mut EM) -> Result<StageStep<I2>, Error> {
        let (to_do, mut done) = state
            .named_metadata_map()
            .get::<super::StageProgressMetadata>(&self.name)
            .map_or((0, 0), |m| (m.testcases_to_do, m.testcases_done));

        if done >= to_do {
            return Ok(StageStep::Done);
        }

        if self.base_transformed.is_none() {
            let mut testcase = state.current_testcase_mut()?;
            if let Ok(transformed) = I1::try_transform_from(&mut testcase, state) {
                self.base_transformed = Some(transformed);
            }
            drop(testcase);
        }

        let Some(ref base) = self.base_transformed else {
            return Ok(StageStep::Done);
        };

        let mut mutated = false;
        let mut transformed = base.clone();
        while done < to_do {
            done += 1;
            let res = self.mutator.mutate(state, &mut transformed)?;
            if res == MutationResult::Mutated {
                mutated = true;
                break;
            }
            transformed = base.clone();
        }
        if let Ok(meta) = state.named_metadata_mut::<super::StageProgressMetadata>(&self.name) {
            meta.testcases_done = done;
        }
        if !mutated {
            return Ok(StageStep::Done);
        }

        let (input, post) = transformed.try_transform_into(state)?;
        self.last_post = Some(post);

        Ok(StageStep::Execute(ExecutionRequest::single(input)))
    }

    fn post_exec(
        &mut self,
        state: &mut S,
        _manager: &mut EM,
        obs: crate::fuzzer::BorrowedObservation<'_, I2, OT>,
    ) -> Result<(), Error> {
        let corpus_id = obs.tag.and_then(|t| t.corpus_id);
        self.mutator.post_exec(state, corpus_id)?;
        if let Some(post) = self.last_post.take() {
            post.post_exec(state, corpus_id)?;
        }
        Ok(())
    }

    fn deinit(&mut self, state: &mut S, _manager: &mut EM) -> Result<(), Error> {
        self.base_transformed = None;
        self.last_post = None;
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
    fn test_std_mutational_push_stage() {
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

        let mut stage = StdMutationalPushStage::new(BitFlipMutator::new());
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

    #[derive(Debug)]
    struct SkippingMutator {
        name: Cow<'static, str>,
        calls: usize,
        mutate_on_call: Option<usize>,
    }

    impl Named for SkippingMutator {
        fn name(&self) -> &Cow<'static, str> {
            &self.name
        }
    }

    impl<I, S> Mutator<I, S> for SkippingMutator {
        fn mutate(&mut self, _state: &mut S, _input: &mut I) -> Result<MutationResult, Error> {
            self.calls += 1;
            if Some(self.calls) == self.mutate_on_call {
                Ok(MutationResult::Mutated)
            } else {
                Ok(MutationResult::Skipped)
            }
        }

        fn post_exec(
            &mut self,
            _state: &mut S,
            _new_corpus_id: Option<crate::corpus::CorpusId>,
        ) -> Result<(), Error> {
            Ok(())
        }
    }

    #[test]
    fn test_std_mutational_push_stage_skips_on_skipped_mutation() {
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
        let mut mgr = NopEventManager::new();

        // Mutator that skips on calls 1 & 2, mutates on call 3, and skips thereafter
        let mut stage = StdMutationalPushStage::new(SkippingMutator {
            name: Cow::Borrowed("skipping"),
            calls: 0,
            mutate_on_call: Some(3),
        });

        PushStage::<NopEventManager, BytesInput, (StdMapObserver<'static, u8, false>, ()), _>::init(&mut stage, &mut state, &mut mgr).unwrap();
        if let Ok(meta) =
            state.named_metadata_mut::<crate::stages::StageProgressMetadata>(stage.name())
        {
            meta.testcases_to_do = 5;
        }

        // First step should skip 2 calls and return Execute on the 3rd call
        let step1 = PushStage::<
            NopEventManager,
            BytesInput,
            (StdMapObserver<'static, u8, false>, ()),
            _,
        >::step(&mut stage, &mut state, &mut mgr)
        .unwrap();
        assert!(matches!(step1, StageStep::Execute(_)));
        assert_eq!(stage.mutator().calls, 3);

        // Second step should skip remaining 2 calls (4 and 5) and return Done without executing
        let step2 = PushStage::<
            NopEventManager,
            BytesInput,
            (StdMapObserver<'static, u8, false>, ()),
            _,
        >::step(&mut stage, &mut state, &mut mgr)
        .unwrap();
        assert!(matches!(step2, StageStep::Done));
        assert_eq!(stage.mutator().calls, 5);

        PushStage::<NopEventManager, BytesInput, (StdMapObserver<'static, u8, false>, ()), _>::deinit(&mut stage, &mut state, &mut mgr).unwrap();
    }
}
