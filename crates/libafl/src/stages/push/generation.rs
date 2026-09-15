//! Generation push stage for generating and evaluating fresh inputs.

use alloc::borrow::Cow;
use core::{fmt::Debug, marker::PhantomData};

use libafl_bolts::{Error, Named};

use super::{PushStage, StageStep};
use crate::{
    common::HasNamedMetadata, fuzzer::ExecutionRequest, generators::Generator, inputs::Input,
    stages::Restartable, state::HasRand,
};

/// A stage that generates an input using a [`Generator`] and evaluates it.
#[derive(Debug, Clone)]
pub struct GenerationStage<G, I> {
    name: Cow<'static, str>,
    generator: G,
    runs: usize,
    phantom: PhantomData<I>,
}

/// Backwards compatibility alias for [`GenerationStage`].
pub type GenerationPushStage<G, I> = GenerationStage<G, I>;

impl<G, I> GenerationStage<G, I> {
    /// Create a new single-run generation stage.
    pub fn new(generator: G) -> Self {
        Self::with_runs(generator, 1)
    }

    /// Create a new generation stage with a specified number of runs.
    pub fn with_runs(generator: G, runs: usize) -> Self {
        Self::with_name_and_runs(generator, runs, "GenerationStage")
    }

    /// Create a new generation stage with custom name and runs.
    pub fn with_name_and_runs<N: Into<Cow<'static, str>>>(
        generator: G,
        runs: usize,
        name: N,
    ) -> Self {
        Self {
            name: name.into(),
            generator,
            runs,
            phantom: PhantomData,
        }
    }

    /// Access the generator.
    pub fn generator(&self) -> &G {
        &self.generator
    }

    /// Access the generator (mutable).
    pub fn generator_mut(&mut self) -> &mut G {
        &mut self.generator
    }
}

impl<G, I> Named for GenerationPushStage<G, I> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<G, I, S> Restartable<S> for GenerationPushStage<G, I> {
    fn should_restart(&mut self, _state: &mut S) -> Result<bool, Error> {
        Ok(true)
    }

    fn clear_progress(&mut self, _state: &mut S) -> Result<(), Error> {
        Ok(())
    }
}

impl<EM, G, I, OT, S> PushStage<EM, I, OT, S> for GenerationPushStage<G, I>
where
    G: Generator<I, S>,
    I: Input + Clone,
    S: HasRand + HasNamedMetadata,
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
                    testcases_to_do: self.runs,
                    testcases_done: 0,
                },
            );
        }
        Ok(())
    }

    fn step(&mut self, state: &mut S, _manager: &mut EM) -> Result<StageStep<I>, Error> {
        let (to_do, done) = state
            .named_metadata_map()
            .get::<super::StageProgressMetadata>(&self.name)
            .map_or((self.runs, 0), |m| (m.testcases_to_do, m.testcases_done));

        if done >= to_do {
            return Ok(StageStep::Done);
        }

        let input = self.generator.generate(state)?;

        if let Ok(meta) = state.named_metadata_mut::<super::StageProgressMetadata>(&self.name) {
            meta.testcases_done = done + 1;
        } else {
            state.add_named_metadata(
                &self.name,
                super::StageProgressMetadata {
                    testcases_to_do: self.runs,
                    testcases_done: done + 1,
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
        corpus::{Corpus, HasCurrentCorpusId, InMemoryCorpus, Testcase},
        events::NopEventManager,
        feedbacks::ConstFeedback,
        inputs::BytesInput,
        observers::StdMapObserver,
        state::StdState,
    };

    struct DummyGenerator;
    impl<S> Generator<BytesInput, S> for DummyGenerator {
        fn generate(&mut self, _state: &mut S) -> Result<BytesInput, Error> {
            Ok(BytesInput::new(vec![1, 2, 3]))
        }
    }

    #[test]
    fn test_generation_push_stage() {
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

        let mut stage = GenerationPushStage::with_runs(DummyGenerator, 2);
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
        assert!(matches!(step2, StageStep::Execute(_)));

        let step3 = PushStage::<
            NopEventManager,
            BytesInput,
            (StdMapObserver<'static, u8, false>, ()),
            _,
        >::step(&mut stage, &mut state, &mut mgr)
        .unwrap();
        assert!(matches!(step3, StageStep::Done));

        PushStage::<NopEventManager, BytesInput, (StdMapObserver<'static, u8, false>, ()), _>::deinit(&mut stage, &mut state, &mut mgr).unwrap();
    }
}
