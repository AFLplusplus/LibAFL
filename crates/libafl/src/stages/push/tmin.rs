//! Corpus entry minimizing push stage.

use alloc::borrow::Cow;
use core::{fmt::Debug, hash::Hash, marker::PhantomData};

use libafl_bolts::{Error, HasLen, Named};

use super::{PushStage, StageStep};
use crate::{
    common::HasNamedMetadata,
    feedbacks::{Feedback, FeedbackFactory},
    fuzzer::ExecutionRequest,
    inputs::Input,
    mutators::Mutator,
    observers::ObserversTuple,
    stages::{ExecutionCountRestartHelper, Restartable, tmin::TMIN_STAGE_NAME},
    state::{HasCorpus, HasCurrentTestcase, HasExecutions},
};

/// The default corpus entry minimising mutational stage.
#[derive(Debug, Clone)]
pub struct StdTMinMutationalStage<F, FF, I, M> {
    name: Cow<'static, str>,
    mutator: M,
    factory: FF,
    runs: usize,
    current_min: Option<I>,
    feedback: Option<F>,
    restart_helper: ExecutionCountRestartHelper,
    phantom: PhantomData<I>,
}

/// Backwards compatibility alias for [`StdTMinMutationalStage`].
pub type StdTMinMutationalPushStage<F, FF, I, M> = StdTMinMutationalStage<F, FF, I, M>;

impl<F, FF, I, M> StdTMinMutationalStage<F, FF, I, M> {
    /// Create a new testcase minimizing stage.
    #[must_use]
    pub fn new(mutator: M, factory: FF, runs: usize) -> Self {
        Self::with_name(mutator, factory, runs, TMIN_STAGE_NAME)
    }

    /// Create a new testcase minimizing stage with a custom name.
    #[must_use]
    pub fn with_name<N: Into<Cow<'static, str>>>(
        mutator: M,
        factory: FF,
        runs: usize,
        name: N,
    ) -> Self {
        Self {
            name: name.into(),
            mutator,
            factory,
            runs,
            current_min: None,
            feedback: None,
            restart_helper: ExecutionCountRestartHelper::new(),
            phantom: PhantomData,
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

impl<F, FF, I, M> Named for StdTMinMutationalPushStage<F, FF, I, M> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<F, FF, I, M, S> Restartable<S> for StdTMinMutationalPushStage<F, FF, I, M>
where
    S: HasNamedMetadata + HasExecutions,
{
    fn should_restart(&mut self, state: &mut S) -> Result<bool, Error> {
        self.restart_helper.should_restart(state, &self.name)
    }

    fn clear_progress(&mut self, state: &mut S) -> Result<(), Error> {
        self.restart_helper.clear_progress(state, &self.name)
    }
}

impl<EM, F, FF, I, M, OT, S> PushStage<EM, I, OT, S> for StdTMinMutationalPushStage<F, FF, I, M>
where
    F: Feedback<EM, I, OT, S>,
    FF: FeedbackFactory<F, OT>,
    I: Input + HasLen + Hash + Clone + Debug,
    M: Mutator<I, S>,
    OT: ObserversTuple<I, S>,
    S: HasCorpus<I> + HasCurrentTestcase<I> + HasNamedMetadata + HasExecutions,
{
    fn init(&mut self, state: &mut S, _manager: &mut EM) -> Result<(), Error> {
        let input = state.current_input_cloned()?;
        self.current_min = Some(input);
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
        self.feedback = None;
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

        let base_candidate = self
            .current_min
            .clone()
            .unwrap_or_else(|| state.current_input_cloned().unwrap());

        let mut done = done;
        while done < to_do {
            let mut candidate = base_candidate.clone();
            done += 1;
            if self.mutator.mutate(state, &mut candidate)?
                == crate::mutators::MutationResult::Mutated
            {
                if let Ok(meta) =
                    state.named_metadata_mut::<super::StageProgressMetadata>(&self.name)
                {
                    meta.testcases_done = done;
                }
                return Ok(StageStep::Execute(ExecutionRequest::single(candidate)));
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
        manager: &mut EM,
        obs: crate::fuzzer::BorrowedObservation<'_, I, OT>,
    ) -> Result<(), Error> {
        if self.feedback.is_none() {
            self.feedback = Some(self.factory.create_feedback(obs.observers));
        }

        if self.current_min.is_none() {
            self.current_min = state.current_input_cloned().ok();
        }

        let candidate = obs.input;
        if let (Some(feedback), Some(current_min)) = (&mut self.feedback, &self.current_min) {
            let is_interesting = feedback.is_interesting(
                state,
                manager,
                candidate,
                obs.observers,
                &obs.exit_kind,
            )?;

            if is_interesting && candidate.len() < current_min.len() {
                // Found a smaller interesting input!
                *self.current_min.as_mut().unwrap() = candidate.clone();
                let mut tc = state.current_testcase_mut()?;
                *tc.input_mut() = Some(candidate.clone());
            }
        }

        let corpus_id = obs.tag.and_then(|t| t.corpus_id);
        self.mutator.post_exec(state, corpus_id)
    }

    fn deinit(&mut self, state: &mut S, _manager: &mut EM) -> Result<(), Error> {
        self.current_min = None;
        self.feedback = None;
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

    #[derive(Debug, Clone)]
    struct DummyFeedbackFactory;

    impl<OT> FeedbackFactory<ConstFeedback, OT> for DummyFeedbackFactory {
        fn create_feedback(&self, _ctx: &OT) -> ConstFeedback {
            ConstFeedback::new(true)
        }
    }

    #[test]
    fn test_tmin_push_stage() {
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

        let mut stage =
            StdTMinMutationalPushStage::new(BitFlipMutator::new(), DummyFeedbackFactory, 3);
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

        assert_eq!(steps, 3);
        PushStage::<NopEventManager, BytesInput, (StdMapObserver<'static, u8, false>, ()), _>::deinit(&mut stage, &mut state, &mut mgr).unwrap();
    }
}
