//! Power-scheduled mutational push stage.

use alloc::borrow::Cow;
use core::{fmt::Debug, marker::PhantomData};

use libafl_bolts::{Error, Named};

use super::{PushStage, StageStep};
use crate::{
    common::HasNamedMetadata,
    fuzzer::ExecutionRequest,
    inputs::Input,
    mutators::Mutator,
    schedulers::{TestcaseScore, testcase_score::CorpusPowerTestcaseScore},
    state::{HasCorpus, HasCurrentTestcase, HasRand},
};

/// A mutational stage driven by power schedules.
#[derive(Debug, Clone)]
pub struct StdPowerMutationalStage<F, M, I, S> {
    name: Cow<'static, str>,
    mutator: M,
    phantom: PhantomData<(F, I, S)>,
}

/// Backwards compatibility alias for [`StdPowerMutationalStage`].
pub type StdPowerMutationalPushStage<F, M, I, S> = StdPowerMutationalStage<F, M, I, S>;

impl<M, I, S> StdPowerMutationalStage<CorpusPowerTestcaseScore, M, I, S> {
    /// Create a new power-scheduled mutational stage with default power score.
    #[must_use]
    pub fn new(mutator: M) -> Self {
        Self::with_name(mutator, "StdPowerMutationalStage")
    }

    /// Create a new power-scheduled mutational stage with a custom name.
    #[must_use]
    pub fn with_name<N: Into<Cow<'static, str>>>(mutator: M, name: N) -> Self {
        Self {
            name: name.into(),
            mutator,
            phantom: PhantomData,
        }
    }
}

impl<F, M, I, S> StdPowerMutationalStage<F, M, I, S> {
    /// Create a new power-scheduled mutational stage with custom score calculator.
    #[must_use]
    pub fn with_score(mutator: M) -> Self {
        Self {
            name: Cow::Borrowed("StdPowerMutationalStage"),
            mutator,
            phantom: PhantomData,
        }
    }

    /// Create a new power-scheduled mutational stage with score calculator and custom name.
    #[must_use]
    pub fn with_score_and_name<N: Into<Cow<'static, str>>>(mutator: M, name: N) -> Self {
        Self {
            name: name.into(),
            mutator,
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

impl<F, M, I, S> Named for StdPowerMutationalStage<F, M, I, S> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<EM, F, I, M, OT, S> PushStage<EM, I, OT, S> for StdPowerMutationalStage<F, M, I, S>
where
    F: TestcaseScore<I, S>,
    I: Input + Clone,
    M: Mutator<I, S>,
    S: HasCorpus<I> + HasRand + HasCurrentTestcase<I> + HasNamedMetadata,
{
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    fn init(&mut self, state: &mut S, _manager: &mut EM) -> Result<(), Error> {
        if state
            .named_metadata_map()
            .get::<super::StageProgressMetadata>(&self.name)
            .is_none()
        {
            let iters = {
                let mut tc = state.current_testcase_mut()?;
                let score = F::compute(state, &mut tc)?;
                if score > 0.0 { score as usize } else { 64 }
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
    use core::time::Duration;

    use libafl_bolts::rands::StdRand;

    use super::*;
    use crate::{
        common::HasMetadata,
        corpus::{
            Corpus, HasCurrentCorpusId, HasTestcase, InMemoryCorpus, Testcase,
            testcase::SchedulerTestcaseMetadata,
        },
        events::NopEventManager,
        feedbacks::ConstFeedback,
        inputs::BytesInput,
        mutators::mutations::BitFlipMutator,
        observers::StdMapObserver,
        schedulers::powersched::{PowerSchedule, SchedulerMetadata},
        state::StdState,
    };

    #[test]
    fn test_power_mutational_push_stage() {
        let rand = StdRand::with_seed(1234);
        let mut corpus = InMemoryCorpus::<BytesInput>::new();
        let mut testcase = Testcase::new(BytesInput::new(vec![1, 2, 3, 4]));
        *testcase.exec_time_mut() = Some(Duration::from_millis(10));
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
        state.add_metadata(SchedulerMetadata::new(Some(PowerSchedule::fast())));
        {
            let mut tc = state.testcase_mut(id).unwrap();
            tc.add_metadata(SchedulerTestcaseMetadata::new(0));
        }

        let mut stage = StdPowerMutationalPushStage::new(BitFlipMutator::new());
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
