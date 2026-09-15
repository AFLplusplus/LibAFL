//! Dynamic push stage for switching between stages at runtime.

use alloc::borrow::Cow;
use core::fmt::Debug;

use libafl_bolts::{Error, Named};

use super::{PushStage, StageStep};
use crate::stages::Restartable;

/// A dynamic stage that can hold either of two stage types.
#[derive(Debug, Clone)]
pub enum DynamicStage<T1, T2> {
    /// The first stage variant.
    Stage1(T1),
    /// The second stage variant.
    Stage2(T2),
}

/// Backwards compatibility alias for [`DynamicStage`].
pub type DynamicPushStage<T1, T2> = DynamicStage<T1, T2>;

impl<T1, T2> Named for DynamicStage<T1, T2>
where
    T1: Named,
    T2: Named,
{
    fn name(&self) -> &Cow<'static, str> {
        match self {
            Self::Stage1(st1) => st1.name(),
            Self::Stage2(st2) => st2.name(),
        }
    }
}

impl<T1, T2, S> Restartable<S> for DynamicPushStage<T1, T2>
where
    T1: Restartable<S>,
    T2: Restartable<S>,
{
    fn should_restart(&mut self, state: &mut S) -> Result<bool, Error> {
        match self {
            Self::Stage1(st1) => st1.should_restart(state),
            Self::Stage2(st2) => st2.should_restart(state),
        }
    }

    fn clear_progress(&mut self, state: &mut S) -> Result<(), Error> {
        match self {
            Self::Stage1(st1) => st1.clear_progress(state),
            Self::Stage2(st2) => st2.clear_progress(state),
        }
    }
}

impl<EM, I, OT, S, T1, T2> PushStage<EM, I, OT, S> for DynamicPushStage<T1, T2>
where
    T1: PushStage<EM, I, OT, S>,
    T2: PushStage<EM, I, OT, S>,
{
    fn init(&mut self, state: &mut S, manager: &mut EM) -> Result<(), Error> {
        match self {
            Self::Stage1(st1) => st1.init(state, manager),
            Self::Stage2(st2) => st2.init(state, manager),
        }
    }

    fn step(&mut self, state: &mut S, manager: &mut EM) -> Result<StageStep<I>, Error> {
        match self {
            Self::Stage1(st1) => st1.step(state, manager),
            Self::Stage2(st2) => st2.step(state, manager),
        }
    }

    fn post_exec(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        obs: crate::fuzzer::BorrowedObservation<'_, I, OT>,
    ) -> Result<(), Error> {
        match self {
            Self::Stage1(st1) => st1.post_exec(state, manager, obs),
            Self::Stage2(st2) => st2.post_exec(state, manager, obs),
        }
    }

    fn deinit(&mut self, state: &mut S, manager: &mut EM) -> Result<(), Error> {
        match self {
            Self::Stage1(st1) => st1.deinit(state, manager),
            Self::Stage2(st2) => st2.deinit(state, manager),
        }
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
        stages::push::{calibrate::CalibrationPushStage, shadow::ShadowPushStage},
        state::StdState,
    };

    #[test]
    fn test_dynamic_push_stage() {
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

        let mut stage = DynamicPushStage::<CalibrationPushStage, ShadowPushStage>::Stage1(
            CalibrationPushStage::with_runs(2),
        );
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
