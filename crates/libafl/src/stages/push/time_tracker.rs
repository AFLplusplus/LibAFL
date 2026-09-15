//! Time tracking push stage wrapper.

use alloc::borrow::Cow;
use core::{fmt::Debug, marker::PhantomData, time::Duration};

use libafl_bolts::{Error, Named, current_time, serdeany::SerdeAny};

use super::{PushStage, StageStep};
use crate::{common::HasMetadata, stages::Restartable};

/// A stage that tracks the execution time of an inner stage.
#[derive(Debug)]
pub struct TimeTrackingStage<ST, T> {
    name: Cow<'static, str>,
    inner: ST,
    accumulated: Duration,
    last_timestamp: Option<Duration>,
    phantom: PhantomData<T>,
}

/// Backwards compatibility alias for [`TimeTrackingStage`].
pub type TimeTrackingPushStage<ST, T> = TimeTrackingStage<ST, T>;

impl<ST, T> TimeTrackingStage<ST, T>
where
    ST: Named,
{
    /// Create a new `TimeTrackingStage`.
    pub fn new(inner: ST) -> Self {
        let name = Cow::Owned(alloc::format!("TimeTrackingStage({})", inner.name()));
        Self {
            name,
            inner,
            accumulated: Duration::ZERO,
            last_timestamp: None,
            phantom: PhantomData,
        }
    }
}

impl<ST, T> Named for TimeTrackingStage<ST, T> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<ST, T, S> Restartable<S> for TimeTrackingPushStage<ST, T>
where
    ST: Restartable<S>,
{
    fn should_restart(&mut self, state: &mut S) -> Result<bool, Error> {
        self.inner.should_restart(state)
    }

    fn clear_progress(&mut self, state: &mut S) -> Result<(), Error> {
        self.inner.clear_progress(state)
    }
}

impl<EM, I, OT, S, ST, T> PushStage<EM, I, OT, S> for TimeTrackingPushStage<ST, T>
where
    ST: PushStage<EM, I, OT, S>,
    S: HasMetadata,
    T: SerdeAny + From<Duration>,
{
    fn init(&mut self, state: &mut S, manager: &mut EM) -> Result<(), Error> {
        let now = current_time();
        self.last_timestamp = Some(now);
        self.inner.init(state, manager)?;
        let after = current_time();
        self.accumulated += after.saturating_sub(now);
        self.last_timestamp = Some(after);
        Ok(())
    }

    fn step(&mut self, state: &mut S, manager: &mut EM) -> Result<StageStep<I>, Error> {
        let now = current_time();
        if let Some(prev) = self.last_timestamp {
            self.accumulated += now.saturating_sub(prev);
        }
        let step_res = self.inner.step(state, manager);
        let after = current_time();
        self.accumulated += after.saturating_sub(now);
        self.last_timestamp = Some(after);

        if let Ok(meta) = state.metadata_mut::<T>() {
            *meta = T::from(self.accumulated);
        } else {
            state.add_metadata::<T>(T::from(self.accumulated));
        }

        step_res
    }

    fn post_exec(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        obs: crate::fuzzer::BorrowedObservation<'_, I, OT>,
    ) -> Result<(), Error> {
        self.inner.post_exec(state, manager, obs)
    }

    fn deinit(&mut self, state: &mut S, manager: &mut EM) -> Result<(), Error> {
        let now = current_time();
        if let Some(prev) = self.last_timestamp.take() {
            self.accumulated += now.saturating_sub(prev);
        }
        self.inner.deinit(state, manager)?;
        self.accumulated += current_time().saturating_sub(now);

        if let Ok(meta) = state.metadata_mut::<T>() {
            *meta = T::from(self.accumulated);
        } else {
            state.add_metadata::<T>(T::from(self.accumulated));
        }

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

    use libafl_bolts::{impl_serdeany, rands::StdRand};
    use serde::{Deserialize, Serialize};

    use super::*;
    use crate::{
        corpus::{Corpus, HasCurrentCorpusId, InMemoryCorpus, Testcase},
        events::NopEventManager,
        feedbacks::ConstFeedback,
        inputs::BytesInput,
        observers::StdMapObserver,
        stages::push::CalibrationPushStage,
        state::StdState,
    };

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct DummyTime(Duration);
    impl_serdeany!(DummyTime);
    impl From<Duration> for DummyTime {
        fn from(d: Duration) -> Self {
            Self(d)
        }
    }

    #[test]
    fn test_time_tracking_push_stage() {
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

        let inner = CalibrationPushStage::with_runs(1);
        let mut stage = TimeTrackingPushStage::<_, DummyTime>::new(inner);
        let mut mgr = NopEventManager::new();

        PushStage::<NopEventManager, BytesInput, (StdMapObserver<'static, u8, false>, ()), _>::init(&mut stage, &mut state, &mut mgr).unwrap();

        let res = PushStage::<
            NopEventManager,
            BytesInput,
            (StdMapObserver<'static, u8, false>, ()),
            _,
        >::step(&mut stage, &mut state, &mut mgr)
        .unwrap();
        assert!(matches!(res, StageStep::Execute(_)));

        PushStage::<NopEventManager, BytesInput, (StdMapObserver<'static, u8, false>, ()), _>::deinit(&mut stage, &mut state, &mut mgr).unwrap();
        assert!(state.has_metadata::<DummyTime>());
    }
}
