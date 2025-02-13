//! Stage that wraps another stage and tracks it's execution time in `State`
use std::{marker::PhantomData, time::Duration};

use libafl_bolts::{current_time, Error};

use crate::{stages::Stage, HasMetadata};
/// Track an inner Stage's execution time
#[derive(Debug)]
pub struct TimeTrackingStageWrapper<T, S, ST> {
    inner: ST,
    count: Duration,
    phantom: PhantomData<(T, S)>,
}

impl<T, S, ST> TimeTrackingStageWrapper<T, S, ST> {
    /// Create a `TimeTrackingStageWrapper`
    pub fn new(inner: ST) -> Self {
        Self {
            inner,
            count: Duration::from_secs(0),
            phantom: PhantomData,
        }
    }
}

impl<T, E, M, Z, S, ST> Stage<E, M, S, Z> for TimeTrackingStageWrapper<T, S, ST>
where
    S: HasMetadata,
    ST: Stage<E, M, S, Z>,
    T: libafl_bolts::serdeany::SerdeAny + From<Duration>,
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut M,
    ) -> Result<(), Error> {
        let before_run = current_time();
        self.inner.perform(fuzzer, executor, state, manager)?;
        let after_run = current_time();
        self.count += after_run - before_run;
        *state.metadata_mut::<T>()? = T::from(self.count);
        Ok(())
    }

    fn should_restart(&mut self, state: &mut S) -> Result<bool, Error> {
        self.inner.should_restart(state)
    }

    fn clear_progress(&mut self, state: &mut S) -> Result<(), Error> {
        self.inner.clear_progress(state)
    }

    fn perform_restartable(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut M,
    ) -> Result<(), Error> {
        self.inner
            .perform_restartable(fuzzer, executor, state, manager)
    }
}
