//! Stage that wraps another stage and tracks it's execution time in `State`
use std::{marker::PhantomData, time::Duration};

use libafl_bolts::{current_time, Error};

use crate::{
    inputs::UsesInput,
    stages::Stage,
    state::{State, UsesState},
    HasMetadata,
};
/// Track an inner Stage's execution time 
/// ```
///#[derive(Debug, SerdeAny, Serialize, Deserialize)]
///pub struct FuzzTime(pub Duration);
///impl From<Duration> for FuzzTime {
///    fn from(value: Duration) -> Self {
///        Self(value)
///    }
///}
/// TimeTrackingStageWrapper::<FuzzTime, _, _>::new(my_fuzz_stage);
/// state.metadata::<FuzzTime>();
/// ```
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

impl<T, S, ST> UsesState for TimeTrackingStageWrapper<T, S, ST>
where
    S: State + HasMetadata,
{
    type State = S;
}

impl<T, E, M, Z, S, ST> Stage<E, M, Z> for TimeTrackingStageWrapper<T, S, ST>
where
    S: UsesInput + State + HasMetadata,
    ST: Stage<E, M, Z, State = S>,
    M: UsesState<State = S>,
    Z: UsesState<State = S>,
    E: UsesState<State = S>,
    T: libafl_bolts::serdeany::SerdeAny + From<Duration>,
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Self::State,
        manager: &mut M,
    ) -> Result<(), Error> {
        let before_run = current_time();
        self.inner.perform(fuzzer, executor, state, manager)?;
        let after_run = current_time();
        self.count += after_run - before_run;
        *state.metadata_mut::<T>()? = T::from(self.count);
        Ok(())
    }

    fn should_restart(&mut self, state: &mut Self::State) -> Result<bool, Error> {
        self.inner.should_restart(state)
    }

    fn clear_progress(&mut self, state: &mut Self::State) -> Result<(), Error> {
        self.inner.clear_progress(state)
    }

    fn perform_restartable(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Self::State,
        manager: &mut M,
    ) -> Result<(), Error> {
        self.inner
            .perform_restartable(fuzzer, executor, state, manager)
    }
}
