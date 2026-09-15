//! Legacy pull-based stages for `LibAFL`.
//!
//! In pull-based fuzzing, stages execute inputs directly inside a loop by invoking `executor.run_target()`.

use alloc::{
    borrow::{Cow, ToOwned},
    boxed::Box,
    string::ToString,
    vec::Vec,
};
use core::marker::PhantomData;

use libafl_bolts::{
    Named,
    tuples::{HasConstLen, IntoVec},
};
use tuple_list::NonEmptyTuple;

#[cfg(feature = "std")]
pub use super::afl_stats::{AflStatsStage, CalibrationTime, FuzzTime, SyncTime};
#[cfg(feature = "std")]
pub use super::dump::*;
#[cfg(feature = "std")]
pub use super::sync::*;
#[cfg(feature = "std")]
pub use super::time_tracker::TimeTrackingStageWrapper;
#[cfg(feature = "unicode")]
pub use super::unicode::*;
#[cfg(feature = "std")]
pub use super::verify_timeouts::{TimeoutsToVerify, VerifyTimeoutsStage};
pub use super::{
    ExecutionCountRestartHelper, ExecutionCountRestartHelperMetadata, Restartable,
    RetryCountRestartHelper, StageId,
    calibrate::{CalibrationStage, run_target_with_timing},
    colorization::*,
    dynamic::DynamicStage,
    generalization::GeneralizationStage,
    generation::GenStage,
    logics::*,
    mutational::{MultiMutationalStage, MutationalStage, StdMutationalStage},
    nop::NopStage,
    power::{PowerMutationalStage, StdPowerMutationalStage},
    replay::*,
    shadow::*,
    tmin::{ObserverEqualityFactory, ObserverEqualityFeedback, StdTMinMutationalStage},
    tracing::TracingStage,
    tuneable::*,
};
use crate::{
    Error, HasNamedMetadata,
    corpus::HasCurrentCorpusId,
    events::SendExiting,
    state::{HasCurrentStageId, MaybeHasClientPerfMonitor, Stoppable},
};

/// A stage is one step in the pull-based fuzzing process.
/// Multiple stages will be scheduled one by one for each input.
pub trait Stage<E, EM, S, Z> {
    /// Run the stage.
    ///
    /// If you want this stage to restart, then
    /// Before a call to perform, [`Restartable::should_restart`] will be (must be!) called.
    /// After returning (so non-target crash or timeout in a restarting case), [`Restartable::clear_progress`] gets called.
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<(), Error>;
}

/// Alias for pull-based [`Stage`].
pub use Stage as PullStage;

/// A tuple holding all pull-based `Stages` used for fuzzing.
pub trait StagesTuple<E, EM, S, Z> {
    /// Performs all `Stages` in this tuple.
    fn perform_all(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<(), Error>;
}

/// Alias for pull-based [`StagesTuple`].
pub use StagesTuple as PullStagesTuple;

impl<E, EM, S, Z> StagesTuple<E, EM, S, Z> for ()
where
    S: HasCurrentStageId,
{
    fn perform_all(
        &mut self,
        _: &mut Z,
        _: &mut E,
        stage: &mut S,
        _: &mut EM,
    ) -> Result<(), Error> {
        if stage.current_stage_id()?.is_some() {
            Err(Error::illegal_state(
                "Got to the end of the tuple without completing resume.",
            ))
        } else {
            Ok(())
        }
    }
}

impl<Head, Tail, E, EM, S, Z> StagesTuple<E, EM, S, Z> for (Head, Tail)
where
    Head: Stage<E, EM, S, Z> + Restartable<S>,
    Tail: StagesTuple<E, EM, S, Z> + HasConstLen,
    S: HasCurrentStageId + Stoppable + MaybeHasClientPerfMonitor,
    EM: SendExiting,
{
    /// Performs all stages in the tuple,
    /// Checks after every stage if state wants to stop
    /// and returns an [`Error::ShuttingDown`] if so
    fn perform_all(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<(), Error> {
        match state.current_stage_id()? {
            Some(idx) if idx < StageId(Self::LEN) => {
                // do nothing; we are resuming
            }
            Some(idx) if idx == StageId(Self::LEN) => {
                // perform the stage, but don't set it

                let stage = &mut self.0;

                match stage.perform_restartable(fuzzer, executor, state, manager) {
                    Ok(()) => {}
                    Err(Error::SkipRemainingStages) => {
                        state.clear_stage_id()?;
                        return Ok(());
                    }
                    Err(e) => return Err(e),
                }

                state.clear_stage_id()?;
            }
            Some(idx) if idx > StageId(Self::LEN) => {
                unreachable!("We should clear the stage index before we get here...");
            }
            // this is None, but the match can't deduce that
            _ => {
                state.set_current_stage_id(StageId(Self::LEN))?;

                let stage = &mut self.0;

                match stage.perform_restartable(fuzzer, executor, state, manager) {
                    Ok(()) => {}
                    Err(Error::SkipRemainingStages) => {
                        state.clear_stage_id()?;
                        return Ok(());
                    }
                    Err(e) => return Err(e),
                }

                state.clear_stage_id()?;
            }
        }

        // Mark the elapsed time for the scheduler
        #[cfg(feature = "introspection")]
        state.introspection_stats_mut().finish_stage();

        if state.stop_requested() {
            state.discard_stop_request();
            manager.on_shutdown()?;
            return Err(Error::shutting_down());
        }

        // Execute the remaining stages
        match self.1.perform_all(fuzzer, executor, state, manager) {
            Ok(()) | Err(Error::SkipRemainingStages) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

impl<Head, Tail, E, EM, S, Z> IntoVec<Box<dyn Stage<E, EM, S, Z>>> for (Head, Tail)
where
    Head: Stage<E, EM, S, Z> + 'static,
    Tail: StagesTuple<E, EM, S, Z> + HasConstLen + IntoVec<Box<dyn Stage<E, EM, S, Z>>>,
    S: HasCurrentStageId,
{
    fn into_vec_reversed(self) -> Vec<Box<dyn Stage<E, EM, S, Z>>> {
        let (head, tail) = self.uncons();
        let mut ret = tail.0.into_vec_reversed();
        ret.push(Box::new(head));
        ret
    }

    fn into_vec(self) -> Vec<Box<dyn Stage<E, EM, S, Z>>> {
        let mut ret = self.into_vec_reversed();
        ret.reverse();
        ret
    }
}

impl<Tail, E, EM, S, Z> IntoVec<Box<dyn Stage<E, EM, S, Z>>> for (Tail,)
where
    Tail: IntoVec<Box<dyn Stage<E, EM, S, Z>>>,
{
    fn into_vec(self) -> Vec<Box<dyn Stage<E, EM, S, Z>>> {
        self.0.into_vec()
    }
}

impl<E, EM, S, Z> IntoVec<Box<dyn Stage<E, EM, S, Z>>> for Vec<Box<dyn Stage<E, EM, S, Z>>> {
    fn into_vec(self) -> Vec<Box<dyn Stage<E, EM, S, Z>>> {
        self
    }
}

/// Restartable pull stage helper trait.
pub trait RestartableStage<E, EM, S, Z>: Stage<E, EM, S, Z> + Restartable<S> {
    /// Perform the pull stage with restartable tracking.
    fn perform_restartable(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<(), Error>;
}

impl<E, EM, S, ST, Z> RestartableStage<E, EM, S, Z> for ST
where
    ST: Stage<E, EM, S, Z> + Restartable<S>,
{
    /// Run the stage, calling [`Restartable::should_restart`] and [`Restartable::clear_progress`] appropriately
    fn perform_restartable(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<(), Error> {
        if self.should_restart(state)? {
            self.perform(fuzzer, executor, state, manager)?;
        }
        self.clear_progress(state)
    }
}

impl<E, EM, S, Z> StagesTuple<E, EM, S, Z> for Vec<Box<dyn RestartableStage<E, EM, S, Z>>>
where
    EM: SendExiting,
    S: HasCurrentStageId + Stoppable,
{
    /// Performs all stages in the `Vec`
    /// Checks after every stage if state wants to stop
    /// and returns an [`Error::ShuttingDown`] if so
    fn perform_all(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<(), Error> {
        self.iter_mut()
            .try_for_each(|stage| {
                if state.stop_requested() {
                    state.discard_stop_request();
                    manager.on_shutdown()?;
                    return Err(Error::shutting_down());
                }
                match stage.perform_restartable(fuzzer, executor, state, manager) {
                    Ok(()) => Ok(()),
                    Err(Error::SkipRemainingStages) => {
                        // Skip the remaining stages
                        // We return an error to stop the iterator, but we want to return Ok(()) from perform_all

                        Err(Error::SkipRemainingStages)
                    }
                    Err(e) => Err(e),
                }
            })
            .or_else(|e| match e {
                Error::SkipRemainingStages => Ok(()),
                _ => Err(e),
            })
    }
}

static mut CLOSURE_STAGE_ID: usize = 0;
/// The name for closure stage
pub static CLOSURE_STAGE_NAME: &str = "closure";

/// A pull-based [`Stage`] that will call a closure
#[derive(Debug)]
pub struct ClosureStage<CB, E, EM, Z> {
    name: Cow<'static, str>,
    closure: CB,
    phantom: PhantomData<(E, EM, Z)>,
}

/// Alias for pull-based [`ClosureStage`].
pub use ClosureStage as ClosurePullStage;

impl<CB, E, EM, Z> Named for ClosureStage<CB, E, EM, Z> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<CB, E, EM, S, Z> Stage<E, EM, S, Z> for ClosureStage<CB, E, EM, Z>
where
    CB: FnMut(&mut Z, &mut E, &mut S, &mut EM) -> Result<(), Error>,
    S: HasNamedMetadata + HasCurrentCorpusId,
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<(), Error> {
        (self.closure)(fuzzer, executor, state, manager)
    }
}

impl<CB, E, EM, S, Z> Restartable<S> for ClosureStage<CB, E, EM, Z>
where
    S: HasNamedMetadata + HasCurrentCorpusId,
{
    #[inline]
    fn should_restart(&mut self, state: &mut S) -> Result<bool, Error> {
        // There's no restart safety in the content of the closure.
        // don't restart
        RetryCountRestartHelper::no_retry(state, &self.name)
    }

    #[inline]
    fn clear_progress(&mut self, state: &mut S) -> Result<(), Error> {
        RetryCountRestartHelper::clear_progress(state, &self.name)
    }
}

/// A stage that takes a closure
impl<CB, E, EM, Z> ClosureStage<CB, E, EM, Z> {
    /// Create a new [`ClosureStage`]
    #[must_use]
    pub fn new(closure: CB) -> Self {
        // unsafe but impossible that you create two threads both instantiating this instance
        let stage_id = unsafe {
            let ret = CLOSURE_STAGE_ID;
            CLOSURE_STAGE_ID += 1;
            ret
        };
        Self {
            name: Cow::Owned(CLOSURE_STAGE_NAME.to_owned() + ":" + stage_id.to_string().as_ref()),
            closure,
            phantom: PhantomData,
        }
    }
}
