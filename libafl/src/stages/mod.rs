/*!
A [`Stage`] is a technique used during fuzzing, working on one [`crate::corpus::Corpus`] entry, and potentially altering it or creating new entries.
A well-known [`Stage`], for example, is the mutational stage, running multiple [`crate::mutators::Mutator`]s against a [`crate::corpus::Testcase`], potentially storing new ones, according to [`crate::feedbacks::Feedback`].
Other stages may enrich [`crate::corpus::Testcase`]s with metadata.
*/

use alloc::{
    borrow::{Cow, ToOwned},
    boxed::Box,
    string::ToString,
    vec::Vec,
};
use core::{fmt, marker::PhantomData};

#[cfg(feature = "std")]
pub use afl_stats::{AflStatsStage, CalibrationTime, FuzzTime, SyncTime};
pub use calibrate::CalibrationStage;
pub use colorization::*;
#[cfg(all(feature = "std", unix))]
pub use concolic::ConcolicTracingStage;
#[cfg(all(feature = "std", feature = "concolic_mutation", unix))]
pub use concolic::SimpleConcolicMutationalStage;
#[cfg(feature = "std")]
pub use dump::*;
pub use generalization::GeneralizationStage;
use hashbrown::HashSet;
use libafl_bolts::{
    impl_serdeany,
    tuples::{HasConstLen, IntoVec},
    Named,
};
pub use logics::*;
pub use mutational::{MutationalStage, StdMutationalStage};
pub use power::{PowerMutationalStage, StdPowerMutationalStage};
use serde::{Deserialize, Serialize};
#[cfg(feature = "std")]
pub use sync::*;
#[cfg(feature = "std")]
pub use time_tracker::TimeTrackingStageWrapper;
pub use tmin::{MapEqualityFactory, MapEqualityFeedback, StdTMinMutationalStage};
pub use tracing::{ShadowTracingStage, TracingStage};
pub use tuneable::*;
use tuple_list::NonEmptyTuple;
#[cfg(feature = "unicode")]
pub use unicode::*;
#[cfg(feature = "std")]
pub use verify_timeouts::{TimeoutsToVerify, VerifyTimeoutsStage};

use crate::{
    corpus::{CorpusId, HasCurrentCorpusId},
    events::EventProcessor,
    state::{HasExecutions, State, Stoppable},
    Error, HasNamedMetadata,
};

/// Mutational stage is the normal fuzzing stage.
pub mod mutational;
pub mod push;
pub mod tmin;

#[cfg(feature = "std")]
pub mod afl_stats;
pub mod calibrate;
pub mod colorization;
#[cfg(all(feature = "std", unix))]
pub mod concolic;
#[cfg(feature = "std")]
pub mod dump;
pub mod generalization;
pub mod generation;
pub mod logics;
pub mod power;
#[cfg(feature = "std")]
pub mod sync;
#[cfg(feature = "std")]
pub mod time_tracker;
pub mod tracing;
pub mod tuneable;
#[cfg(feature = "unicode")]
pub mod unicode;
#[cfg(feature = "std")]
pub mod verify_timeouts;

/// A stage is one step in the fuzzing process.
/// Multiple stages will be scheduled one by one for each input.
pub trait Stage<E, EM, S, Z> {
    /// This method will be called before every call to [`Stage::perform`].
    /// Initialize the restart tracking for this stage, _if it is not yet initialized_.
    /// On restart, this will be called again.
    /// As long as [`Stage::clear_progress`], all subsequent calls happen on restart.
    /// Returns `true`, if the stage's [`Stage::perform`] method should run, else `false`.
    fn should_restart(&mut self, state: &mut S) -> Result<bool, Error>;

    /// Clear the current status tracking of the associated stage
    fn clear_progress(&mut self, state: &mut S) -> Result<(), Error>;

    /// Run the stage.
    ///
    /// Before a call to perform, [`Stage::should_restart`] will be (must be!) called.
    /// After returning (so non-target crash or timeout in a restarting case), [`Stage::clear_progress`] gets called.
    /// A call to [`Stage::perform_restartable`] will do these things implicitly.
    /// DON'T call this function directly except from `preform_restartable` !!
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<(), Error>;

    /// Run the stage, calling [`Stage::should_restart`] and [`Stage::clear_progress`] appropriately
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

/// A tuple holding all `Stages` used for fuzzing.
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
    Head: Stage<E, EM, S, Z>,
    Tail: StagesTuple<E, EM, S, Z> + HasConstLen,
    S: HasCurrentStageId + Stoppable,
    EM: EventProcessor<E, Z>,
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

                #[allow(clippy::similar_names)]
                let stage = &mut self.0;

                stage.perform_restartable(fuzzer, executor, state, manager)?;

                state.clear_stage_id()?;
            }
            Some(idx) if idx > StageId(Self::LEN) => {
                unreachable!("We should clear the stage index before we get here...");
            }
            // this is None, but the match can't deduce that
            _ => {
                state.set_current_stage_id(StageId(Self::LEN))?;

                #[allow(clippy::similar_names)]
                let stage = &mut self.0;
                stage.perform_restartable(fuzzer, executor, state, manager)?;

                state.clear_stage_id()?;
            }
        }

        if state.stop_requested() {
            state.discard_stop_request();
            manager.on_shutdown()?;
            return Err(Error::shutting_down());
        }

        // Execute the remaining stages
        self.1.perform_all(fuzzer, executor, state, manager)
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

impl<E, EM, S, Z> StagesTuple<E, EM, S, Z> for Vec<Box<dyn Stage<E, EM, S, Z>>>
where
    EM: EventProcessor<E, Z>,
    S: HasCurrentStageId + State,
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
        self.iter_mut().try_for_each(|x| {
            if state.stop_requested() {
                state.discard_stop_request();
                manager.on_shutdown()?;
                return Err(Error::shutting_down());
            }
            x.perform_restartable(fuzzer, executor, state, manager)
        })
    }
}

static mut CLOSURE_STAGE_ID: usize = 0;
/// The name for closure stage
pub static CLOSURE_STAGE_NAME: &str = "closure";

/// A [`Stage`] that will call a closure
#[derive(Debug)]
pub struct ClosureStage<CB, E, EM, Z> {
    name: Cow<'static, str>,
    closure: CB,
    phantom: PhantomData<(E, EM, Z)>,
}

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

/// Progress which permits a fixed amount of resumes per round of fuzzing. If this amount is ever
/// exceeded, the input will no longer be executed by this stage.
#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct RetryCountRestartHelper {
    tries_remaining: Option<usize>,
    skipped: HashSet<CorpusId>,
}

impl_serdeany!(RetryCountRestartHelper);

impl RetryCountRestartHelper {
    /// Don't allow restart
    pub fn no_retry<S>(state: &mut S, name: &str) -> Result<bool, Error>
    where
        S: HasNamedMetadata + HasCurrentCorpusId,
    {
        Self::should_restart(state, name, 1)
    }

    /// Initializes (or counts down in) the progress helper, giving it the amount of max retries
    ///
    /// Returns `true` if the stage should run
    pub fn should_restart<S>(state: &mut S, name: &str, max_retries: usize) -> Result<bool, Error>
    where
        S: HasNamedMetadata + HasCurrentCorpusId,
    {
        let corpus_id = state.current_corpus_id()?.ok_or_else(|| {
            Error::illegal_state(
                "No current_corpus_id set in State, but called RetryCountRestartHelper::should_skip",
            )
        })?;

        let initial_tries_remaining = max_retries + 1;
        let metadata = state.named_metadata_or_insert_with(name, || Self {
            tries_remaining: Some(initial_tries_remaining),
            skipped: HashSet::new(),
        });
        let tries_remaining = metadata
            .tries_remaining
            .unwrap_or(initial_tries_remaining)
            .checked_sub(1)
            .ok_or_else(|| {
                Error::illegal_state(
                    "Attempted further retries after we had already gotten to none remaining.",
                )
            })?;

        metadata.tries_remaining = Some(tries_remaining);

        Ok(if tries_remaining == 0 {
            metadata.skipped.insert(corpus_id);
            false
        } else if metadata.skipped.contains(&corpus_id) {
            // skip this testcase, we already retried it often enough...
            false
        } else {
            true
        })
    }

    /// Clears the progress
    pub fn clear_progress<S>(state: &mut S, name: &str) -> Result<(), Error>
    where
        S: HasNamedMetadata,
    {
        state.named_metadata_mut::<Self>(name)?.tries_remaining = None;
        Ok(())
    }
}

/// The index of a stage
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(transparent)]
pub struct StageId(pub(crate) usize);

impl fmt::Display for StageId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Trait for types which track the current stage
pub trait HasCurrentStageId {
    /// Set the current stage; we have started processing this stage
    fn set_current_stage_id(&mut self, id: StageId) -> Result<(), Error>;

    /// Clear the current stage; we are done processing this stage
    fn clear_stage_id(&mut self) -> Result<(), Error>;

    /// Fetch the current stage -- typically used after a state recovery or transfer
    fn current_stage_id(&self) -> Result<Option<StageId>, Error>;

    /// Notify of a reset from which we may recover
    fn on_restart(&mut self) -> Result<(), Error> {
        Ok(())
    }
}

/// Trait for types which track nested stages. Stages which themselves contain stage tuples should
/// ensure that they constrain the state with this trait accordingly.
pub trait HasNestedStageStatus: HasCurrentStageId {
    /// Enter a stage scope, potentially resuming to an inner stage status. Returns Ok(true) if
    /// resumed.
    fn enter_inner_stage(&mut self) -> Result<(), Error>;

    /// Exit a stage scope
    fn exit_inner_stage(&mut self) -> Result<(), Error>;
}

impl_serdeany!(ExecutionCountRestartHelperMetadata);

/// `SerdeAny` metadata used to keep track of executions since start for a given stage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionCountRestartHelperMetadata {
    /// How many executions we had when we started this stage initially (this round)
    started_at_execs: u64,
}

/// A tool shed of functions to be used for stages that try to run for `n` iterations.
///
/// # Note
/// This helper assumes resumable mutational stages are not nested.
/// If you want to nest them, you will have to switch all uses of `metadata` in this helper to `named_metadata` instead.
#[derive(Debug, Default, Clone)]
pub struct ExecutionCountRestartHelper {
    /// At what exec count this Stage was started (cache)
    /// Only used as cache for the value stored in [`MutationalStageMetadata`].
    started_at_execs: Option<u64>,
}

impl ExecutionCountRestartHelper {
    /// Create a new [`ExecutionCountRestartHelperMetadata`]
    #[must_use]
    pub fn new() -> Self {
        Self {
            started_at_execs: None,
        }
    }

    /// The execs done since start of this [`Stage`]/helper
    pub fn execs_since_progress_start<S>(&mut self, state: &mut S, name: &str) -> Result<u64, Error>
    where
        S: HasNamedMetadata + HasExecutions,
    {
        let started_at_execs = if let Some(started_at_execs) = self.started_at_execs {
            started_at_execs
        } else {
            state
                .named_metadata::<ExecutionCountRestartHelperMetadata>(name)
                .map(|x| {
                    self.started_at_execs = Some(x.started_at_execs);
                    x.started_at_execs
                })
                .map_err(|err| {
                    Error::illegal_state(format!(
                        "The ExecutionCountRestartHelperMetadata should have been set at this point - {err}"
                    ))
                })?
        };
        Ok(state.executions() - started_at_execs)
    }

    /// Initialize progress for the stage this wrapper wraps.
    pub fn should_restart<S>(&mut self, state: &mut S, name: &str) -> Result<bool, Error>
    where
        S: HasNamedMetadata + HasExecutions,
    {
        let executions = *state.executions();
        let metadata =
            state.named_metadata_or_insert_with(name, || ExecutionCountRestartHelperMetadata {
                started_at_execs: executions,
            });
        self.started_at_execs = Some(metadata.started_at_execs);
        Ok(true)
    }

    /// Clear progress for the stage this wrapper wraps.
    pub fn clear_progress<S>(&mut self, state: &mut S, name: &str) -> Result<(), Error>
    where
        S: HasNamedMetadata,
    {
        self.started_at_execs = None;
        let _metadata = state.remove_named_metadata::<ExecutionCountRestartHelperMetadata>(name);
        debug_assert!(_metadata.is_some(), "Called clear_progress, but should_restart was not called before (or did mutational stages get nested?)");
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use alloc::borrow::Cow;
    use core::marker::PhantomData;

    use libafl_bolts::{impl_serdeany, Error, Named};
    use serde::{Deserialize, Serialize};

    use crate::{
        corpus::{Corpus, HasCurrentCorpusId, Testcase},
        inputs::NopInput,
        stages::{RetryCountRestartHelper, Stage},
        state::{HasCorpus, StdState},
        HasMetadata,
    };

    /// A stage that succeeds to resume
    #[derive(Debug)]
    pub struct ResumeSucceededStage<S> {
        phantom: PhantomData<S>,
    }

    /// A progress state for testing
    #[derive(Serialize, Deserialize, Debug)]
    pub struct TestProgress {
        count: usize,
    }

    impl_serdeany!(TestProgress);

    impl TestProgress {
        #[allow(clippy::unnecessary_wraps)]
        fn should_restart<S, ST>(state: &mut S, _stage: &ST) -> Result<bool, Error>
        where
            S: HasMetadata,
        {
            // check if we're resuming
            let metadata = state.metadata_or_insert_with(|| Self { count: 0 });

            metadata.count += 1;
            assert!(
                metadata.count == 1,
                "Test failed; we resumed a succeeded stage!"
            );

            Ok(true)
        }

        fn clear_progress<S, ST>(state: &mut S, _stage: &ST) -> Result<(), Error>
        where
            S: HasMetadata,
        {
            if state.remove_metadata::<Self>().is_none() {
                return Err(Error::illegal_state(
                    "attempted to clear status metadata when none was present",
                ));
            }
            Ok(())
        }
    }

    impl<E, EM, S, Z> Stage<E, EM, S, Z> for ResumeSucceededStage<S>
    where
        S: HasMetadata,
    {
        fn perform(
            &mut self,
            _fuzzer: &mut Z,
            _executor: &mut E,
            _state: &mut S,
            _manager: &mut EM,
        ) -> Result<(), Error> {
            Ok(())
        }

        fn should_restart(&mut self, state: &mut S) -> Result<bool, Error> {
            TestProgress::should_restart(state, self)
        }

        fn clear_progress(&mut self, state: &mut S) -> Result<(), Error> {
            TestProgress::clear_progress(state, self)
        }
    }

    /// Test to test retries in stages
    #[test]
    fn test_tries_progress() -> Result<(), Error> {
        // # Safety
        // No concurrency per testcase
        #[cfg(any(not(feature = "serdeany_autoreg"), miri))]
        unsafe {
            RetryCountRestartHelper::register();
        }

        struct StageWithOneTry;

        impl Named for StageWithOneTry {
            fn name(&self) -> &Cow<'static, str> {
                static NAME: Cow<'static, str> = Cow::Borrowed("TestStage");
                &NAME
            }
        }

        #[allow(clippy::similar_names)]
        let mut state = StdState::nop()?;
        let stage = StageWithOneTry;

        let corpus_id = state.corpus_mut().add(Testcase::new(NopInput {}))?;

        state.set_corpus_id(corpus_id)?;

        for _ in 0..10 {
            // used normally, no retries means we never skip
            assert!(RetryCountRestartHelper::should_restart(
                &mut state,
                stage.name(),
                1
            )?);
            RetryCountRestartHelper::clear_progress(&mut state, stage.name())?;
        }

        for _ in 0..10 {
            // used normally, only one retry means we never skip
            assert!(RetryCountRestartHelper::should_restart(
                &mut state,
                stage.name(),
                2
            )?);
            assert!(RetryCountRestartHelper::should_restart(
                &mut state,
                stage.name(),
                2
            )?);
            RetryCountRestartHelper::clear_progress(&mut state, stage.name())?;
        }

        assert!(RetryCountRestartHelper::should_restart(
            &mut state,
            stage.name(),
            2
        )?);
        // task failed, let's resume
        // we still have one more try!
        assert!(RetryCountRestartHelper::should_restart(
            &mut state,
            stage.name(),
            2
        )?);

        // task failed, let's resume
        // out of retries, so now we skip
        assert!(!RetryCountRestartHelper::should_restart(
            &mut state,
            stage.name(),
            2
        )?);
        RetryCountRestartHelper::clear_progress(&mut state, stage.name())?;

        // we previously exhausted this testcase's retries, so we skip
        assert!(!RetryCountRestartHelper::should_restart(
            &mut state,
            stage.name(),
            2
        )?);
        RetryCountRestartHelper::clear_progress(&mut state, stage.name())?;

        Ok(())
    }
}
