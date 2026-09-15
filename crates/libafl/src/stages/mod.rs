/*!
A [`Stage`] is a technique used during fuzzing, working on one [`crate::corpus::Corpus`] entry, and potentially altering it or creating new entries.
A well-known [`Stage`], for example, is the mutational stage, running multiple [`crate::mutators::Mutator`]s against a [`crate::corpus::Testcase`], potentially storing new ones, according to [`crate::feedbacks::Feedback`].
Other stages may enrich [`crate::corpus::Testcase`]s with metadata.
*/

use core::fmt;

#[cfg(feature = "std")]
pub use afl_stats::{AflStatsStage, CalibrationTime, FuzzTime, SyncTime};
pub use calibrate::run_target_with_timing;
pub use colorization::{COLORIZATION_STAGE_NAME, TaintMetadata};
#[cfg(feature = "std")]
pub use dump::{DumpTargetBytesToDiskStage, DumpToDiskMetadata, generate_filename};
pub use generalization::GENERALIZATION_STAGE_NAME;
pub use generation::GenStage;
use hashbrown::HashSet;
use libafl_bolts::impl_serdeany;
pub use logics::{NestedStageRetryCountRestartHelper, OptionalStage};
pub use mutational::{
    DEFAULT_MUTATIONAL_MAX_ITERATIONS, MULTI_MUTATIONAL_STAGE_NAME, MUTATIONAL_STAGE_NAME,
    MutatedTransform, MutatedTransformPost, MutationalStage,
};
pub use nop::NopStage;
pub use power::{POWER_MUTATIONAL_STAGE_NAME, PowerMutationalStage};
pub use push::*;
pub use replay::{REPLAY_STAGE_NAME, ReplayHook, ReplayRestarterMetadata};
use serde::{Deserialize, Serialize};
pub use shadow::SHADOW_TRACING_STAGE_NAME;
#[cfg(feature = "std")]
pub use sync::{
    SYNC_FROM_DISK_STAGE_NAME, SyncFromBrokerMetadata, SyncFromBrokerStage, SyncFromDiskFunction,
    SyncFromDiskMetadata,
};
#[cfg(feature = "std")]
pub use time_tracker::TimeTrackingStageWrapper;
pub use tmin::{ObserverEqualityFactory, ObserverEqualityFeedback, TMIN_STAGE_NAME};
pub use tracing::TRACING_STAGE_NAME;
pub use tuneable::{
    STD_TUNEABLE_MUTATIONAL_STAGE_NAME, TuneableMutationalStageMetadata, get_iters_by_name,
    get_iters_std, get_seed_fuzz_time_by_name, get_seed_fuzz_time_std, reset_by_name, reset_std,
    set_iters_by_name, set_iters_std, set_seed_fuzz_time_by_name, set_seed_fuzz_time_std,
};
#[cfg(feature = "unicode")]
pub use unicode::{UnicodeIdentificationMetadata, UnicodeIdentificationStage};
#[cfg(feature = "std")]
pub use verify_timeouts::TimeoutsToVerify;

use crate::{
    Error, HasNamedMetadata,
    corpus::{CorpusId, HasCurrentCorpusId},
    state::HasExecutions,
};

/// Mutational stage is the normal fuzzing stage.
pub mod mutational;
pub mod pull;
pub mod push;
pub mod tmin;

pub mod replay;
pub mod shadow;

#[cfg(feature = "std")]
pub mod afl_stats;
pub mod calibrate;
pub mod colorization;
#[cfg(feature = "std")]
pub mod dump;
pub mod dynamic;
pub mod generalization;
pub mod generation;
pub mod logics;
pub mod nop;
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

/// Restartable trait takes care of stage restart.
pub trait Restartable<S> {
    /// This method will be called before every execution of a stage.
    /// Initialize the restart tracking for this stage, _if it is not yet initialized_.
    /// On restart, this will be called again.
    /// As long as [`Restartable::clear_progress`], all subsequent calls happen on restart.
    /// Returns `true`, if the stage should run, else `false`.
    fn should_restart(&mut self, state: &mut S) -> Result<bool, Error>;

    /// Clear the current status tracking of the associated stage
    fn clear_progress(&mut self, state: &mut S) -> Result<(), Error>;
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
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(transparent)]
pub struct StageId(pub(crate) usize);

impl fmt::Display for StageId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
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
    /// Only used as cache for the value stored in [`ExecutionCountRestartHelperMetadata`].
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
        debug_assert!(
            _metadata.is_some(),
            "Called clear_progress, but should_restart was not called before (or did mutational stages get nested?)"
        );
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use alloc::borrow::Cow;

    use libafl_bolts::{Error, Named};

    use crate::{
        corpus::{Corpus, HasCurrentCorpusId, Testcase},
        inputs::NopInput,
        stages::RetryCountRestartHelper,
        state::{HasCorpus, StdState},
    };

    /// Test to test retries in stages
    #[test]
    fn test_tries_progress() -> Result<(), Error> {
        struct StageWithOneTry;

        impl Named for StageWithOneTry {
            fn name(&self) -> &Cow<'static, str> {
                static NAME: Cow<'static, str> = Cow::Borrowed("TestStage");
                &NAME
            }
        }

        // # Safety
        // No concurrency per testcase
        #[cfg(any(not(feature = "serdeany_autoreg"), miri))]
        unsafe {
            RetryCountRestartHelper::register();
        }

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
