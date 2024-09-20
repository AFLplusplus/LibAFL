//! The [`SyncFromDiskStage`] is a stage that imports inputs from disk for e.g. sync with AFL

use alloc::{
    borrow::{Cow, ToOwned},
    vec::Vec,
};
use core::time::Duration;
use std::path::{Path, PathBuf};

use libafl_bolts::{current_time, fs::find_new_files_rec, shmem::ShMemProvider, Named};
use serde::{Deserialize, Serialize};

#[cfg(feature = "introspection")]
use crate::state::HasClientPerfMonitor;
use crate::{
    corpus::{Corpus, CorpusId, HasCorpus, HasCurrentCorpusId},
    events::{llmp::LlmpEventConverter, Event, EventConfig, EventFirer},
    executors::ExitKind,
    fuzzer::{Evaluator, EvaluatorObservers},
    inputs::{Input, InputConverter},
    stages::{RetryCountRestartHelper, Stage},
    state::HasRand,
    Error, HasMetadata, HasNamedMetadata,
};

/// Default name for `SyncFromDiskStage`; derived from AFL++
pub const SYNC_FROM_DISK_STAGE_NAME: &str = "sync";

/// Metadata used to store information about disk sync time
#[allow(clippy::unsafe_derive_deserialize)] // for SerdeAny
#[derive(Serialize, Deserialize, Debug)]
pub struct SyncFromDiskMetadata {
    /// The last time the sync was done
    pub last_time: Duration,
    /// The paths that are left to sync
    pub left_to_sync: Vec<PathBuf>,
}

libafl_bolts::impl_serdeany!(SyncFromDiskMetadata);

impl SyncFromDiskMetadata {
    /// Create a new [`struct@SyncFromDiskMetadata`]
    #[must_use]
    pub fn new(last_time: Duration, left_to_sync: Vec<PathBuf>) -> Self {
        Self {
            last_time,
            left_to_sync,
        }
    }
}

/// A stage that loads testcases from disk to sync with other fuzzers such as AFL++
#[derive(Debug)]
pub struct SyncFromDiskStage<CB> {
    name: Cow<'static, str>,
    sync_dirs: Vec<PathBuf>,
    load_callback: CB,
    interval: Duration,
}

impl<CB> Named for SyncFromDiskStage<CB> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<CB, E, EM, S, Z> Stage<E, EM, S, Z> for SyncFromDiskStage<CB>
where
    CB: FnMut(&mut Z, &mut S, &Path) -> Result<<S::Corpus as Corpus>::Input, Error>,
    Z: Evaluator<E, EM, <S::Corpus as Corpus>::Input, S>,
    S: HasCorpus + HasRand + HasMetadata + HasNamedMetadata + HasCurrentCorpusId,
{
    #[inline]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<(), Error> {
        let last = state
            .metadata_map()
            .get::<SyncFromDiskMetadata>()
            .map(|m| m.last_time);

        if let Some(last) = last {
            if current_time().saturating_sub(last) < self.interval {
                return Ok(());
            }
        }

        let max_time = match last {
            None => None,
            Some(last) => Some(last + self.interval),
        };
        let new_max_time = max_time.unwrap_or(current_time());

        let mut new_files = vec![];
        for dir in &self.sync_dirs {
            log::debug!("Syncing from dir: {:?}", dir);
            let new_dir_files = find_new_files_rec(dir, &max_time)?;
            new_files.extend(new_dir_files);
        }
        *state.metadata_mut::<SyncFromDiskMetadata>().unwrap() = SyncFromDiskMetadata {
            last_time: new_max_time,
            left_to_sync: new_files,
        };
        let sync_from_disk_metadata = state.metadata_mut::<SyncFromDiskMetadata>().unwrap();
        // Iterate over the paths of files left to sync.
        // By keeping track of these files, we ensure that no file is missed during synchronization,
        // even in the event of a target restart.
        let to_sync = sync_from_disk_metadata.left_to_sync.clone();
        log::debug!("Number of files to sync: {:?}", to_sync.len());
        for path in to_sync {
            let input = (self.load_callback)(fuzzer, state, &path)?;
            // Removing each path from the `left_to_sync` Vec before evaluating
            // prevents duplicate processing and ensures that each file is evaluated only once. This approach helps
            // avoid potential infinite loops that may occur if a file is an objective.
            state
                .metadata_mut::<SyncFromDiskMetadata>()
                .unwrap()
                .left_to_sync
                .retain(|p| p != &path);
            log::debug!("Syncing and evaluating {:?}", path);
            fuzzer.evaluate_input(state, executor, manager, input)?;
        }

        #[cfg(feature = "introspection")]
        state.introspection_monitor_mut().finish_stage();

        Ok(())
    }

    #[inline]
    fn should_restart(&mut self, state: &mut S) -> Result<bool, Error> {
        // TODO: Needs proper crash handling for when an imported testcase crashes
        // For now, Make sure we don't get stuck crashing on this testcase
        RetryCountRestartHelper::no_retry(state, &self.name)
    }

    #[inline]
    fn clear_progress(&mut self, state: &mut S) -> Result<(), Error> {
        RetryCountRestartHelper::clear_progress(state, &self.name)
    }
}

impl<CB> SyncFromDiskStage<CB> {
    /// Creates a new [`SyncFromDiskStage`]
    #[must_use]
    pub fn new(sync_dirs: Vec<PathBuf>, load_callback: CB, interval: Duration, name: &str) -> Self {
        Self {
            name: Cow::Owned(SYNC_FROM_DISK_STAGE_NAME.to_owned() + ":" + name),
            sync_dirs,
            interval,
            load_callback,
        }
    }
}

/// Function type when the callback in `SyncFromDiskStage` is not a lambda
pub type SyncFromDiskFunction<I, S, Z> = fn(&mut Z, &mut S, &Path) -> Result<I, Error>;

impl<I, S, Z> SyncFromDiskStage<SyncFromDiskFunction<I, S, Z>>
where
    I: Input,
{
    /// Creates a new [`SyncFromDiskStage`] invoking `Input::from_file` to load inputs
    #[must_use]
    pub fn with_from_file(sync_dirs: Vec<PathBuf>, interval: Duration) -> Self {
        fn load_callback<I: Input, S, Z>(_: &mut Z, _: &mut S, p: &Path) -> Result<I, Error> {
            Input::from_file(p)
        }
        Self {
            interval,
            name: Cow::Borrowed(SYNC_FROM_DISK_STAGE_NAME),
            sync_dirs,
            load_callback: load_callback::<_, _, _>,
        }
    }
}

/// Metadata used to store information about the last sent testcase with `SyncFromBrokerStage`
#[allow(clippy::unsafe_derive_deserialize)] // for SerdeAny
#[derive(Serialize, Deserialize, Debug)]
pub struct SyncFromBrokerMetadata {
    /// The `CorpusId` of the last sent testcase
    pub last_id: Option<CorpusId>,
}

libafl_bolts::impl_serdeany!(SyncFromBrokerMetadata);

impl SyncFromBrokerMetadata {
    /// Create a new [`struct@SyncFromBrokerMetadata`]
    #[must_use]
    pub fn new(last_id: Option<CorpusId>) -> Self {
        Self { last_id }
    }
}

/// A stage that loads testcases from disk to sync with other fuzzers such as AFL++
#[derive(Debug)]
pub struct SyncFromBrokerStage<IC, ICB, S, SP>
where
    SP: ShMemProvider,
{
    client: LlmpEventConverter<IC, ICB, S, SP>,
}

impl<E, EM, IC, ICB, S, SP, Z> Stage<E, EM, S, Z> for SyncFromBrokerStage<IC, ICB, S, SP>
where
    ICB: InputConverter<To = <S::Corpus as Corpus>::Input>,
    IC: InputConverter<From = <S::Corpus as Corpus>::Input>,
    SP: ShMemProvider,
    S: HasMetadata + HasCorpus,
    <S::Corpus as Corpus>::Input: Clone,
    Z: EvaluatorObservers<E, EM, <S::Corpus as Corpus>::Input, S>,
{
    #[inline]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<(), Error> {
        if self.client.can_convert() {
            let last_id = state
                .metadata_map()
                .get::<SyncFromBrokerMetadata>()
                .and_then(|m| m.last_id);

            let mut cur_id =
                last_id.map_or_else(|| state.corpus().first(), |id| state.corpus().next(id));

            while let Some(id) = cur_id {
                let input = state.corpus().cloned_input_for_id(id)?;

                self.client.fire(
                    state,
                    Event::NewTestcase {
                        input,
                        observers_buf: None,
                        exit_kind: ExitKind::Ok,
                        corpus_size: 0, // TODO choose if sending 0 or the actual real value
                        client_config: EventConfig::AlwaysUnique,
                        time: current_time(),
                        executions: 0,
                        forward_id: None,
                        #[cfg(all(unix, feature = "std", feature = "multi_machine"))]
                        node_id: None,
                    },
                )?;

                cur_id = state.corpus().next(id);
            }

            let last = state.corpus().last();
            if last_id.is_none() {
                state
                    .metadata_map_mut()
                    .insert(SyncFromBrokerMetadata::new(last));
            } else {
                state
                    .metadata_map_mut()
                    .get_mut::<SyncFromBrokerMetadata>()
                    .unwrap()
                    .last_id = last;
            }
        }

        self.client.process(fuzzer, state, executor, manager)?;
        #[cfg(feature = "introspection")]
        state.introspection_monitor_mut().finish_stage();
        Ok(())
    }

    #[inline]
    fn should_restart(&mut self, _state: &mut S) -> Result<bool, Error> {
        // No restart handling needed - does not execute the target.
        Ok(true)
    }

    #[inline]
    fn clear_progress(&mut self, _state: &mut S) -> Result<(), Error> {
        // Not needed - does not execute the target.
        Ok(())
    }
}

impl<IC, ICB, S, SP> SyncFromBrokerStage<IC, ICB, S, SP>
where
    SP: ShMemProvider,
{
    /// Creates a new [`SyncFromBrokerStage`]
    #[must_use]
    pub fn new(client: LlmpEventConverter<IC, ICB, S, SP>) -> Self {
        Self { client }
    }
}
