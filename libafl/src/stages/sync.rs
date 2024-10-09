//! The [`SyncFromDiskStage`] is a stage that imports inputs from disk for e.g. sync with AFL

use alloc::{
    borrow::{Cow, ToOwned},
    vec::Vec,
};
use core::{marker::PhantomData, time::Duration};
use std::path::{Path, PathBuf};

use libafl_bolts::{current_time, fs::find_new_files_rec, shmem::ShMemProvider, Named};
use serde::{Deserialize, Serialize};

#[cfg(feature = "introspection")]
use crate::state::HasClientPerfMonitor;
use crate::{
    corpus::{Corpus, CorpusId},
    events::{llmp::LlmpEventConverter, Event, EventConfig, EventFirer},
    executors::{Executor, ExitKind, HasObservers},
    fuzzer::{Evaluator, EvaluatorObservers, ExecutionProcessor},
    inputs::{Input, InputConverter, UsesInput},
    stages::{RetryCountRestartHelper, Stage},
    state::{HasCorpus, HasExecutions, HasRand, State, UsesState},
    Error, HasMetadata, HasNamedMetadata,
};

/// Default name for `SyncFromDiskStage`; derived from AFL++
pub const SYNC_FROM_DISK_STAGE_NAME: &str = "sync";

/// Metadata used to store information about disk sync time
#[cfg_attr(
    any(not(feature = "serdeany_autoreg"), miri),
    allow(clippy::unsafe_derive_deserialize)
)] // for SerdeAny
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
pub struct SyncFromDiskStage<CB, E, EM, Z> {
    name: Cow<'static, str>,
    sync_dirs: Vec<PathBuf>,
    load_callback: CB,
    interval: Duration,
    phantom: PhantomData<(E, EM, Z)>,
}

impl<CB, E, EM, Z> UsesState for SyncFromDiskStage<CB, E, EM, Z>
where
    Z: UsesState,
{
    type State = Z::State;
}

impl<CB, E, EM, Z> Named for SyncFromDiskStage<CB, E, EM, Z> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<CB, E, EM, Z> Stage<E, EM, Z> for SyncFromDiskStage<CB, E, EM, Z>
where
    CB: FnMut(&mut Z, &mut Self::State, &Path) -> Result<<Self::State as UsesInput>::Input, Error>,
    E: UsesState<State = Self::State>,
    EM: UsesState<State = Self::State>,
    Z: Evaluator<E, EM>,
    Self::State: HasCorpus + HasRand + HasMetadata + HasNamedMetadata,
{
    #[inline]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Self::State,
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

        let new_max_time = current_time();

        let mut new_files = vec![];
        for dir in &self.sync_dirs {
            log::debug!("Syncing from dir: {:?}", dir);
            let new_dir_files = find_new_files_rec(dir, &last)?;
            new_files.extend(new_dir_files);
        }

        let sync_from_disk_metadata = state
            .metadata_or_insert_with(|| SyncFromDiskMetadata::new(new_max_time, new_files.clone()));

        // At the very first sync, last_time and file_to_sync are set twice
        sync_from_disk_metadata.last_time = new_max_time;
        sync_from_disk_metadata.left_to_sync = new_files;

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
    fn should_restart(&mut self, state: &mut Self::State) -> Result<bool, Error> {
        // TODO: Needs proper crash handling for when an imported testcase crashes
        // For now, Make sure we don't get stuck crashing on this testcase
        RetryCountRestartHelper::no_retry(state, &self.name)
    }

    #[inline]
    fn clear_progress(&mut self, state: &mut Self::State) -> Result<(), Error> {
        RetryCountRestartHelper::clear_progress(state, &self.name)
    }
}

impl<CB, E, EM, Z> SyncFromDiskStage<CB, E, EM, Z> {
    /// Creates a new [`SyncFromDiskStage`]
    #[must_use]
    pub fn new(sync_dirs: Vec<PathBuf>, load_callback: CB, interval: Duration, name: &str) -> Self {
        Self {
            name: Cow::Owned(SYNC_FROM_DISK_STAGE_NAME.to_owned() + ":" + name),
            phantom: PhantomData,
            sync_dirs,
            interval,
            load_callback,
        }
    }
}

/// Function type when the callback in `SyncFromDiskStage` is not a lambda
pub type SyncFromDiskFunction<S, Z> =
    fn(&mut Z, &mut S, &Path) -> Result<<S as UsesInput>::Input, Error>;

impl<E, EM, Z> SyncFromDiskStage<SyncFromDiskFunction<Z::State, Z>, E, EM, Z>
where
    E: UsesState<State = <Self as UsesState>::State>,
    EM: UsesState<State = <Self as UsesState>::State>,
    Z: Evaluator<E, EM>,
{
    /// Creates a new [`SyncFromDiskStage`] invoking `Input::from_file` to load inputs
    #[must_use]
    pub fn with_from_file(sync_dirs: Vec<PathBuf>, interval: Duration) -> Self {
        fn load_callback<S: UsesInput, Z>(
            _: &mut Z,
            _: &mut S,
            p: &Path,
        ) -> Result<S::Input, Error> {
            Input::from_file(p)
        }
        Self {
            interval,
            name: Cow::Borrowed(SYNC_FROM_DISK_STAGE_NAME),
            sync_dirs,
            load_callback: load_callback::<_, _>,
            phantom: PhantomData,
        }
    }
}

/// Metadata used to store information about the last sent testcase with `SyncFromBrokerStage`
#[cfg_attr(
    any(not(feature = "serdeany_autoreg"), miri),
    allow(clippy::unsafe_derive_deserialize)
)] // for SerdeAny
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
pub struct SyncFromBrokerStage<DI, IC, ICB, S, SP>
where
    SP: ShMemProvider + 'static,
    S: UsesInput,
    IC: InputConverter<From = S::Input, To = DI>,
    ICB: InputConverter<From = DI, To = S::Input>,
    DI: Input,
{
    client: LlmpEventConverter<DI, IC, ICB, S, SP>,
}

impl<DI, IC, ICB, S, SP> UsesState for SyncFromBrokerStage<DI, IC, ICB, S, SP>
where
    SP: ShMemProvider + 'static,
    S: State,
    IC: InputConverter<From = S::Input, To = DI>,
    ICB: InputConverter<From = DI, To = S::Input>,
    DI: Input,
{
    type State = S;
}

impl<E, EM, IC, ICB, DI, S, SP, Z> Stage<E, EM, Z> for SyncFromBrokerStage<DI, IC, ICB, S, SP>
where
    EM: UsesState<State = S> + EventFirer,
    S: State + HasExecutions + HasCorpus + HasRand + HasMetadata,
    SP: ShMemProvider,
    E: HasObservers<State = S> + Executor<EM, Z>,
    for<'a> E::Observers: Deserialize<'a>,
    Z: EvaluatorObservers<E::Observers, State = S> + ExecutionProcessor<State = S>,
    IC: InputConverter<From = S::Input, To = DI>,
    ICB: InputConverter<From = DI, To = S::Input>,
    DI: Input,
    <<S as HasCorpus>::Corpus as Corpus>::Input: Clone,
    S::Corpus: Corpus<Input = S::Input>, // delete me
{
    #[inline]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Self::State,
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
    fn should_restart(&mut self, _state: &mut Self::State) -> Result<bool, Error> {
        // No restart handling needed - does not execute the target.
        Ok(true)
    }

    #[inline]
    fn clear_progress(&mut self, _state: &mut Self::State) -> Result<(), Error> {
        // Not needed - does not execute the target.
        Ok(())
    }
}

impl<DI, IC, ICB, S, SP> SyncFromBrokerStage<DI, IC, ICB, S, SP>
where
    SP: ShMemProvider + 'static,
    S: UsesInput,
    IC: InputConverter<From = S::Input, To = DI>,
    ICB: InputConverter<From = DI, To = S::Input>,
    DI: Input,
{
    /// Creates a new [`SyncFromBrokerStage`]
    #[must_use]
    pub fn new(client: LlmpEventConverter<DI, IC, ICB, S, SP>) -> Self {
        Self { client }
    }
}
