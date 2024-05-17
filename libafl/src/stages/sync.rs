//! The [`SyncFromDiskStage`] is a stage that imports inputs from disk for e.g. sync with AFL

use alloc::borrow::Cow;
use core::marker::PhantomData;
use std::{
    fs,
    path::{Path, PathBuf},
    time::SystemTime,
    vec::Vec,
};

use libafl_bolts::{current_time, shmem::ShMemProvider, Named};
use serde::{Deserialize, Serialize};

#[cfg(feature = "introspection")]
use crate::state::HasClientPerfMonitor;
use crate::{
    corpus::{Corpus, CorpusId, HasTestcase},
    events::{llmp::LlmpEventConverter, Event, EventConfig, EventFirer},
    executors::{Executor, ExitKind, HasObservers},
    fuzzer::{Evaluator, EvaluatorObservers, ExecutionProcessor},
    inputs::{Input, InputConverter, UsesInput},
    stages::{RetryRestartHelper, Stage},
    state::{HasCorpus, HasExecutions, HasRand, State, UsesState},
    Error, HasMetadata, HasNamedMetadata,
};

/// Metadata used to store information about disk sync time
#[cfg_attr(
    any(not(feature = "serdeany_autoreg"), miri),
    allow(clippy::unsafe_derive_deserialize)
)] // for SerdeAny
#[derive(Serialize, Deserialize, Debug)]
pub struct SyncFromDiskMetadata {
    /// The last time the sync was done
    pub last_time: SystemTime,
    /// The paths that are left to sync
    pub left_to_sync: Vec<PathBuf>,
}

libafl_bolts::impl_serdeany!(SyncFromDiskMetadata);

impl SyncFromDiskMetadata {
    /// Create a new [`struct@SyncFromDiskMetadata`]
    #[must_use]
    pub fn new(last_time: SystemTime, left_to_sync: Vec<PathBuf>) -> Self {
        Self {
            last_time,
            left_to_sync,
        }
    }
}

/// A stage that loads testcases from disk to sync with other fuzzers such as AFL++
#[derive(Debug)]
pub struct SyncFromDiskStage<CB, E, EM, Z> {
    sync_dir: PathBuf,
    load_callback: CB,
    phantom: PhantomData<(E, EM, Z)>,
}

impl<CB, E, EM, Z> UsesState for SyncFromDiskStage<CB, E, EM, Z>
where
    E: UsesState,
{
    type State = E::State;
}

impl<CB, E, EM, Z> Named for SyncFromDiskStage<CB, E, EM, Z>
where
    E: UsesState,
{
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("SyncFromDiskStage");
        &NAME
    }
}

impl<CB, E, EM, Z> Stage<E, EM, Z> for SyncFromDiskStage<CB, E, EM, Z>
where
    CB: FnMut(&mut Z, &mut Z::State, &Path) -> Result<<Z::State as UsesInput>::Input, Error>,
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: HasCorpus + HasRand + HasMetadata + HasNamedMetadata,
{
    #[inline]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Z::State,
        manager: &mut EM,
    ) -> Result<(), Error> {
        log::debug!("Syncing from disk: {:?}", self.sync_dir);
        let last = state
            .metadata_map()
            .get::<SyncFromDiskMetadata>()
            .map(|m| m.last_time);

        if let (Some(max_time), mut new_files) = self.load_from_directory(&last)? {
            if last.is_none() {
                state
                    .metadata_map_mut()
                    .insert(SyncFromDiskMetadata::new(max_time, new_files));
            } else {
                state
                    .metadata_map_mut()
                    .get_mut::<SyncFromDiskMetadata>()
                    .unwrap()
                    .last_time = max_time;
                state
                    .metadata_map_mut()
                    .get_mut::<SyncFromDiskMetadata>()
                    .unwrap()
                    .left_to_sync
                    .append(&mut new_files);
            }
        }

        if let Some(sync_from_disk_metadata) =
            state.metadata_map_mut().get_mut::<SyncFromDiskMetadata>()
        {
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
                    .metadata_map_mut()
                    .get_mut::<SyncFromDiskMetadata>()
                    .unwrap()
                    .left_to_sync
                    .retain(|p| p != &path);
                log::debug!("Evaluating: {:?}", path);
                fuzzer.evaluate_input(state, executor, manager, input)?;
            }
        }

        #[cfg(feature = "introspection")]
        state.introspection_monitor_mut().finish_stage();

        Ok(())
    }

    #[inline]
    fn restart_progress_should_run(&mut self, state: &mut Self::State) -> Result<bool, Error> {
        // TODO: Needs proper crash handling for when an imported testcase crashes
        // For now, Make sure we don't get stuck crashing on this testcase
        RetryRestartHelper::restart_progress_should_run(state, self, 3)
    }

    #[inline]
    fn clear_restart_progress(&mut self, state: &mut Self::State) -> Result<(), Error> {
        RetryRestartHelper::clear_restart_progress(state, self)
    }
}

impl<CB, E, EM, Z> SyncFromDiskStage<CB, E, EM, Z>
where
    CB: FnMut(&mut Z, &mut Z::State, &Path) -> Result<<Z::State as UsesInput>::Input, Error>,
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: HasCorpus + HasRand + HasMetadata,
{
    /// Creates a new [`SyncFromDiskStage`]
    #[must_use]
    pub fn new(sync_dir: PathBuf, load_callback: CB) -> Self {
        Self {
            sync_dir,
            load_callback,
            phantom: PhantomData,
        }
    }

    fn load_from_directory(
        &self,
        last: &Option<SystemTime>,
    ) -> Result<(Option<SystemTime>, Vec<PathBuf>), Error> {
        let mut max_time = None;
        let mut left_to_sync = Vec::<PathBuf>::new();
        let in_dir = self.sync_dir.clone();

        for entry in fs::read_dir(in_dir)? {
            let entry = entry?;
            let path = entry.path();
            let attributes = fs::metadata(&path);

            if attributes.is_err() {
                continue;
            }

            let attr = attributes?;

            if attr.is_file() && attr.len() > 0 {
                if let Ok(time) = attr.modified() {
                    if let Some(l) = last {
                        if time.duration_since(*l).is_err() || time == *l {
                            continue;
                        }
                    }
                    max_time = Some(max_time.map_or(time, |t: SystemTime| t.max(time)));
                    log::info!("Syncing file: {:?}", path);
                    left_to_sync.push(path.clone());
                }
            } else if attr.is_dir() {
                let (dir_max_time, dir_left_to_sync) = self.load_from_directory(last)?;
                if let Some(time) = dir_max_time {
                    max_time = Some(max_time.map_or(time, |t: SystemTime| t.max(time)));
                }
                left_to_sync.extend(dir_left_to_sync);
            }
        }

        Ok((max_time, left_to_sync))
    }
}

/// Function type when the callback in `SyncFromDiskStage` is not a lambda
pub type SyncFromDiskFunction<S, Z> =
    fn(&mut Z, &mut S, &Path) -> Result<<S as UsesInput>::Input, Error>;

impl<E, EM, Z> SyncFromDiskStage<SyncFromDiskFunction<Z::State, Z>, E, EM, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: HasCorpus + HasRand + HasMetadata,
{
    /// Creates a new [`SyncFromDiskStage`] invoking `Input::from_file` to load inputs
    #[must_use]
    pub fn with_from_file(sync_dir: PathBuf) -> Self {
        fn load_callback<S: UsesInput, Z>(
            _: &mut Z,
            _: &mut S,
            p: &Path,
        ) -> Result<S::Input, Error> {
            Input::from_file(p)
        }
        Self {
            sync_dir,
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
    S: State + HasExecutions + HasCorpus + HasRand + HasMetadata + HasTestcase,
    SP: ShMemProvider,
    E: HasObservers<State = S> + Executor<EM, Z>,
    for<'a> E::Observers: Deserialize<'a>,
    Z: EvaluatorObservers<E::Observers, State = S> + ExecutionProcessor<E::Observers, State = S>,
    IC: InputConverter<From = S::Input, To = DI>,
    ICB: InputConverter<From = DI, To = S::Input>,
    DI: Input,
{
    #[inline]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Z::State,
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
    fn restart_progress_should_run(&mut self, _state: &mut Self::State) -> Result<bool, Error> {
        // No restart handling needed - does not execute the target.
        Ok(true)
    }

    #[inline]
    fn clear_restart_progress(&mut self, _state: &mut Self::State) -> Result<(), Error> {
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
