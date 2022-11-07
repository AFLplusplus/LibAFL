//| The [`MutationalStage`] is the default stage used during fuzzing.
//! For the current input, it will perform a range of random mutations, and then run them in the executor.

use core::marker::PhantomData;
use std::{
    fs,
    path::{Path, PathBuf},
    time::SystemTime,
};

use serde::{Deserialize, Serialize};

use crate::{
    fuzzer::Evaluator,
    inputs::{Input, UsesInput},
    stages::Stage,
    state::{HasClientPerfMonitor, HasCorpus, HasMetadata, HasRand, UsesState},
    Error,
};

/// Metadata used to store information about disk sync time
#[derive(Serialize, Deserialize, Debug)]
pub struct SyncFromDiskMetadata {
    /// The last time the sync was done
    pub last_time: SystemTime,
}

crate::impl_serdeany!(SyncFromDiskMetadata);

impl SyncFromDiskMetadata {
    /// Create a new [`struct@SyncFromDiskMetadata`]
    #[must_use]
    pub fn new(last_time: SystemTime) -> Self {
        Self { last_time }
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

impl<CB, E, EM, Z> Stage<E, EM, Z> for SyncFromDiskStage<CB, E, EM, Z>
where
    CB: FnMut(&mut Z, &mut Z::State, &Path) -> Result<<Z::State as UsesInput>::Input, Error>,
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: HasClientPerfMonitor + HasCorpus + HasRand + HasMetadata,
{
    #[inline]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Z::State,
        manager: &mut EM,
        _corpus_idx: usize,
    ) -> Result<(), Error> {
        let last = state
            .metadata()
            .get::<SyncFromDiskMetadata>()
            .map(|m| m.last_time);
        let path = self.sync_dir.clone();
        if let Some(max_time) =
            self.load_from_directory(&path, &last, fuzzer, executor, state, manager)?
        {
            if last.is_none() {
                state
                    .metadata_mut()
                    .insert(SyncFromDiskMetadata::new(max_time));
            } else {
                state
                    .metadata_mut()
                    .get_mut::<SyncFromDiskMetadata>()
                    .unwrap()
                    .last_time = max_time;
            }
        }

        #[cfg(feature = "introspection")]
        state.introspection_monitor_mut().finish_stage();

        Ok(())
    }
}

impl<CB, E, EM, Z> SyncFromDiskStage<CB, E, EM, Z>
where
    CB: FnMut(&mut Z, &mut Z::State, &Path) -> Result<<Z::State as UsesInput>::Input, Error>,
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: HasClientPerfMonitor + HasCorpus + HasRand + HasMetadata,
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
        &mut self,
        in_dir: &Path,
        last: &Option<SystemTime>,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Z::State,
        manager: &mut EM,
    ) -> Result<Option<SystemTime>, Error> {
        let mut max_time = None;
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
                        if time.duration_since(*l).is_err() {
                            continue;
                        }
                    }
                    max_time = Some(max_time.map_or(time, |t: SystemTime| t.max(time)));
                    let input = (self.load_callback)(fuzzer, state, &path)?;
                    fuzzer.evaluate_input(state, executor, manager, input)?;
                }
            } else if attr.is_dir() {
                let dir_max_time =
                    self.load_from_directory(&path, last, fuzzer, executor, state, manager)?;
                if let Some(time) = dir_max_time {
                    max_time = Some(max_time.map_or(time, |t: SystemTime| t.max(time)));
                }
            }
        }

        Ok(max_time)
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
    Z::State: HasClientPerfMonitor + HasCorpus + HasRand + HasMetadata,
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
