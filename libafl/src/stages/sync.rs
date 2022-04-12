//| The [`MutationalStage`] is the default stage used during fuzzing.
//! For the current input, it will perform a range of random mutations, and then run them in the executor.

use core::marker::PhantomData;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
    time::SystemTime,
};

use crate::{
    fuzzer::Evaluator,
    inputs::Input,
    stages::Stage,
    state::{HasClientPerfMonitor, HasCorpus, HasMetadata, HasRand},
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
pub struct SyncFromDiskStage<CB, E, EM, I, S, Z>
where
    CB: FnMut(&mut Z, &mut S, &Path) -> Result<I, Error>,
    I: Input,
    S: HasClientPerfMonitor + HasCorpus<I> + HasRand + HasMetadata,
    Z: Evaluator<E, EM, I, S>,
{
    sync_dir: PathBuf,
    load_callback: CB,
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(E, EM, I, S, Z)>,
}

impl<CB, E, EM, I, S, Z> Stage<E, EM, S, Z> for SyncFromDiskStage<CB, E, EM, I, S, Z>
where
    CB: FnMut(&mut Z, &mut S, &Path) -> Result<I, Error>,
    I: Input,
    S: HasClientPerfMonitor + HasCorpus<I> + HasRand + HasMetadata,
    Z: Evaluator<E, EM, I, S>,
{
    #[inline]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
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

impl<CB, E, EM, I, S, Z> SyncFromDiskStage<CB, E, EM, I, S, Z>
where
    CB: FnMut(&mut Z, &mut S, &Path) -> Result<I, Error>,
    I: Input,
    S: HasClientPerfMonitor + HasCorpus<I> + HasRand + HasMetadata,
    Z: Evaluator<E, EM, I, S>,
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
        state: &mut S,
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

impl<E, EM, I, S, Z>
    SyncFromDiskStage<fn(&mut Z, &mut S, &Path) -> Result<I, Error>, E, EM, I, S, Z>
where
    I: Input,
    S: HasClientPerfMonitor + HasCorpus<I> + HasRand + HasMetadata,
    Z: Evaluator<E, EM, I, S>,
{
    /// Creates a new [`SyncFromDiskStage`] invoking `Input::from_file` to load inputs
    #[must_use]
    pub fn with_from_file(sync_dir: PathBuf) -> Self {
        fn load_callback<Z, S, I: Input>(_: &mut Z, _: &mut S, p: &Path) -> Result<I, Error> {
            I::from_file(p)
        }
        Self {
            sync_dir,
            load_callback: load_callback::<_, _, I>,
            phantom: PhantomData,
        }
    }
}
