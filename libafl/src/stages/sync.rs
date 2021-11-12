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
    bolts::rands::Rand,
    corpus::Corpus,
    fuzzer::Evaluator,
    inputs::Input,
    stages::Stage,
    state::{HasClientPerfMonitor, HasCorpus, HasMetadata, HasRand},
    Error,
};

#[cfg(feature = "introspection")]
use crate::monitors::PerfFeature;

#[derive(Serialize, Deserialize)]
pub struct SyncFromDiskMetadata {
    pub last_time: SystemTime,
}

crate::impl_serdeany!(SyncFromDiskMetadata);

impl SyncFromDiskMetadata {
    pub fn new(last_time: SystemTime) -> Self {
        Self { last_time }
    }
}

/// The default mutational stage
pub struct SyncFromDiskStage<C, CB, E, EM, I, R, S, Z>
where
    C: Corpus<I>,
    CB: FnMut(&mut Z, &mut S, &Path) -> Result<I, Error>,
    I: Input,
    R: Rand,
    S: HasClientPerfMonitor + HasCorpus<C, I> + HasRand<R> + HasMetadata,
    Z: Evaluator<E, EM, I, S>,
{
    sync_dir: PathBuf,
    load_callback: CB,
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(C, E, EM, I, R, S, Z)>,
}

impl<C, CB, E, EM, I, R, S, Z> Stage<E, EM, S, Z> for SyncFromDiskStage<C, CB, E, EM, I, R, S, Z>
where
    C: Corpus<I>,
    CB: FnMut(&mut Z, &mut S, &Path) -> Result<I, Error>,
    I: Input,
    R: Rand,
    S: HasClientPerfMonitor + HasCorpus<C, I> + HasRand<R> + HasMetadata,
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
                    .insert::<SyncFromDiskMetadata>(SyncFromDiskMetadata::new(max_time))
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

impl<C, CB, E, EM, I, R, S, Z> SyncFromDiskStage<C, CB, E, EM, I, R, S, Z>
where
    C: Corpus<I>,
    CB: FnMut(&mut Z, &mut S, &Path) -> Result<I, Error>,
    I: Input,
    R: Rand,
    S: HasClientPerfMonitor + HasCorpus<C, I> + HasRand<R> + HasMetadata,
    Z: Evaluator<E, EM, I, S>,
{
    /// Creates a new default mutational stage
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
                    max_time = Some(max_time.map(|t: SystemTime| t.max(time)).unwrap_or(time));
                    let input = (self.load_callback)(fuzzer, state, &path)?;
                    drop(fuzzer.evaluate_input(state, executor, manager, input)?);
                }
            } else if attr.is_dir() {
                let dir_max_time =
                    self.load_from_directory(&path, last, fuzzer, executor, state, manager)?;
                if let Some(time) = dir_max_time {
                    max_time = Some(max_time.map(|t: SystemTime| t.max(time)).unwrap_or(time));
                }
            }
        }

        Ok(max_time)
    }
}
