//! Sync from disk push stage for importing inputs from other fuzzer instances.

use alloc::{borrow::Cow, vec::Vec};
use core::time::Duration;
use std::path::{Path, PathBuf};

use libafl_bolts::{Error, Named, current_time, fs::find_new_files_rec};

use super::{PushStage, StageStep};
use crate::{
    common::{HasMetadata, HasNamedMetadata},
    corpus::HasCurrentCorpusId,
    fuzzer::ExecutionRequest,
    inputs::Input,
    stages::{
        Restartable, RetryCountRestartHelper,
        sync::{SYNC_FROM_DISK_STAGE_NAME, SyncFromDiskMetadata},
    },
};

/// A stage that loads and yields new inputs from disk directories to sync with other fuzzers.
pub struct SyncFromDiskStage<CB> {
    name: Cow<'static, str>,
    sync_dirs: Vec<PathBuf>,
    load_callback: CB,
    interval: Duration,
    batch_size: usize,
}

/// Backwards compatibility alias for [`SyncFromDiskStage`].
pub type SyncFromDiskPushStage<CB> = SyncFromDiskStage<CB>;

impl<CB> core::fmt::Debug for SyncFromDiskStage<CB> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SyncFromDiskStage")
            .field("name", &self.name)
            .field("sync_dirs", &self.sync_dirs)
            .field("interval", &self.interval)
            .field("batch_size", &self.batch_size)
            .finish_non_exhaustive()
    }
}

impl<CB> SyncFromDiskStage<CB> {
    /// Create a new `SyncFromDiskStage`.
    pub fn new(sync_dirs: Vec<PathBuf>, load_callback: CB, interval: Duration) -> Self {
        Self::with_name(
            sync_dirs,
            load_callback,
            interval,
            SYNC_FROM_DISK_STAGE_NAME,
        )
    }

    /// Create a new `SyncFromDiskStage` with a custom name.
    pub fn with_name<N: Into<Cow<'static, str>>>(
        sync_dirs: Vec<PathBuf>,
        load_callback: CB,
        interval: Duration,
        name: N,
    ) -> Self {
        Self {
            name: name.into(),
            sync_dirs,
            load_callback,
            interval,
            batch_size: 16,
        }
    }

    /// Set batch size for yielding inputs.
    #[must_use]
    pub fn with_batch_size(mut self, batch_size: usize) -> Self {
        self.batch_size = batch_size;
        self
    }
}

impl<CB> Named for SyncFromDiskPushStage<CB> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<CB, S> Restartable<S> for SyncFromDiskPushStage<CB>
where
    S: HasMetadata + HasNamedMetadata + HasCurrentCorpusId,
{
    fn should_restart(&mut self, state: &mut S) -> Result<bool, Error> {
        RetryCountRestartHelper::should_restart(state, &self.name, 3)
    }

    fn clear_progress(&mut self, state: &mut S) -> Result<(), Error> {
        RetryCountRestartHelper::clear_progress(state, &self.name)
    }
}

impl<CB, EM, I, OT, S> PushStage<EM, I, OT, S> for SyncFromDiskPushStage<CB>
where
    CB: FnMut(&mut S, &Path) -> Result<I, Error>,
    I: Input + Clone,
    S: HasMetadata + HasNamedMetadata + HasCurrentCorpusId,
{
    fn init(&mut self, state: &mut S, _manager: &mut EM) -> Result<(), Error> {
        let (last, has_pending) = state
            .metadata_map()
            .get::<SyncFromDiskMetadata>()
            .map_or((None, false), |m| {
                (Some(m.last_time), !m.left_to_sync.is_empty())
            });

        if has_pending {
            return Ok(());
        }

        if let Some(last) = last
            && current_time().saturating_sub(last) < self.interval
        {
            return Ok(());
        }

        let new_max_time = current_time();
        let mut new_files = Vec::new();
        for dir in &self.sync_dirs {
            if let Ok(files) = find_new_files_rec(dir, &last) {
                new_files.extend(files);
            }
        }

        let sync_meta = state
            .metadata_or_insert_with(|| SyncFromDiskMetadata::new(new_max_time, new_files.clone()));
        sync_meta.last_time = new_max_time;
        sync_meta.left_to_sync.clone_from(&new_files);

        Ok(())
    }

    fn step(&mut self, state: &mut S, _manager: &mut EM) -> Result<StageStep<I>, Error> {
        let mut batch = Vec::new();
        while batch.len() < self.batch_size {
            let path = if let Ok(meta) = state.metadata_mut::<SyncFromDiskMetadata>() {
                meta.left_to_sync.pop()
            } else {
                None
            };
            let Some(path) = path else {
                break;
            };

            match (self.load_callback)(state, &path) {
                Ok(input) => batch.push(input),
                Err(Error::InvalidInput(..)) => {}
                Err(e) => return Err(e),
            }
        }

        if batch.is_empty() {
            Ok(StageStep::Done)
        } else {
            Ok(StageStep::Execute(ExecutionRequest::batch(batch)))
        }
    }

    fn deinit(&mut self, _state: &mut S, _manager: &mut EM) -> Result<(), Error> {
        Ok(())
    }
}

#[cfg(test)]
#[cfg(feature = "std")]
#[allow(
    clippy::type_complexity,
    clippy::match_wildcard_for_single_variants,
    clippy::duration_suboptimal_units
)]
mod tests {
    use alloc::vec;

    use libafl_bolts::rands::StdRand;

    use super::*;
    use crate::{
        corpus::{Corpus, HasCurrentCorpusId, InMemoryCorpus, Testcase},
        events::NopEventManager,
        feedbacks::ConstFeedback,
        inputs::BytesInput,
        observers::StdMapObserver,
        state::StdState,
    };

    #[test]
    fn test_sync_from_disk_push_stage() {
        let rand = StdRand::with_seed(1234);
        let mut corpus = InMemoryCorpus::<BytesInput>::new();
        let testcase = Testcase::new(BytesInput::new(vec![1, 2, 3, 4]));
        let id = corpus.add(testcase).unwrap();

        let mut feedback = ConstFeedback::new(true);
        let mut objective = ConstFeedback::new(false);
        let mut state = StdState::new(
            rand,
            corpus,
            InMemoryCorpus::new(),
            &mut feedback,
            &mut objective,
        )
        .unwrap();
        state.set_corpus_id(id).unwrap();

        let mut stage = SyncFromDiskPushStage::new(
            vec![],
            |_state: &mut _, path: &Path| {
                Ok(BytesInput::new(path.to_str().unwrap().as_bytes().to_vec()))
            },
            Duration::from_secs(60),
        );
        let mut mgr = NopEventManager::new();

        PushStage::<NopEventManager, BytesInput, (StdMapObserver<'static, u8, false>, ()), _>::init(&mut stage, &mut state, &mut mgr).unwrap();

        let res = PushStage::<
            NopEventManager,
            BytesInput,
            (StdMapObserver<'static, u8, false>, ()),
            _,
        >::step(&mut stage, &mut state, &mut mgr)
        .unwrap();
        assert!(matches!(res, StageStep::Done));

        PushStage::<NopEventManager, BytesInput, (StdMapObserver<'static, u8, false>, ()), _>::deinit(&mut stage, &mut state, &mut mgr).unwrap();
    }
}
