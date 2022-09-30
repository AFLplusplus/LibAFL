//! The tracing stage can trace the target and enrich a testcase with metadata, for example for `CmpLog`.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::{fmt::Debug, marker::PhantomData};

use hashbrown::HashSet;
use serde::{Deserialize, Serialize};

#[cfg(feature = "introspection")]
use crate::monitors::PerfFeature;
use crate::{
    bolts::AsSlice,
    corpus::Corpus,
    executors::{Executor, HasObservers},
    feedbacks::map::MapNoveltiesMetadata,
    inputs::{GeneralizedInput, GeneralizedItem, HasBytesVec},
    mark_feature_time,
    observers::{MapObserver, ObserversTuple},
    stages::Stage,
    start_timer,
    state::{HasClientPerfMonitor, HasCorpus, HasExecutions, HasMetadata},
    Error,
};

const MAX_GENERALIZED_LEN: usize = 8192;

/// A state metadata holding the set of indexes related to the generalized corpus entries
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct GeneralizedIndexesMetadata {
    /// The set of indexes
    pub indexes: HashSet<usize>,
}

crate::impl_serdeany!(GeneralizedIndexesMetadata);

impl GeneralizedIndexesMetadata {
    /// Create the metadata
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

fn increment_by_offset(_list: &[Option<u8>], idx: usize, off: u8) -> usize {
    idx + 1 + off as usize
}

fn find_next_char(list: &[Option<u8>], mut idx: usize, ch: u8) -> usize {
    while idx < list.len() {
        if list[idx] == Some(ch) {
            return idx + 1;
        }
        idx += 1;
    }
    idx
}

/// A stage that runs a tracer executor
#[derive(Clone, Debug)]
pub struct GetDepsStage<I>
where
    O: MapObserver,
    OT: ObserversTuple<GeneralizedInput, S>,
    S: HasClientPerfMonitor + HasExecutions + HasMetadata + HasCorpus<GeneralizedInput>,
{
    map_observer_name: String,
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(EM, O, OT, S, Z)>,
}

impl<E, EM, O, OT, S, Z> Stage<E, EM, S, Z> for GetDepsStage<EM, O, OT, S, Z>
where
    O: MapObserver,
    E: Executor<EM, GeneralizedInput, S, Z> + HasObservers<GeneralizedInput, OT, S>,
    OT: ObserversTuple<GeneralizedInput, S>,
    S: HasClientPerfMonitor + HasExecutions + HasMetadata + HasCorpus<GeneralizedInput>,
{
    #[inline]
    #[allow(clippy::too_many_lines)]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error> {
        if state
            .metadata()
            .get::<GeneralizedIndexesMetadata>()
            .is_none()
        {
            state.add_metadata(GeneralizedIndexesMetadata::new());
        }

        let (mut payload, original, novelties) = {
            start_timer!(state);
            state.corpus().get(corpus_idx)?.borrow_mut().load_input()?;
            mark_feature_time!(state, PerfFeature::GetInputFromCorpus);
            let mut entry = state.corpus().get(corpus_idx)?.borrow_mut();
            let input = entry.input_mut().as_mut().unwrap();

            if input.generalized().is_some() {
                drop(entry);
                state
                    .metadata_mut()
                    .get_mut::<GeneralizedIndexesMetadata>()
                    .unwrap()
                    .indexes
                    .insert(corpus_idx);
                return Ok(());
            }

            let payload: Vec<_> = input.bytes().iter().map(|&x| Some(x)).collect();
            let original = input.clone();
            let meta = entry.metadata().get::<MapNoveltiesMetadata>().ok_or_else(|| {
                    Error::key_not_found(format!(
                        "MapNoveltiesMetadata needed for GetDepsStage not found in testcase #{} (check the arguments of MapFeedback::new(...))",
                        corpus_idx
                    ))
                })?;
            (payload, original, meta.as_slice().to_vec())
        };

        // Do not generalized unstable inputs
        if !self.verify_input(fuzzer, executor, state, manager, &novelties, &original)? {
            return Ok(());
        }

        Ok(())
    }
}

impl<EM, O, OT, S, Z> GetDepsStage<EM, O, OT, S, Z>
where
    O: MapObserver,
    OT: ObserversTuple<GeneralizedInput, S>,
    S: HasClientPerfMonitor + HasExecutions + HasMetadata + HasCorpus<GeneralizedInput>,
{
    /// Create a new [`GetDepsStage`].
    #[must_use]
    pub fn new(map_observer: &O) -> Self {
        Self {
            map_observer_name: map_observer.name().to_string(),
            phantom: PhantomData,
        }
    }

    /// Create a new [`GetDepsStage`] from name
    #[must_use]
    pub fn from_name(map_observer_name: &str) -> Self {
        Self {
            map_observer_name: map_observer_name.to_string(),
            phantom: PhantomData,
        }
    }
}
