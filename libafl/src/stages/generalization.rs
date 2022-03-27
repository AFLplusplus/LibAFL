//! The tracing stage can trace the target and enrich a testcase with metadata, for example for `CmpLog`.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::{fmt::Debug, marker::PhantomData};
use hashbrown::HashSet;
use serde::{Deserialize, Serialize};

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

#[cfg(feature = "introspection")]
use crate::monitors::PerfFeature;

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
pub struct GeneralizationStage<EM, O, OT, S, Z>
where
    O: MapObserver,
    OT: ObserversTuple<GeneralizedInput, S>,
    S: HasClientPerfMonitor + HasExecutions + HasMetadata + HasCorpus<GeneralizedInput>,
{
    map_observer_name: String,
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(EM, O, OT, S, Z)>,
}

impl<E, EM, O, OT, S, Z> Stage<E, EM, S, Z> for GeneralizationStage<EM, O, OT, S, Z>
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
                    Error::KeyNotFound(format!(
                        "MapNoveltiesMetadata needed for GeneralizationStage not found in testcase #{} (check the arguments of MapFeedback::new(...))",
                        corpus_idx
                    ))
                })?;
            (payload, original, meta.as_slice().to_vec())
        };

        // Do not generalized unstable inputs
        if !self.verify_input(fuzzer, executor, state, manager, &novelties, &original)? {
            return Ok(());
        }

        self.find_gaps(
            fuzzer,
            executor,
            state,
            manager,
            &mut payload,
            &novelties,
            increment_by_offset,
            255,
        )?;
        self.find_gaps(
            fuzzer,
            executor,
            state,
            manager,
            &mut payload,
            &novelties,
            increment_by_offset,
            127,
        )?;
        self.find_gaps(
            fuzzer,
            executor,
            state,
            manager,
            &mut payload,
            &novelties,
            increment_by_offset,
            63,
        )?;
        self.find_gaps(
            fuzzer,
            executor,
            state,
            manager,
            &mut payload,
            &novelties,
            increment_by_offset,
            31,
        )?;
        self.find_gaps(
            fuzzer,
            executor,
            state,
            manager,
            &mut payload,
            &novelties,
            increment_by_offset,
            0,
        )?;

        self.find_gaps(
            fuzzer,
            executor,
            state,
            manager,
            &mut payload,
            &novelties,
            find_next_char,
            b'.',
        )?;
        self.find_gaps(
            fuzzer,
            executor,
            state,
            manager,
            &mut payload,
            &novelties,
            find_next_char,
            b';',
        )?;
        self.find_gaps(
            fuzzer,
            executor,
            state,
            manager,
            &mut payload,
            &novelties,
            find_next_char,
            b',',
        )?;
        self.find_gaps(
            fuzzer,
            executor,
            state,
            manager,
            &mut payload,
            &novelties,
            find_next_char,
            b'\n',
        )?;
        self.find_gaps(
            fuzzer,
            executor,
            state,
            manager,
            &mut payload,
            &novelties,
            find_next_char,
            b'\r',
        )?;
        self.find_gaps(
            fuzzer,
            executor,
            state,
            manager,
            &mut payload,
            &novelties,
            find_next_char,
            b'#',
        )?;
        self.find_gaps(
            fuzzer,
            executor,
            state,
            manager,
            &mut payload,
            &novelties,
            find_next_char,
            b' ',
        )?;

        self.find_gaps_in_closures(
            fuzzer,
            executor,
            state,
            manager,
            &mut payload,
            &novelties,
            b'(',
            b')',
        )?;
        self.find_gaps_in_closures(
            fuzzer,
            executor,
            state,
            manager,
            &mut payload,
            &novelties,
            b'[',
            b']',
        )?;
        self.find_gaps_in_closures(
            fuzzer,
            executor,
            state,
            manager,
            &mut payload,
            &novelties,
            b'{',
            b'}',
        )?;
        self.find_gaps_in_closures(
            fuzzer,
            executor,
            state,
            manager,
            &mut payload,
            &novelties,
            b'<',
            b'>',
        )?;
        self.find_gaps_in_closures(
            fuzzer,
            executor,
            state,
            manager,
            &mut payload,
            &novelties,
            b'\'',
            b'\'',
        )?;
        self.find_gaps_in_closures(
            fuzzer,
            executor,
            state,
            manager,
            &mut payload,
            &novelties,
            b'"',
            b'"',
        )?;

        if payload.len() <= MAX_GENERALIZED_LEN {
            // Save the modified input in the corpus
            {
                let mut entry = state.corpus().get(corpus_idx)?.borrow_mut();
                entry.load_input()?;
                entry
                    .input_mut()
                    .as_mut()
                    .unwrap()
                    .generalized_from_options(&payload);
                entry.store_input()?;

                debug_assert!(
                    entry.load_input()?.generalized().unwrap().first()
                        == Some(&GeneralizedItem::Gap)
                );
                debug_assert!(
                    entry.load_input()?.generalized().unwrap().last()
                        == Some(&GeneralizedItem::Gap)
                );
            }

            state
                .metadata_mut()
                .get_mut::<GeneralizedIndexesMetadata>()
                .unwrap()
                .indexes
                .insert(corpus_idx);
        }

        Ok(())
    }
}

impl<EM, O, OT, S, Z> GeneralizationStage<EM, O, OT, S, Z>
where
    O: MapObserver,
    OT: ObserversTuple<GeneralizedInput, S>,
    S: HasClientPerfMonitor + HasExecutions + HasMetadata + HasCorpus<GeneralizedInput>,
{
    /// Create a new [`GeneralizationStage`].
    #[must_use]
    pub fn new(map_observer: &O) -> Self {
        Self {
            map_observer_name: map_observer.name().to_string(),
            phantom: PhantomData,
        }
    }

    /// Create a new [`GeneralizationStage`] from name
    #[must_use]
    pub fn from_name(map_observer_name: &str) -> Self {
        Self {
            map_observer_name: map_observer_name.to_string(),
            phantom: PhantomData,
        }
    }

    fn verify_input<E>(
        &self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        novelties: &[usize],
        input: &GeneralizedInput,
    ) -> Result<bool, Error>
    where
        E: Executor<EM, GeneralizedInput, S, Z> + HasObservers<GeneralizedInput, OT, S>,
    {
        start_timer!(state);
        executor.observers_mut().pre_exec_all(state, input)?;
        mark_feature_time!(state, PerfFeature::PreExecObservers);

        start_timer!(state);
        let exit_kind = executor.run_target(fuzzer, state, manager, input)?;
        mark_feature_time!(state, PerfFeature::TargetExecution);

        *state.executions_mut() += 1;

        start_timer!(state);
        executor
            .observers_mut()
            .post_exec_all(state, input, &exit_kind)?;
        mark_feature_time!(state, PerfFeature::PostExecObservers);

        let cnt = executor
            .observers()
            .match_name::<O>(&self.map_observer_name)
            .ok_or_else(|| Error::KeyNotFound("MapObserver not found".to_string()))?
            .how_many_set(novelties);

        Ok(cnt == novelties.len())
    }

    fn trim_payload(payload: &mut Vec<Option<u8>>) {
        let mut previous = false;
        payload.retain(|&x| !(x.is_none() & core::mem::replace(&mut previous, x.is_none())));
    }

    #[allow(clippy::too_many_arguments)]
    fn find_gaps<E>(
        &self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        payload: &mut Vec<Option<u8>>,
        novelties: &[usize],
        find_next_index: fn(&[Option<u8>], usize, u8) -> usize,
        split_char: u8,
    ) -> Result<(), Error>
    where
        E: Executor<EM, GeneralizedInput, S, Z> + HasObservers<GeneralizedInput, OT, S>,
    {
        let mut start = 0;
        while start < payload.len() {
            let mut end = find_next_index(payload, start, split_char);
            if end > payload.len() {
                end = payload.len();
            }
            let mut candidate = GeneralizedInput::new(vec![]);
            candidate
                .bytes_mut()
                .extend(payload[..start].iter().flatten());
            candidate
                .bytes_mut()
                .extend(payload[end..].iter().flatten());

            if self.verify_input(fuzzer, executor, state, manager, novelties, &candidate)? {
                for item in &mut payload[start..end] {
                    *item = None;
                }
            }

            start = end;
        }

        Self::trim_payload(payload);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn find_gaps_in_closures<E>(
        &self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        payload: &mut Vec<Option<u8>>,
        novelties: &[usize],
        opening_char: u8,
        closing_char: u8,
    ) -> Result<(), Error>
    where
        E: Executor<EM, GeneralizedInput, S, Z> + HasObservers<GeneralizedInput, OT, S>,
    {
        let mut index = 0;
        while index < payload.len() {
            // Find start index
            while index < payload.len() {
                if payload[index] == Some(opening_char) {
                    break;
                }
                index += 1;
            }
            let mut start = index;
            let mut end = payload.len() - 1;
            let mut endings = 0;
            // Process every ending
            while end > start {
                if payload[end] == Some(closing_char) {
                    endings += 1;
                    let mut candidate = GeneralizedInput::new(vec![]);
                    candidate
                        .bytes_mut()
                        .extend(payload[..start].iter().flatten());
                    candidate
                        .bytes_mut()
                        .extend(payload[end..].iter().flatten());

                    if self.verify_input(fuzzer, executor, state, manager, novelties, &candidate)? {
                        for item in &mut payload[start..end] {
                            *item = None;
                        }
                    }
                    start = end;
                }
                end -= 1;
                index += 1;
            }

            if endings == 0 {
                break;
            }
        }

        Self::trim_payload(payload);
        Ok(())
    }
}
