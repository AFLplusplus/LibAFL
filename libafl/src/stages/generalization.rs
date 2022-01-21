//! The tracing stage can trace the target and enrich a testcase with metadata, for example for `CmpLog`.

use core::{fmt::Debug, marker::PhantomData};

use crate::{
    bolts::AsSlice,
    corpus::Corpus,
    executors::{Executor, HasObservers},
    feedbacks::map::MapNoveltiesMetadata,
    inputs::{GeneralizedInput, HasBytesVec},
    mark_feature_time,
    observers::{MapObserver, ObserversTuple},
    stages::Stage,
    start_timer,
    state::{HasClientPerfMonitor, HasCorpus, HasExecutions, HasMetadata},
    Error,
};

#[cfg(feature = "introspection")]
use crate::monitors::PerfFeature;

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
    S: HasClientPerfMonitor + HasExecutions + HasCorpus<GeneralizedInput>,
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
    S: HasClientPerfMonitor + HasExecutions + HasCorpus<GeneralizedInput>,
{
    #[inline]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error> {
        let (mut payload, original, novelties) = {
            start_timer!(state);
            let mut entry = state.corpus().get(corpus_idx)?.borrow_mut();
            let input = entry.load_input()?;
            mark_feature_time!(state, PerfFeature::GetInputFromCorpus);

            if input.generalized().is_some() {
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

        let mut verify_input = |input| -> Result<bool, Error> {
            start_timer!(state);
            executor.observers_mut().pre_exec_all(state, &input)?;
            mark_feature_time!(state, PerfFeature::PreExecObservers);

            start_timer!(state);
            let _ = executor.run_target(fuzzer, state, manager, &input)?;
            mark_feature_time!(state, PerfFeature::TargetExecution);

            *state.executions_mut() += 1;

            start_timer!(state);
            executor.observers_mut().post_exec_all(state, &input)?;
            mark_feature_time!(state, PerfFeature::PostExecObservers);

            let cnt = executor
                .observers()
                .match_name::<O>(&self.map_observer_name)
                .ok_or_else(|| Error::KeyNotFound("MapObserver not found".to_string()))?
                .how_many_set(&novelties);

            Ok(cnt == novelties.len())
        };

        // Do not generalized unstable inputs
        if !verify_input(original)? {
            return Ok(());
        }

        let trim_payload = |payload: &mut Vec<Option<u8>>| {
            let mut previous = false;
            payload.retain(|&x| !(x.is_none() & core::mem::replace(&mut previous, x.is_none())));
        };

        let mut find_gaps = |find_next_index: fn(&[Option<u8>], usize, u8) -> usize,
                             split_char: u8|
         -> Result<(), Error> {
            let mut start = 0;
            while start < payload.len() {
                let end = find_next_index(&payload, start, split_char);
                let mut candidate = GeneralizedInput::new(vec![]);
                candidate.bytes_mut().extend(
                    payload[..start]
                        .iter()
                        .filter(|x| x.is_some())
                        .map(|x| x.unwrap()),
                ); //maybe copied()
                candidate.bytes_mut().extend(
                    payload[end..]
                        .iter()
                        .filter(|x| x.is_some())
                        .map(|x| x.unwrap()),
                );

                if verify_input(candidate)? {
                    for item in &mut payload[start..end] {
                        *item = None;
                    }
                }

                start = end;
            }

            trim_payload(&mut payload);
            Ok(())
        };

        find_gaps(increment_by_offset, 255)?;
        find_gaps(increment_by_offset, 127)?;
        find_gaps(increment_by_offset, 63)?;
        find_gaps(increment_by_offset, 31)?;
        find_gaps(increment_by_offset, 0)?;

        find_gaps(find_next_char, '.' as u8)?;
        find_gaps(find_next_char, ';' as u8)?;
        find_gaps(find_next_char, ',' as u8)?;
        find_gaps(find_next_char, '\n' as u8)?;
        find_gaps(find_next_char, '\r' as u8)?;
        find_gaps(find_next_char, '#' as u8)?;
        find_gaps(find_next_char, ' ' as u8)?;

        // TODO find_gaps_in_closures

        // Save the modified input in the corpus
        let mut entry = state.corpus().get(corpus_idx)?.borrow_mut();
        entry.load_input()?;
        entry
            .input_mut()
            .as_mut()
            .unwrap()
            .generalized_from_options(&payload);
        entry.store_input()?;

        Ok(())
    }
}

impl<EM, O, OT, S, Z> GeneralizationStage<EM, O, OT, S, Z>
where
    O: MapObserver,
    OT: ObserversTuple<GeneralizedInput, S>,
    S: HasClientPerfMonitor + HasExecutions + HasCorpus<GeneralizedInput>,
{
    /// Create a new [`GeneralizationStage`].
    pub fn new(map_observer: &O) -> Self {
        Self {
            map_observer_name: map_observer.name().to_string(),
            phantom: PhantomData,
        }
    }

    /// Create a new [`GeneralizationStage`] from name
    pub fn from_name(map_observer_name: &str) -> Self {
        Self {
            map_observer_name: map_observer_name.to_string(),
            phantom: PhantomData,
        }
    }
}
