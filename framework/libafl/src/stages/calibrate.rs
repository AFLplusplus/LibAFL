//! The calibration stage. The fuzzer measures the average exec time and the bitmap size.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::{fmt::Debug, marker::PhantomData, time::Duration};

use hashbrown::HashSet;
use num_traits::Bounded;
use serde::{Deserialize, Serialize};

use crate::{
    bolts::{current_time, tuples::Named, AsIter},
    corpus::{Corpus, SchedulerTestcaseMetaData},
    events::{EventFirer, LogSeverity},
    executors::{Executor, ExitKind, HasObservers},
    feedbacks::{
        map::{IsNovel, MapFeedback, MapFeedbackMetadata, Reducer},
        HasObserverName,
    },
    fuzzer::Evaluator,
    inputs::UsesInput,
    observers::{MapObserver, ObserversTuple},
    schedulers::powersched::SchedulerMetadata,
    stages::Stage,
    state::{HasClientPerfMonitor, HasCorpus, HasMetadata, HasNamedMetadata, UsesState},
    Error,
};

crate::impl_serdeany!(UnstableEntriesMetadata);
/// The metadata to keep unstable entries
/// In libafl, the stability is the number of the unstable entries divided by the size of the map
/// This is different from AFL++, which shows the number of the unstable entries divided by the number of filled entries.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UnstableEntriesMetadata {
    unstable_entries: HashSet<usize>,
    map_len: usize,
}

impl UnstableEntriesMetadata {
    #[must_use]
    /// Create a new [`struct@UnstableEntriesMetadata`]
    pub fn new(entries: HashSet<usize>, map_len: usize) -> Self {
        Self {
            unstable_entries: entries,
            map_len,
        }
    }

    /// Getter
    #[must_use]
    pub fn unstable_entries(&self) -> &HashSet<usize> {
        &self.unstable_entries
    }

    /// Getter
    #[must_use]
    pub fn map_len(&self) -> usize {
        self.map_len
    }
}

/// The calibration stage will measure the average exec time and the target's stability for this input.
#[derive(Clone, Debug)]
pub struct CalibrationStage<O, OT, S> {
    map_observer_name: String,
    map_name: String,
    stage_max: usize,
    track_stability: bool,
    phantom: PhantomData<(O, OT, S)>,
}

const CAL_STAGE_START: usize = 4; // AFL++'s CAL_CYCLES_FAST + 1
const CAL_STAGE_MAX: usize = 8; // AFL++'s CAL_CYCLES + 1

impl<O, OT, S> UsesState for CalibrationStage<O, OT, S>
where
    S: UsesInput,
{
    type State = S;
}

impl<E, EM, O, OT, Z> Stage<E, EM, Z> for CalibrationStage<O, OT, E::State>
where
    E: Executor<EM, Z> + HasObservers<Observers = OT>,
    EM: EventFirer<State = E::State>,
    O: MapObserver,
    for<'de> <O as MapObserver>::Entry: Serialize + Deserialize<'de> + 'static,
    OT: ObserversTuple<E::State>,
    E::State: HasCorpus + HasMetadata + HasClientPerfMonitor + HasNamedMetadata,
    Z: Evaluator<E, EM, State = E::State>,
{
    #[inline]
    #[allow(clippy::let_and_return, clippy::too_many_lines)]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut E::State,
        mgr: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error> {
        // Run this stage only once for each corpus entry
        if state.corpus().get(corpus_idx)?.borrow_mut().fuzz_level() > 0 {
            return Ok(());
        }

        let mut iter = self.stage_max;

        let input = state
            .corpus()
            .get(corpus_idx)?
            .borrow_mut()
            .load_input()?
            .clone();

        // Run once to get the initial calibration map
        executor.observers_mut().pre_exec_all(state, &input)?;

        let mut start = current_time();

        let exit_kind = executor.run_target(fuzzer, state, mgr, &input)?;
        let mut total_time = if exit_kind == ExitKind::Ok {
            current_time() - start
        } else {
            mgr.log(
                state,
                LogSeverity::Warn,
                "Corpus entry errored on execution!".into(),
            )?;
            // assume one second as default time
            Duration::from_secs(1)
        };

        executor
            .observers_mut()
            .post_exec_all(state, &input, &exit_kind)?;

        let map_first = &executor
            .observers()
            .match_name::<O>(&self.map_observer_name)
            .ok_or_else(|| Error::key_not_found("MapObserver not found".to_string()))?
            .to_vec();

        let mut unstable_entries: Vec<usize> = vec![];
        let map_len: usize = map_first.len();
        // Run CAL_STAGE_START - 1 times, increase by 2 for every time a new
        // run is found to be unstable, with CAL_STAGE_MAX total runs.
        let mut i = 1;
        let mut has_errors = false;

        while i < iter {
            let input = state
                .corpus()
                .get(corpus_idx)?
                .borrow_mut()
                .load_input()?
                .clone();

            executor.observers_mut().pre_exec_all(state, &input)?;
            start = current_time();

            let exit_kind = executor.run_target(fuzzer, state, mgr, &input)?;
            if exit_kind != ExitKind::Ok {
                if !has_errors {
                    mgr.log(
                        state,
                        LogSeverity::Warn,
                        "Corpus entry errored on execution!".into(),
                    )?;

                    has_errors = true;
                    if iter < CAL_STAGE_MAX {
                        iter += 2;
                    };
                }
                continue;
            };

            total_time += current_time() - start;

            executor
                .observers_mut()
                .post_exec_all(state, &input, &exit_kind)?;

            if self.track_stability {
                let map = &executor
                    .observers()
                    .match_name::<O>(&self.map_observer_name)
                    .ok_or_else(|| Error::key_not_found("MapObserver not found".to_string()))?
                    .to_vec();

                let history_map = &mut state
                    .named_metadata_mut()
                    .get_mut::<MapFeedbackMetadata<O::Entry>>(&self.map_name)
                    .unwrap()
                    .history_map;

                if history_map.len() < map_len {
                    history_map.resize(map_len, O::Entry::default());
                }

                for (idx, (first, (cur, history))) in map_first
                    .iter()
                    .zip(map.iter().zip(history_map.iter_mut()))
                    .enumerate()
                {
                    if *first != *cur && *history != O::Entry::max_value() {
                        *history = O::Entry::max_value();
                        unstable_entries.push(idx);
                    };
                }

                if !unstable_entries.is_empty() && iter < CAL_STAGE_MAX {
                    iter += 2;
                }
            }
            i += 1;
        }

        #[allow(clippy::cast_precision_loss)]
        if !unstable_entries.is_empty() {
            // If we see new stable entries executing this new corpus entries, then merge with the existing one
            if state.has_metadata::<UnstableEntriesMetadata>() {
                let existing = state
                    .metadata_mut()
                    .get_mut::<UnstableEntriesMetadata>()
                    .unwrap();
                for item in unstable_entries {
                    existing.unstable_entries.insert(item); // Insert newly found items
                }
                existing.map_len = map_len;
            } else {
                state.add_metadata::<UnstableEntriesMetadata>(UnstableEntriesMetadata::new(
                    HashSet::from_iter(unstable_entries),
                    map_len,
                ));
            }
        };

        // If weighted scheduler or powerscheduler is used, update it
        let use_powerschedule = state.has_metadata::<SchedulerMetadata>()
            && state
                .corpus()
                .get(corpus_idx)?
                .borrow()
                .has_metadata::<SchedulerTestcaseMetaData>();

        if use_powerschedule {
            let map = executor
                .observers()
                .match_name::<O>(&self.map_observer_name)
                .ok_or_else(|| Error::key_not_found("MapObserver not found".to_string()))?;

            let bitmap_size = map.count_bytes();

            let psmeta = state.metadata_mut().get_mut::<SchedulerMetadata>().unwrap();
            let handicap = psmeta.queue_cycles();

            psmeta.set_exec_time(psmeta.exec_time() + total_time);
            psmeta.set_cycles(psmeta.cycles() + (iter as u64));
            psmeta.set_bitmap_size(psmeta.bitmap_size() + bitmap_size);
            psmeta.set_bitmap_entries(psmeta.bitmap_entries() + 1);

            let mut testcase = state.corpus().get(corpus_idx)?.borrow_mut();
            let fuzz_level = testcase.fuzz_level();

            testcase.set_exec_time(total_time / (iter as u32));
            testcase.set_fuzz_leve(fuzz_level + 1);
            // println!("time: {:#?}", testcase.exec_time());

            let data = testcase
                .metadata_mut()
                .get_mut::<SchedulerTestcaseMetaData>()
                .ok_or_else(|| {
                    Error::key_not_found("SchedulerTestcaseMetaData not found".to_string())
                })?;

            data.set_bitmap_size(bitmap_size);
            data.set_handicap(handicap);
        }

        Ok(())
    }
}

impl<O, OT, S> CalibrationStage<O, OT, S>
where
    O: MapObserver,
    OT: ObserversTuple<S>,
    S: HasCorpus + HasMetadata + HasNamedMetadata,
{
    /// Create a new [`CalibrationStage`].
    #[must_use]
    pub fn new<N, R>(map_feedback: &MapFeedback<N, O, R, S, O::Entry>) -> Self
    where
        O::Entry:
            PartialEq + Default + Copy + 'static + Serialize + serde::de::DeserializeOwned + Debug,
        R: Reducer<O::Entry>,
        for<'it> O: AsIter<'it, Item = O::Entry>,
        N: IsNovel<O::Entry>,
    {
        Self {
            map_observer_name: map_feedback.observer_name().to_string(),
            map_name: map_feedback.name().to_string(),
            stage_max: CAL_STAGE_START,
            track_stability: true,
            phantom: PhantomData,
        }
    }

    /// Create a new [`CalibrationStage`], but without checking stability.
    #[must_use]
    pub fn ignore_stability<N, R>(map_feedback: &MapFeedback<N, O, R, S, O::Entry>) -> Self
    where
        O::Entry:
            PartialEq + Default + Copy + 'static + Serialize + serde::de::DeserializeOwned + Debug,
        R: Reducer<O::Entry>,
        for<'it> O: AsIter<'it, Item = O::Entry>,
        N: IsNovel<O::Entry>,
    {
        Self {
            map_observer_name: map_feedback.observer_name().to_string(),
            map_name: map_feedback.name().to_string(),
            stage_max: CAL_STAGE_START,
            track_stability: false,
            phantom: PhantomData,
        }
    }
}
