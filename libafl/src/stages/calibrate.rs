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
    corpus::{Corpus, CorpusId, SchedulerTestcaseMetadata},
    events::{Event, EventFirer, LogSeverity},
    executors::{Executor, ExitKind, HasObservers},
    feedbacks::{map::MapFeedbackMetadata, HasObserverName},
    fuzzer::Evaluator,
    inputs::UsesInput,
    monitors::UserStats,
    observers::{MapObserver, ObserversTuple, UsesObserver},
    schedulers::powersched::SchedulerMetadata,
    stages::Stage,
    state::{
        HasClientPerfMonitor, HasCorpus, HasCurrentStageInfo, HasMetadata, HasNamedMetadata,
        UsesState,
    },
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
pub struct CalibrationStage<O, OT, S>
where
    O: MapObserver,
{
    map_observer_name: String,
    map_name: String,
    stage_max: usize,
    track_stability: bool,
    phantom: PhantomData<(O, OT, S)>,
    iter_limit: usize,
    corpus_idx: Option<CorpusId>,
    unstable_entries: Vec<usize>,
    map_first: Vec<O::Entry>,
    map_len: usize,
    start: Duration,
    total_time: Duration,
    has_errors: bool,
}

const CAL_STAGE_START: usize = 4; // AFL++'s CAL_CYCLES_FAST + 1
const CAL_STAGE_MAX: usize = 8; // AFL++'s CAL_CYCLES + 1

impl<O, OT, S> UsesState for CalibrationStage<O, OT, S>
where
    S: UsesInput,
    O: MapObserver,
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
    E::State:
        HasCorpus + HasMetadata + HasCurrentStageInfo + HasClientPerfMonitor + HasNamedMetadata,
    Z: Evaluator<E, EM, State = E::State>,
{
    type Context = Self::Input;

    #[inline]
    fn init(
        &mut self,
        _fuzzer: &mut Z,
        _executor: &mut E,
        state: &mut Self::State,
        _manager: &mut EM,
        corpus_idx: CorpusId,
    ) -> Result<Option<E::Input>, Error> {
        // Run this stage only once for each corpus entry and only if we haven't already inspected it
        {
            let corpus = state.corpus().get(corpus_idx)?.borrow();
            // println!("calibration; corpus.scheduled_count() : {}", corpus.scheduled_count());

            if corpus.scheduled_count() > 0 {
                return Ok(None);
            }
        }
        self.iter_limit = self.stage_max;
        self.corpus_idx = Some(corpus_idx);

        let input = state.corpus().cloned_input_for_id(corpus_idx)?;

        Ok(Some(input))
    }

    #[inline]
    fn limit(&self) -> Result<usize, Error> {
        Ok(self.iter_limit)
    }

    #[inline]
    fn pre_exec(
        &mut self,
        _fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Self::State,
        _manager: &mut EM,
        input: E::Input,
        _index: usize,
    ) -> Result<(E::Input, bool), Error> {
        log::error!("calibrating index: {}", _index);
        executor.observers_mut().pre_exec_all(state, &input)?;

        self.start = current_time();
        Ok((input, true))
    }

    #[inline]
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Self::State,
        manager: &mut EM,
        input: E::Input,
        _index: usize,
    ) -> Result<(E::Input, ExitKind), Error> {
        executor.pre_exec(fuzzer, state, manager, &input)?;
        let exit_kind = executor.run_target(fuzzer, state, manager, &input)?;
        executor.post_exec(fuzzer, state, manager, &input)?;

        Ok((input, exit_kind))
    }

    #[inline]
    fn post_exec(
        &mut self,
        _fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Self::State,
        manager: &mut EM,
        input: E::Input,
        index: usize,
        exit_kind: ExitKind,
    ) -> Result<(E::Input, Option<usize>), Error> {
        log::error!(
            "calibrating postexec index: {}",
            core::any::type_name::<E>()
        );
        if index == 0 {
            self.total_time = if exit_kind == ExitKind::Ok {
                current_time() - self.start
            } else {
                manager.log(
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

            self.map_first = executor
                .observers()
                .match_name::<O>(&self.map_observer_name)
                .ok_or_else(|| Error::key_not_found("MapObserver not found".to_string()))?
                .to_vec();
            self.map_len = self.map_first.len();
        } else {
            if exit_kind != ExitKind::Ok {
                if !self.has_errors {
                    manager.log(
                        state,
                        LogSeverity::Warn,
                        "Corpus entry errored on execution!".into(),
                    )?;

                    self.has_errors = true;
                }

                if self.iter_limit < CAL_STAGE_MAX {
                    self.iter_limit += 2;
                };
            };

            self.total_time += current_time() - self.start;

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
                    .named_metadata_map_mut()
                    .get_mut::<MapFeedbackMetadata<O::Entry>>(&self.map_name)
                    .unwrap()
                    .history_map;

                if history_map.len() < self.map_len {
                    history_map.resize(self.map_len, O::Entry::default());
                }

                for (idx, (first, (cur, history))) in self
                    .map_first
                    .iter()
                    .zip(map.iter().zip(history_map.iter_mut()))
                    .enumerate()
                {
                    if *first != *cur && *history != O::Entry::max_value() {
                        *history = O::Entry::max_value();
                        self.unstable_entries.push(idx);
                    };
                }

                if !self.unstable_entries.is_empty() && self.iter_limit < CAL_STAGE_MAX {
                    self.iter_limit += 2;
                }
            }
        }

        Ok((input, None))
    }

    #[inline]
    fn deinit(
        &mut self,
        _fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Self::State,
        manager: &mut EM,
    ) -> Result<(), Error> {
        if !self.unstable_entries.is_empty() {
            // If we see new stable entries executing this new corpus entries, then merge with the existing one
            if state.has_metadata::<UnstableEntriesMetadata>() {
                let existing = state
                    .metadata_map_mut()
                    .get_mut::<UnstableEntriesMetadata>()
                    .unwrap();
                for item in &self.unstable_entries {
                    existing.unstable_entries.insert(*item); // Insert newly found items
                }
                existing.map_len = self.map_len;
            } else {
                state.add_metadata::<UnstableEntriesMetadata>(UnstableEntriesMetadata::new(
                    HashSet::from_iter(self.unstable_entries.clone()),
                    self.map_len,
                ));
            }
        };

        // If weighted scheduler or powerscheduler is used, update it
        if state.has_metadata::<SchedulerMetadata>() {
            let map = executor
                .observers()
                .match_name::<O>(&self.map_observer_name)
                .ok_or_else(|| Error::key_not_found("MapObserver not found".to_string()))?;

            let bitmap_size = map.count_bytes();

            let psmeta = state
                .metadata_map_mut()
                .get_mut::<SchedulerMetadata>()
                .unwrap();
            let handicap = psmeta.queue_cycles();

            psmeta.set_exec_time(psmeta.exec_time() + self.total_time);
            psmeta.set_cycles(psmeta.cycles() + (self.iter_limit as u64));
            psmeta.set_bitmap_size(psmeta.bitmap_size() + bitmap_size);
            psmeta.set_bitmap_size_log(psmeta.bitmap_size_log() + libm::log2(bitmap_size as f64));
            psmeta.set_bitmap_entries(psmeta.bitmap_entries() + 1);

            let mut testcase = state.corpus().get(self.corpus_idx.unwrap())?.borrow_mut();

            testcase.set_exec_time(self.total_time / (self.iter_limit as u32));
            // log::trace!("time: {:#?}", testcase.exec_time());

            // If the testcase doesn't have its own `SchedulerTestcaseMetadata`, create it.
            let data = if let Ok(metadata) = testcase.metadata_mut::<SchedulerTestcaseMetadata>() {
                metadata
            } else {
                let depth = if let Some(parent_id) = testcase.parent_id() {
                    if let Some(parent_metadata) = (*state.corpus().get(parent_id)?)
                        .borrow()
                        .metadata_map()
                        .get::<SchedulerTestcaseMetadata>()
                    {
                        parent_metadata.depth() + 1
                    } else {
                        0
                    }
                } else {
                    0
                };
                testcase.add_metadata(SchedulerTestcaseMetadata::new(depth));
                testcase
                    .metadata_mut::<SchedulerTestcaseMetadata>()
                    .unwrap()
            };

            data.set_cycle_and_time((self.total_time, self.iter_limit));
            data.set_bitmap_size(bitmap_size);
            data.set_handicap(handicap);
        }

        // Send the stability event to the broker
        if let Some(meta) = state.metadata_map().get::<UnstableEntriesMetadata>() {
            let unstable_entries = meta.unstable_entries().len();
            let map_len = meta.map_len();
            manager.fire(
                state,
                Event::UpdateUserStats {
                    name: "stability".to_string(),
                    value: UserStats::Ratio((map_len - unstable_entries) as u64, map_len as u64),
                    phantom: PhantomData,
                },
            )?;
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
    pub fn new<F>(map_feedback: &F) -> Self
    where
        F: HasObserverName + Named + UsesObserver<S, Observer = O>,
        for<'it> O: AsIter<'it, Item = O::Entry>,
    {
        Self {
            map_observer_name: map_feedback.observer_name().to_string(),
            map_name: map_feedback.name().to_string(),
            stage_max: CAL_STAGE_START,
            track_stability: true,
            phantom: PhantomData,
            iter_limit: 0,
            corpus_idx: None,
            unstable_entries: vec![],
            map_first: vec![],
            map_len: 0,
            start: Duration::from_secs(0),
            total_time: Duration::from_secs(0),
            has_errors: false,
        }
    }

    /// Create a new [`CalibrationStage`], but without checking stability.
    #[must_use]
    pub fn ignore_stability<F>(map_feedback: &F) -> Self
    where
        F: HasObserverName + Named + UsesObserver<S, Observer = O>,
        for<'it> O: AsIter<'it, Item = O::Entry>,
    {
        Self {
            map_observer_name: map_feedback.observer_name().to_string(),
            map_name: map_feedback.name().to_string(),
            stage_max: CAL_STAGE_START,
            track_stability: false,
            phantom: PhantomData,
            iter_limit: 0,
            corpus_idx: None,
            unstable_entries: vec![],
            map_first: vec![],
            map_len: 0,
            start: Duration::from_secs(0),
            total_time: Duration::from_secs(0),
            has_errors: false,
        }
    }
}
