//! The calibration stage. The fuzzer measures the average exec time and the bitmap size.

use crate::{
    bolts::current_time,
    corpus::{Corpus, PowerScheduleTestcaseMetaData},
    events::{EventFirer, LogSeverity},
    executors::{Executor, ExitKind, HasObservers},
    feedbacks::{FeedbackState, MapFeedbackState},
    fuzzer::Evaluator,
    inputs::Input,
    observers::{MapObserver, ObserversTuple},
    stages::Stage,
    state::{HasClientPerfMonitor, HasCorpus, HasFeedbackObjectiveStates, HasMetadata},
    Error,
};
use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::{fmt::Debug, marker::PhantomData, time::Duration};
use num_traits::Bounded;
use serde::{Deserialize, Serialize};

/// The calibration stage will measure the average exec time and the target's stability for this input.
#[derive(Clone, Debug)]
pub struct CalibrationStage<I, O, OT, S>
where
    I: Input,
    O: MapObserver,
    OT: ObserversTuple<I, S>,
    S: HasCorpus<I> + HasMetadata,
{
    map_observer_name: String,
    stage_max: usize,
    phantom: PhantomData<(I, O, OT, S)>,
}

const CAL_STAGE_START: usize = 4;
const CAL_STAGE_MAX: usize = 16;

impl<E, EM, I, O, OT, S, Z> Stage<E, EM, S, Z> for CalibrationStage<I, O, OT, S>
where
    E: Executor<EM, I, S, Z> + HasObservers<I, OT, S>,
    EM: EventFirer<I>,
    I: Input,
    O: MapObserver,
    for<'de> <O as MapObserver>::Entry: Serialize + Deserialize<'de> + 'static,
    OT: ObserversTuple<I, S>,
    S: HasCorpus<I> + HasMetadata + HasFeedbackObjectiveStates + HasClientPerfMonitor,
    Z: Evaluator<E, EM, I, S>,
{
    #[inline]
    #[allow(clippy::let_and_return, clippy::too_many_lines)]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        mgr: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error> {
        let mut iter = self.stage_max;
        let handicap = state
            .metadata()
            .get::<PowerScheduleMetadata>()
            .ok_or_else(|| Error::KeyNotFound("PowerScheduleMetadata not found".to_string()))?
            .queue_cycles;
        let input = state
            .corpus()
            .get(corpus_idx)?
            .borrow_mut()
            .load_input()?
            .clone();

        // Run once to get the initial calibration map
        executor.observers_mut().pre_exec_all(state, &input)?;
        let mut start = current_time();

        let mut total_time = if executor.run_target(fuzzer, state, mgr, &input)? == ExitKind::Ok {
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

        let map_first = &executor
            .observers()
            .match_name::<O>(&self.map_observer_name)
            .ok_or_else(|| Error::KeyNotFound("MapObserver not found".to_string()))?
            .to_vec();

        // Run CAL_STAGE_START - 1 times, increase by 2 for every time a new
        // run is found to be unstable, with CAL_STAGE_MAX total runs.
        let mut i = 1;
        let mut has_errors = false;
        let mut unstable_entries: usize = 0;
        let map_len: usize = map_first.len();
        while i < iter {
            let input = state
                .corpus()
                .get(corpus_idx)?
                .borrow_mut()
                .load_input()?
                .clone();

            executor.observers_mut().pre_exec_all(state, &input)?;
            start = current_time();

            if executor.run_target(fuzzer, state, mgr, &input)? != ExitKind::Ok {
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

            let map = &executor
                .observers()
                .match_name::<O>(&self.map_observer_name)
                .ok_or_else(|| Error::KeyNotFound("MapObserver not found".to_string()))?
                .to_vec();

            let feedback_objective_states = state.feedback_objective_states();
            let mut feedback_objective_states = (*feedback_objective_states).borrow_mut();
            let feedback_state = &mut feedback_objective_states.0;

            let history_map = &mut feedback_state
                .match_name_mut::<MapFeedbackState<O::Entry>>(&self.map_observer_name)
                .unwrap()
                .history_map;

            for j in 0..map_len {
                if map_first[j] != map[j] && history_map[j] != O::Entry::max_value() {
                    history_map[j] = O::Entry::max_value();
                    unstable_entries += 1;
                };
            }

            i += 1;
        }

        #[allow(clippy::cast_precision_loss)]
        if unstable_entries != 0 {
            *state.stability_mut() = Some((map_len - unstable_entries) as f32 / (map_len as f32));

            if iter < CAL_STAGE_MAX {
                iter += 2;
            }
        };

        let psmeta = state
            .metadata_mut()
            .get_mut::<PowerScheduleMetadata>()
            .ok_or_else(|| Error::KeyNotFound("PowerScheduleMetadata not found".to_string()))?;

        let map = executor
            .observers()
            .match_name::<O>(&self.map_observer_name)
            .ok_or_else(|| Error::KeyNotFound("MapObserver not found".to_string()))?;

        let bitmap_size = map.count_bytes();

        psmeta.set_exec_time(psmeta.exec_time() + total_time);
        psmeta.set_cycles(psmeta.cycles() + (iter as u64));
        psmeta.set_bitmap_size(psmeta.bitmap_size() + bitmap_size);
        psmeta.set_bitmap_entries(psmeta.bitmap_entries() + 1);

        let mut testcase = state.corpus().get(corpus_idx)?.borrow_mut();

        testcase.set_exec_time(total_time / (iter as u32));
        // println!("time: {:#?}", testcase.exec_time());
        let data = testcase
            .metadata_mut()
            .get_mut::<PowerScheduleTestcaseMetaData>()
            .ok_or_else(|| Error::KeyNotFound("PowerScheduleTestData not found".to_string()))?;

        data.set_bitmap_size(bitmap_size);
        data.set_handicap(handicap);
        data.set_fuzz_level(data.fuzz_level() + 1);
        // println!("data: {:#?}", data);

        Ok(())
    }
}

/// The n fuzz size
pub const N_FUZZ_SIZE: usize = 1 << 21;

/// The metadata used for power schedules
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PowerScheduleMetadata {
    /// Measured exec time during calibration
    exec_time: Duration,
    /// Calibration cycles
    cycles: u64,
    /// Size of the observer map
    bitmap_size: u64,
    /// Number of filled map entries
    bitmap_entries: u64,
    /// Queue cycles
    queue_cycles: u64,
    /// The vector to contain the frequency of each execution path.
    n_fuzz: Vec<u32>,
}

/// The metadata for runs in the calibration stage.
impl PowerScheduleMetadata {
    /// Creates a new [`struct@PowerScheduleMetadata`]
    #[must_use]
    pub fn new() -> Self {
        Self {
            exec_time: Duration::from_millis(0),
            cycles: 0,
            bitmap_size: 0,
            bitmap_entries: 0,
            queue_cycles: 0,
            n_fuzz: vec![0; N_FUZZ_SIZE],
        }
    }

    /// The measured exec time during calibration
    #[must_use]
    pub fn exec_time(&self) -> Duration {
        self.exec_time
    }

    /// Set the measured exec
    pub fn set_exec_time(&mut self, time: Duration) {
        self.exec_time = time;
    }

    /// The cycles
    #[must_use]
    pub fn cycles(&self) -> u64 {
        self.cycles
    }

    /// Sets the cycles
    pub fn set_cycles(&mut self, val: u64) {
        self.cycles = val;
    }

    /// The bitmap size
    #[must_use]
    pub fn bitmap_size(&self) -> u64 {
        self.bitmap_size
    }

    /// Sets the bitmap size
    pub fn set_bitmap_size(&mut self, val: u64) {
        self.bitmap_size = val;
    }

    /// The number of filled map entries
    #[must_use]
    pub fn bitmap_entries(&self) -> u64 {
        self.bitmap_entries
    }

    /// Sets the number of filled map entries
    pub fn set_bitmap_entries(&mut self, val: u64) {
        self.bitmap_entries = val;
    }

    /// The amount of queue cycles
    #[must_use]
    pub fn queue_cycles(&self) -> u64 {
        self.queue_cycles
    }

    /// Sets the amount of queue cycles
    pub fn set_queue_cycles(&mut self, val: u64) {
        self.queue_cycles = val;
    }

    /// Gets the `n_fuzz`.
    #[must_use]
    pub fn n_fuzz(&self) -> &[u32] {
        &self.n_fuzz
    }

    /// Sets the `n_fuzz`.
    #[must_use]
    pub fn n_fuzz_mut(&mut self) -> &mut [u32] {
        &mut self.n_fuzz
    }
}

crate::impl_serdeany!(PowerScheduleMetadata);

impl<I, O, OT, S> CalibrationStage<I, O, OT, S>
where
    I: Input,
    O: MapObserver,
    OT: ObserversTuple<I, S>,
    S: HasCorpus<I> + HasMetadata,
{
    /// Create a new [`CalibrationStage`].
    pub fn new(state: &mut S, map_observer_name: &O) -> Self {
        state.add_metadata::<PowerScheduleMetadata>(PowerScheduleMetadata::new());
        Self {
            map_observer_name: map_observer_name.name().to_string(),
            stage_max: CAL_STAGE_START,
            phantom: PhantomData,
        }
    }
}

impl Default for PowerScheduleMetadata {
    fn default() -> Self {
        Self::new()
    }
}
