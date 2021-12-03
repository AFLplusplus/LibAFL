//! The calibration stage. The fuzzer measures the average exec time and the bitmap size.

use crate::{
    bolts::current_time,
    corpus::{Corpus, PowerScheduleTestcaseMetaData},
    events::{Event, EventFirer, LogSeverity},
    executors::{Executor, ExitKind, HasObservers},
    feedbacks::{FeedbackStatesTuple, MapFeedbackState},
    fuzzer::Evaluator,
    inputs::Input,
    observers::{MapObserver, ObserversTuple},
    stages::Stage,
    state::{HasCorpus, HasFeedbackStates, HasMetadata},
    Error,
};
use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::{fmt::Debug, marker::PhantomData, time::Duration};
use num_traits::PrimInt;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug)]
pub struct CalibrationStage<C, E, EM, FT, I, O, OT, S, T, Z>
where
    T: PrimInt + Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned + Debug,
    C: Corpus<I>,
    E: Executor<EM, I, S, Z> + HasObservers<I, OT, S>,
    EM: EventFirer<I>,
    FT: FeedbackStatesTuple,
    I: Input,
    O: MapObserver<T>,
    OT: ObserversTuple<I, S>,
    S: HasCorpus<C, I> + HasMetadata,
    Z: Evaluator<E, EM, I, S>,
{
    map_observer_name: String,
    stage_max: usize,
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(C, E, EM, FT, I, O, OT, S, T, Z)>,
}

const CAL_STAGE_START: usize = 4;
const CAL_STAGE_MAX: usize = 16;

impl<C, E, EM, FT, I, O, OT, S, T, Z> Stage<E, EM, S, Z>
    for CalibrationStage<C, E, EM, FT, I, O, OT, S, T, Z>
where
    T: PrimInt + Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned + Debug,
    C: Corpus<I>,
    E: Executor<EM, I, S, Z> + HasObservers<I, OT, S>,
    EM: EventFirer<I>,
    FT: FeedbackStatesTuple,
    I: Input,
    O: MapObserver<T>,
    OT: ObserversTuple<I, S>,
    S: HasCorpus<C, I> + HasMetadata + HasFeedbackStates<FT>,
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
        let _ = executor.run_target(fuzzer, state, mgr, &input)?;
        let mut total_time = current_time() - start;
        let map_first = &executor
            .observers()
            .match_name::<O>(&self.map_observer_name)
            .ok_or_else(|| Error::KeyNotFound("MapObserver not found".to_string()))?
            .map()
            .unwrap()
            .to_vec();

        // Run CAL_STAGE_START - 1 times, increase by 2 for every time a new
        // run is found to be unstable, with CAL_STAGE_MAX total runs.
        let mut i = 1;
        let mut has_errors = false;
        let mut unstable_entries: usize = 0;
        let map_len: usize = map_first.len() as usize;
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
                    mgr.fire(
                        state,
                        Event::Log {
                            severity_level: LogSeverity::Warn,
                            message: "Corpus entry errored on execution!".into(),
                            phantom: PhantomData,
                        },
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
                .map()
                .unwrap()
                .to_vec();

            let history_map = &mut state
                .feedback_states_mut()
                .match_name_mut::<MapFeedbackState<T>>(&self.map_observer_name)
                .unwrap()
                .history_map;

            for j in 0..map_len {
                if map_first[j] != map[j] && history_map[j] != T::max_value() {
                    history_map[j] = T::max_value();
                    unstable_entries += 1;
                };
            }

            i += 1;
        }

        if unstable_entries != 0 {
            #[allow(clippy::cast_precision_loss)]
            mgr.fire(
                state,
                Event::Stability {
                    stability: (map_len - unstable_entries) as f64 / (map_len as f64),
                },
            )?;
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

pub const N_FUZZ_SIZE: usize = 1 << 21;

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

    #[must_use]
    pub fn exec_time(&self) -> Duration {
        self.exec_time
    }

    pub fn set_exec_time(&mut self, time: Duration) {
        self.exec_time = time;
    }

    #[must_use]
    pub fn cycles(&self) -> u64 {
        self.cycles
    }

    pub fn set_cycles(&mut self, val: u64) {
        self.cycles = val;
    }

    #[must_use]
    pub fn bitmap_size(&self) -> u64 {
        self.bitmap_size
    }

    pub fn set_bitmap_size(&mut self, val: u64) {
        self.bitmap_size = val;
    }

    #[must_use]
    pub fn bitmap_entries(&self) -> u64 {
        self.bitmap_entries
    }

    pub fn set_bitmap_entries(&mut self, val: u64) {
        self.bitmap_entries = val;
    }

    #[must_use]
    pub fn queue_cycles(&self) -> u64 {
        self.queue_cycles
    }

    pub fn set_queue_cycles(&mut self, val: u64) {
        self.queue_cycles = val;
    }

    #[must_use]
    pub fn n_fuzz(&self) -> &[u32] {
        &self.n_fuzz
    }

    #[must_use]
    pub fn n_fuzz_mut(&mut self) -> &mut [u32] {
        &mut self.n_fuzz
    }
}

crate::impl_serdeany!(PowerScheduleMetadata);

impl<C, E, EM, FT, I, O, OT, S, T, Z> CalibrationStage<C, E, EM, FT, I, O, OT, S, T, Z>
where
    T: PrimInt + Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned + Debug,
    C: Corpus<I>,
    E: Executor<EM, I, S, Z> + HasObservers<I, OT, S>,
    EM: EventFirer<I>,
    FT: FeedbackStatesTuple,
    I: Input,
    O: MapObserver<T>,
    OT: ObserversTuple<I, S>,
    S: HasCorpus<C, I> + HasMetadata,
    Z: Evaluator<E, EM, I, S>,
{
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
