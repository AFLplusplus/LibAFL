//! The calibration stage. The fuzzer measures the average exec time and the bitmap size.

use crate::{
    bolts::current_time,
    bolts::tuples::MatchName,
    corpus::{Corpus, PowerScheduleTestcaseMetaData},
    events::{EventFirer, LogSeverity},
    executors::{Executor, ExitKind, HasObservers},
    feedbacks::MapFeedbackState,
    fuzzer::Evaluator,
    inputs::Input,
    observers::{MapObserver, ObserversTuple},
    schedulers::powersched::PowerScheduleMetadata,
    stages::Stage,
    state::{HasClientPerfMonitor, HasCorpus, HasFeedbackStates, HasMetadata},
    Error,
};
use alloc::string::{String, ToString};
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
    S: HasCorpus<I> + HasMetadata + HasFeedbackStates + HasClientPerfMonitor,
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

            let history_map = &mut state
                .feedback_states_mut()
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

        // If power schedule is used, update it
        let use_powerschedule = state.has_metadata::<PowerScheduleMetadata>()
            && state
                .corpus()
                .get(corpus_idx)?
                .borrow()
                .has_metadata::<PowerScheduleTestcaseMetaData>();

        if use_powerschedule {
            let map = executor
                .observers()
                .match_name::<O>(&self.map_observer_name)
                .ok_or_else(|| Error::KeyNotFound("MapObserver not found".to_string()))?;

            let bitmap_size = map.count_bytes();

            let psmeta = state
                .metadata_mut()
                .get_mut::<PowerScheduleMetadata>()
                .unwrap();
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
                .get_mut::<PowerScheduleTestcaseMetaData>()
                .ok_or_else(|| Error::KeyNotFound("PowerScheduleTestData not found".to_string()))?;

            data.set_bitmap_size(bitmap_size);
            data.set_handicap(handicap);
        }

        Ok(())
    }
}

impl<I, O, OT, S> CalibrationStage<I, O, OT, S>
where
    I: Input,
    O: MapObserver,
    OT: ObserversTuple<I, S>,
    S: HasCorpus<I> + HasMetadata,
{
    /// Create a new [`CalibrationStage`].
    pub fn new(map_observer_name: &O) -> Self {
        Self {
            map_observer_name: map_observer_name.name().to_string(),
            stage_max: CAL_STAGE_START,
            phantom: PhantomData,
        }
    }
}
