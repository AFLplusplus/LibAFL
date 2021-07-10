use alloc::string::String;
use core::marker::PhantomData;

use crate::{
    bolts::current_time,
    corpus::{Corpus, PowerScheduleTestData},
    executors::{Executor, HasObservers},
    fuzzer::Evaluator,
    inputs::Input,
    observers::{MapObserver, ObserversTuple},
    stages::Stage,
    state::{HasCorpus, HasMetadata},
    Error,
};
use serde::{Deserialize, Serialize};

/// The default mutational stage
#[derive(Clone, Debug)]
pub struct CalibrateStage<C, E, EM, I, O, OT, S, Z>
where
    C: Corpus<I>,
    E: Executor<EM, I, S, Z> + HasObservers<I, OT, S>,
    I: Input,
    O: MapObserver<usize>,
    OT: ObserversTuple<I, S>,
    S: HasCorpus<C, I> + HasMetadata,
    Z: Evaluator<E, EM, I, S>,
{
    map_observer_name: String,
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(C, E, EM, I, O, OT, S, Z)>,
}

// The number of times we run the program in the calibration stage
const CAL_STAGE_MAX: usize = 8;

impl<C, E, EM, I, O, OT, S, Z> Stage<E, EM, S, Z> for CalibrateStage<C, E, EM, I, O, OT, S, Z>
where
    C: Corpus<I>,
    E: Executor<EM, I, S, Z> + HasObservers<I, OT, S>,
    I: Input,
    O: MapObserver<usize>,
    OT: ObserversTuple<I, S>,
    S: HasCorpus<C, I> + HasMetadata,
    Z: Evaluator<E, EM, I, S>,
{
    #[inline]
    #[allow(clippy::let_and_return)]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error> {
        let iter = CAL_STAGE_MAX;
        let handicap = state
            .metadata()
            .get::<PowerScheduleGlobalData>()
            .unwrap()
            .queue_cycles;

        // Timer start
        let start = current_time();

        for _i in 0..iter {
            let input = state
                .corpus()
                .get(corpus_idx)?
                .borrow_mut()
                .load_input()?
                .clone();
            let (_, _) = fuzzer.evaluate_input(state, executor, manager, input)?;
        }
        // Timer end
        let end = current_time();

        let map = executor
            .observers()
            .match_name::<O>(&self.map_observer_name)
            .unwrap();

        let bitmap_size = map.count_bytes();

        let calstat = state
            .metadata_mut()
            .get_mut::<PowerScheduleGlobalData>()
            .unwrap();

        calstat.total_cal_us += (end - start).as_millis();
        calstat.total_cal_cycles += iter as u64;
        calstat.total_bitmap_size += bitmap_size as u64;
        calstat.total_bitmap_entries += 1;

        let mut testcase = state.corpus().get(corpus_idx)?.borrow_mut();
        let data = testcase
            .metadata_mut()
            .get_mut::<PowerScheduleTestData>()
            .unwrap();
        data.exec_us += ((end - start) / (iter as u32)).as_millis();

        data.bitmap_size = bitmap_size as u64;
        data.handicap = handicap as u64;

        Ok(())
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PowerScheduleGlobalData {
    pub total_cal_us: u128,
    pub total_cal_cycles: u64,
    pub total_bitmap_size: u64,
    pub total_bitmap_entries: u64,
    pub queue_cycles: usize,
}

impl PowerScheduleGlobalData {
    pub fn new() -> Self {
        Self {
            total_cal_us: 0,
            total_cal_cycles: 0,
            total_bitmap_size: 0,
            total_bitmap_entries: 0,
            queue_cycles: 0,
        }
    }
}

crate::impl_serdeany!(PowerScheduleGlobalData);

impl<C, E, I, EM, O, OT, S, Z> CalibrateStage<C, E, EM, I, O, OT, S, Z>
where
    C: Corpus<I>,
    E: Executor<EM, I, S, Z> + HasObservers<I, OT, S>,
    I: Input,
    O: MapObserver<usize>,
    OT: ObserversTuple<I, S>,
    S: HasCorpus<C, I> + HasMetadata,
    Z: Evaluator<E, EM, I, S>,
{
    pub fn new(state: &mut S, map_observer_name: String) -> Self {
        state.add_metadata::<PowerScheduleGlobalData>(PowerScheduleGlobalData::new());
        Self {
            map_observer_name: map_observer_name,
            phantom: PhantomData,
        }
    }
}
