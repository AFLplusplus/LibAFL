use core::marker::PhantomData;
use alloc::string::String;


use crate::{
    bolts::current_time,
    corpus::{Corpus, PowerScheduleData},
    executors::{Executor, HasObservers},
    fuzzer::Evaluator,
    inputs::Input,
    observers::ObserversTuple,
    stages::Stage,
    state::{HasCorpus, HasMetadata},
    Error,
};
use serde::{Deserialize, Serialize};

/// The default mutational stage
#[derive(Clone, Debug)]
pub struct CalibrateStage<C, E, EM, I, OT, S, Z>
where
    C: Corpus<I>,
    E: Executor<EM, I, S, Z> + HasObservers<I, OT, S>,
    I: Input,
    OT: ObserversTuple<I, S>,
    S: HasCorpus<C, I> + HasMetadata,
    Z: Evaluator<E, EM, I, S>,
{
    map_observer_name: String,
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(C, E, EM, I, OT, S, Z)>,
}

// The number of times we run the program in the calibration stage
const CAL_STAGE_MAX: usize = 8;

impl<C, E, EM, I, OT, S, Z> Stage<E, EM, S, Z> for CalibrateStage<C, E, EM, I, OT, S, Z>
where
    C: Corpus<I>,
    E: Executor<EM, I, S, Z> + HasObservers<I, OT, S>,
    I: Input,
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
        let iter = self.cal_stages();

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
        let bitmap_size;
        {
            let mut testcase = state.corpus().get(corpus_idx)?.borrow_mut();
            let mut data = testcase
                .metadata_mut()
                .get_mut::<PowerScheduleData>()
                .unwrap();
            data.exec_us += ((end - start) / (iter as u32)).as_millis();
            //let bitmap_size = executor.observers().match_name::<MapObserver<usize>>(self.map_observer_name).unwrap();
            bitmap_size = 1;
            data.bitmap_size = bitmap_size;
            data.handicap = 0; // TODO
        }

        let calstat = state.metadata_mut().get_mut::<CalibrateData>().unwrap();

        calstat.total_cal_us += (end - start).as_millis();
        calstat.total_cal_cycles += iter as u64;
        calstat.total_bitmap_size += bitmap_size;
        calstat.total_bitmap_entries += 1;

        Ok(())
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CalibrateData {
    pub total_cal_us: u128,
    pub total_cal_cycles: u64,
    pub total_bitmap_size: u64,
    total_bitmap_entries: u64,
}

impl CalibrateData {
    pub fn new() -> Self {
        Self {
            total_cal_us: 0,
            total_cal_cycles: 0,
            total_bitmap_size: 0,
            total_bitmap_entries: 0,
        }
    }
}

crate::impl_serdeany!(CalibrateData);

impl<C, E, I, EM, OT, S, Z> CalibrateStage<C, E, EM, I, OT, S, Z>
where
    C: Corpus<I>,
    E: Executor<EM, I, S, Z> + HasObservers<I, OT, S>,
    I: Input,
    OT: ObserversTuple<I, S>,
    S: HasCorpus<C, I> + HasMetadata,
    Z: Evaluator<E, EM, I, S>,
{
    #[inline]
    fn cal_stages(&self) -> usize {
        CAL_STAGE_MAX
    }

    pub fn new(state: &mut S, map_observer_name: String) -> Self {
        state.add_metadata::<CalibrateData>(CalibrateData::new());
        Self {
            map_observer_name: map_observer_name,
            phantom: PhantomData,
        }
    }
}
