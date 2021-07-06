use core::marker::PhantomData;

use crate::{
    bolts::current_time,
    corpus::{Corpus, PowerScheduleData}, 
    fuzzer::Evaluator,
    inputs::Input,
    executors::Executor,
    stages::Stage,
    state::{HasCorpus, HasMetadata},
    Error,
};


/// The default mutational stage
#[derive(Clone, Debug)]
pub struct CalibrateStage<C, E, EM, I, S, Z>
where
    C: Corpus<I>,
    E: Executor<EM, I, S, Z>,
    I: Input,
    S: HasCorpus<C, I>,
    Z: Evaluator<E, EM, I, S>,
{
    total_exec_us: f64,
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(C, E, EM, I, S, Z)>,
}

// The number of times we run the program in the calibration stage
const CAL_STAGE_MAX : usize = 8;

impl<C, E, EM, I, S, Z> Stage<E, EM, S, Z> for CalibrateStage<C, E, EM, I, S, Z>
where
    C: Corpus<I>,
    E: Executor<EM, I, S, Z>,
    I: Input,
    S: HasCorpus<C, I>,
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
            let input = state.corpus().get(corpus_idx)?.borrow_mut().load_input()?.clone();
            let (_, _) = fuzzer.evaluate_input(state, executor, manager, input)?;
        }
        // Timer end
        let end = current_time();


        let mut testcase = state.corpus().get(corpus_idx)?.borrow_mut();
        let mut data = testcase.metadata_mut().get_mut::<PowerScheduleData>().unwrap();
        data.exec_us += (end - start) / (iter as u32);
        data.bitmap_size = 0; // TODO
        data.handicap = 0; // TODO

        Ok(())
    }
}

impl<C, E, I, EM, S, Z> CalibrateStage<C, E, EM, I, S, Z>
where
    C: Corpus<I>,
    E: Executor<EM, I, S, Z>,
    I: Input,
    S: HasCorpus<C, I>,
    Z: Evaluator<E, EM, I, S>,
{
    #[inline]
    fn cal_stages(&self) -> usize{
        CAL_STAGE_MAX
    }

    pub fn new() -> Self {
        Self {
            total_exec_us: 0.0,
            phantom: PhantomData,
        }
    }
}
