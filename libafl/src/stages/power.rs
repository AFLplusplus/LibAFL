use core::marker::PhantomData;

use crate::{
    corpus::{Corpus, PowerScheduleData},
    fuzzer::Evaluator,
    inputs::Input,
    mutators::Mutator,
    stages::{CalibrateData, MutationalStage, Stage},
    state::{HasClientPerfStats, HasCorpus, HasMetadata},
    Error,
};

#[derive(Clone, Debug)]
pub enum PowerSchedule {
    EXPLORE,
    FAST,
    COE,
    LIN,
    QUAD,
    EXPLOIT,
}

/// The mutational stage using power schedules
#[derive(Clone, Debug)]
pub struct PowerMutationalStage<C, E, EM, I, M, S, Z>
where
    M: Mutator<I, S>,
    I: Input,
    S: HasClientPerfStats + HasCorpus<C, I> + HasMetadata,
    C: Corpus<I>,
    Z: Evaluator<E, EM, I, S>,
{
    mutator: M,
    strat: PowerSchedule,
    phantom: PhantomData<(C, E, EM, I, S, Z)>,
}

impl<C, E, EM, I, M, S, Z> MutationalStage<C, E, EM, I, M, S, Z>
    for PowerMutationalStage<C, E, EM, I, M, S, Z>
where
    C: Corpus<I>,
    M: Mutator<I, S>,
    I: Input,
    S: HasClientPerfStats + HasCorpus<C, I> + HasMetadata,
    Z: Evaluator<E, EM, I, S>,
{
    /// The mutator, added to this stage
    #[inline]
    fn mutator(&self) -> &M {
        &self.mutator
    }

    /// The list of mutators, added to this stage (as mutable ref)
    #[inline]
    fn mutator_mut(&mut self) -> &mut M {
        &mut self.mutator
    }

    /// Gets the number of iterations as a random number
    fn iterations(&self, state: &mut S, corpus_idx: usize) -> Result<usize, Error> {
        let mut testcase = state.corpus().get(corpus_idx).unwrap().borrow_mut();
        let psdata = testcase
            .metadata_mut()
            .get_mut::<PowerScheduleData>()
            .unwrap();
        let caldata = state.metadata().get::<CalibrateData>().unwrap();
        // 1 + state.rand_mut().below(DEFAULT_MUTATIONAL_MAX_ITERATIONS) as usize
        Ok(self.calculate_score(psdata, caldata))
    }
}

impl<C, E, EM, I, M, S, Z> Stage<E, EM, S, Z> for PowerMutationalStage<C, E, EM, I, M, S, Z>
where
    C: Corpus<I>,
    M: Mutator<I, S>,
    I: Input,
    S: HasClientPerfStats + HasCorpus<C, I> + HasMetadata,
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
        let ret = self.perform_mutational(fuzzer, executor, state, manager, corpus_idx);
        ret
    }
}

impl<C, E, EM, I, M, S, Z> PowerMutationalStage<C, E, EM, I, M, S, Z>
where
    M: Mutator<I, S>,
    I: Input,
    S: HasClientPerfStats + HasCorpus<C, I> + HasMetadata,
    C: Corpus<I>,
    Z: Evaluator<E, EM, I, S>,
{
    /// Creates a new default mutational stage
    pub fn new(mutator: M, strat: PowerSchedule) -> Self {
        Self {
            mutator: mutator,
            strat: strat,
            phantom: PhantomData,
        }
    }

    #[inline]
    fn calculate_score(&self, psdata: &mut PowerScheduleData, caldata: &CalibrateData) -> usize {
        let mut perf_score = 100.0;
        let avg_exec_us = caldata.total_cal_us / (caldata.total_cal_cycles as u128);
        let avg_bitmap_size = caldata.total_bitmap_size / caldata.total_bitmap_size;

        let q_exec_us = psdata.exec_us as f64;
        if q_exec_us * 0.1 > avg_exec_us as f64 {
            perf_score = 10.0;
        } else if q_exec_us * 0.2 > avg_exec_us as f64 {
            perf_score = 25.0;
        } else if q_exec_us * 0.5 > avg_exec_us as f64 {
            perf_score = 50.0;
        } else if q_exec_us * 0.75 > avg_exec_us as f64 {
            perf_score = 75.0;
        } else if q_exec_us * 4.0 < avg_exec_us as f64 {
            perf_score = 300.0;
        } else if q_exec_us * 3.0 < avg_exec_us as f64 {
            perf_score = 200.0;
        } else if q_exec_us * 2.0 < avg_exec_us as f64 {
            perf_score = 150.0;
        }

        let q_bitmap_size = psdata.bitmap_size as f64;
        if q_bitmap_size * 0.3 > avg_bitmap_size as f64 {
            perf_score *= 3.0;
        } else if q_bitmap_size * 0.5 > avg_bitmap_size as f64 {
            perf_score *= 2.0;
        } else if q_bitmap_size * 0.75 > avg_bitmap_size as f64 {
            perf_score *= 1.5;
        } else if q_bitmap_size * 3.0 < avg_bitmap_size as f64 {
            perf_score *= 0.25;
        } else if q_bitmap_size * 2.0 < avg_bitmap_size as f64 {
            perf_score *= 0.5;
        } else if q_bitmap_size * 1.5 < avg_bitmap_size as f64 {
            perf_score *= 0.75;
        }

        if psdata.handicap >= 4 {
            perf_score *= 4.0;
            psdata.handicap -= 4;
        } else if psdata.handicap > 0 {
            perf_score *= 2.0;
            psdata.handicap -= 1;
        }

        if psdata.depth >= 4 && psdata.depth < 8 {
            perf_score *= 2.0;
        } else if psdata.depth >= 8 && psdata.depth < 14 {
            perf_score *= 3.0;
        } else if psdata.depth >= 14 && psdata.depth < 25 {
            perf_score *= 4.0;
        } else if psdata.depth >= 25 {
            perf_score *= 5.0;
        }

        let mut factor: f64 = 1.0;
        match &self.strat {
            PowerSchedule::EXPLORE => {
                // Nothing happens in EXPLORE
            }
            _ => {}
        }

        perf_score as usize
    }
}
