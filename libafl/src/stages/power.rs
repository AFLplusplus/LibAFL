use alloc::{string::{String, ToString}, vec::Vec};
use core::marker::PhantomData;
use num::Integer;

use crate::{
    corpus::{Corpus, PowerScheduleTestData},
    executors::{Executor, HasObservers},
    fuzzer::Evaluator,
    inputs::Input,
    mutators::Mutator,
    observers::{MapObserver, ObserversTuple},
    stages::{MutationalStage, PowerScheduleStats, Stage},
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

const POWER_BETA: f64 = 1.0;
const MAX_FACTOR: f64 = POWER_BETA * 32.0;
const N_FUZZ_SIZE: usize = 1 << 21;
const HAVOC_MAX_MULT: f64 = 64.0;

/// The mutational stage using power schedules
#[derive(Clone, Debug)]
pub struct PowerMutationalStage<C, E, EM, I, M, O, OT, S, T, Z>
where
    T: Integer + Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
    C: Corpus<I>,
    E: Executor<EM, I, S, Z> + HasObservers<I, OT, S>,
    I: Input,
    M: Mutator<I, S>,
    O: MapObserver<T>,
    OT: ObserversTuple<I, S>,
    S: HasClientPerfStats + HasCorpus<C, I> + HasMetadata,
    Z: Evaluator<E, EM, I, S>,
{
    map_observer_name: String,
    mutator: M,
    n_fuzz: Vec<u32>,
    strat: PowerSchedule,
    phantom: PhantomData<(C, E, EM, I, O, OT, S, T, Z)>,
}

impl<C, E, EM, I, M, O, OT, S, T, Z> MutationalStage<C, E, EM, I, M, S, Z>
    for PowerMutationalStage<C, E, EM, I, M, O, OT, S, T, Z>
where
    T: Integer + Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
    C: Corpus<I>,
    E: Executor<EM, I, S, Z> + HasObservers<I, OT, S>,
    I: Input,
    M: Mutator<I, S>,
    O: MapObserver<T>,
    OT: ObserversTuple<I, S>,
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
        let testcasedata = testcase
            .metadata_mut()
            .get_mut::<PowerScheduleTestData>()
            .unwrap();
        let statsdata = state.metadata().get::<PowerScheduleStats>().unwrap();

        let mut fuzz_mu = 0.0;
        match self.strat {
            PowerSchedule::COE => {
                fuzz_mu = self.fuzz_mu(state)?;
            }
            _ => {}
        }

        // 1 + state.rand_mut().below(DEFAULT_MUTATIONAL_MAX_ITERATIONS) as usize
        Ok(self.calculate_score(testcasedata, statsdata, fuzz_mu))
    }

    #[allow(clippy::cast_possible_wrap)]
    fn perform_mutational(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error> {
        let num = self.iterations(state, corpus_idx)?;

        for i in 0..num {
            let mut input = state
                .corpus()
                .get(corpus_idx)?
                .borrow_mut()
                .load_input()?
                .clone();

            self.mutator_mut().mutate(state, &mut input, i as i32)?;

            // Time is measured directly the `evaluate_input` function
            let (_, corpus_idx) = fuzzer.evaluate_input(state, executor, manager, input)?;

            let observer = executor
                .observers()
                .match_name::<O>(&self.map_observer_name)
                .unwrap();

            let mut hash = observer.hash() as usize;
            hash = hash % N_FUZZ_SIZE;

            match corpus_idx {
                Some(idx) => {
                    state
                        .corpus()
                        .get(idx)?
                        .borrow_mut()
                        .metadata_mut()
                        .get_mut::<PowerScheduleTestData>()
                        .unwrap()
                        .n_fuzz_entry = hash;

                    self.n_fuzz[hash] += 1;
                }
                None => {
                    // self.n_fuzz[hash] can be 0 here when the MapObserver.map() is different it's not deemed as interesting
                    // when the map goes through the AFL's bucket.s
                    self.n_fuzz[hash] += 1;
                }
            }

            self.mutator_mut().post_exec(state, i as i32, corpus_idx)?;
        }

        Ok(())
    }
}

impl<C, E, EM, I, M, O, OT, S, T, Z> Stage<E, EM, S, Z>
    for PowerMutationalStage<C, E, EM, I, M, O, OT, S, T, Z>
where
    T: Integer + Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
    C: Corpus<I>,
    E: Executor<EM, I, S, Z> + HasObservers<I, OT, S>,
    I: Input,
    M: Mutator<I, S>,
    O: MapObserver<T>,
    OT: ObserversTuple<I, S>,
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

impl<C, E, EM, I, M, O, OT, S, T, Z> PowerMutationalStage<C, E, EM, I, M, O, OT, S, T, Z>
where
    T: Integer + Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned,
    C: Corpus<I>,
    E: Executor<EM, I, S, Z> + HasObservers<I, OT, S>,
    I: Input,
    M: Mutator<I, S>,
    O: MapObserver<T>,
    OT: ObserversTuple<I, S>,
    S: HasClientPerfStats + HasCorpus<C, I> + HasMetadata,
    Z: Evaluator<E, EM, I, S>,
{
    /// Creates a new default mutational stage
    pub fn new(mutator: M, strat: PowerSchedule, map_observer_name: &O) -> Self {
        Self {
            map_observer_name: map_observer_name.name().to_string(),
            mutator: mutator,
            n_fuzz: vec![0; N_FUZZ_SIZE],
            strat: strat,
            phantom: PhantomData,
        }
    }

    //
    #[inline]
    pub fn fuzz_mu(&self, state: &S) -> Result<f64, Error> {
        let corpus = state.corpus();
        let mut n_paths = 0;
        let mut fuzz_mu = 0.0;
        for idx in 0..corpus.count() {
            let n_fuzz_entry = corpus
                .get(idx)
                .unwrap()
                .borrow()
                .metadata()
                .get::<PowerScheduleTestData>()
                .unwrap()
                .n_fuzz_entry;
            if cfg!(feature = "std"){
                fuzz_mu += (self.n_fuzz[n_fuzz_entry] as f64).log2();
            }
            else{
                fuzz_mu += libm::log2(self.n_fuzz[n_fuzz_entry] as f64);
            }
            n_paths += 1;
        }

        if n_paths == 0 {
            return Err(Error::Unknown(String::from("Queue state corrput")));
        }

        fuzz_mu = fuzz_mu / (n_paths as f64);
        Ok(fuzz_mu)
    }

    #[inline]
    #[allow(clippy::cast_precision_loss)]
    fn calculate_score(
        &self,
        testcasedata: &mut PowerScheduleTestData,
        statsdata: &PowerScheduleStats,
        fuzz_mu: f64,
    ) -> usize {
        let mut perf_score = 100.0;
        let avg_exec_us = statsdata.total_cal_us / (statsdata.total_cal_cycles as u128);
        let avg_bitmap_size = statsdata.total_bitmap_size / statsdata.total_bitmap_size;

        let q_exec_us = testcasedata.exec_us as f64;
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

        let q_bitmap_size = testcasedata.bitmap_size as f64;
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

        if testcasedata.handicap >= 4 {
            perf_score *= 4.0;
            testcasedata.handicap -= 4;
        } else if testcasedata.handicap > 0 {
            perf_score *= 2.0;
            testcasedata.handicap -= 1;
        }

        if testcasedata.depth >= 4 && testcasedata.depth < 8 {
            perf_score *= 2.0;
        } else if testcasedata.depth >= 8 && testcasedata.depth < 14 {
            perf_score *= 3.0;
        } else if testcasedata.depth >= 14 && testcasedata.depth < 25 {
            perf_score *= 4.0;
        } else if testcasedata.depth >= 25 {
            perf_score *= 5.0;
        }

        let mut factor: f64 = 1.0;

        // TODO: currently we don't have any favored inputs, if that's introduced we need to modify code here
        match &self.strat {
            PowerSchedule::EXPLORE => {
                // Nothing happens in EXPLORE
            }
            PowerSchedule::EXPLOIT => {
                factor = MAX_FACTOR;
            }
            PowerSchedule::COE => {
                if self.n_fuzz[testcasedata.n_fuzz_entry] as f64 > fuzz_mu {
                    factor = 0.0;
                }
            }
            PowerSchedule::FAST => {
                if testcasedata.fuzz_level != 0 {
                    let lg;
                    if cfg!(feature = "std"){
                        lg = (self.n_fuzz[testcasedata.n_fuzz_entry] as f64).log2() as u32;
                    }
                    else{
                        lg = libm::log2(self.n_fuzz[testcasedata.n_fuzz_entry] as f64) as u32;
                    }
                    // Do thing if factor == 5
                    if lg < 2 {
                        factor = 4.0;
                    } else if lg >= 2 && lg < 4 {
                        factor = 3.0;
                    } else if lg >= 4 && lg < 5 {
                        factor = 2.0;
                    } else if lg >= 6 && lg < 7 {
                        factor = 0.8;
                    } else if lg >= 7 && lg < 8 {
                        factor = 0.6;
                    } else if lg >= 8 {
                        factor = 0.4;
                    }
                }
            }
            PowerSchedule::LIN => {
                factor = (testcasedata.fuzz_level as f64) / (self.n_fuzz[testcasedata.n_fuzz_entry] + 1) as f64;
            }
            PowerSchedule::QUAD => {
                factor = ((testcasedata.fuzz_level * testcasedata.fuzz_level) as f64)
                    / (self.n_fuzz[testcasedata.n_fuzz_entry] + 1) as f64;
            }
        }

        perf_score *= factor / POWER_BETA;

        // Lower bound if the strat is not COE.
        match self.strat {
            PowerSchedule::COE => {}
            _ => {
                if perf_score < 1.0 {
                    perf_score = 1.0;
                }
            }
        }

        // Upper bound
        if perf_score > HAVOC_MAX_MULT * 100.0 {
            perf_score = HAVOC_MAX_MULT * 100.0;
        }

        perf_score as usize
    }
}
