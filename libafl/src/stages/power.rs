//! The power schedules. This stage should be invoked after the calibration stage.

use alloc::string::{String, ToString};
use core::{fmt::Debug, marker::PhantomData};
use num_traits::PrimInt;

use crate::{
    corpus::{Corpus, IsFavoredMetadata, PowerScheduleTestcaseMetaData, Testcase},
    executors::{Executor, HasObservers},
    fuzzer::Evaluator,
    inputs::Input,
    mutators::Mutator,
    observers::{MapObserver, ObserversTuple},
    stages::{MutationalStage, PowerScheduleMetadata, Stage},
    state::{HasClientPerfMonitor, HasCorpus, HasMetadata},
    Error,
};

/// The power schedule to use
#[allow(missing_docs)]
#[derive(Clone, Debug, PartialEq)]
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
const HAVOC_MAX_MULT: f64 = 64.0;

/// The mutational stage using power schedules
#[derive(Clone, Debug)]
pub struct PowerMutationalStage<E, EM, I, M, O, OT, S, T, Z>
where
    T: PrimInt + Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned + Debug,
    E: Executor<EM, I, S, Z> + HasObservers<I, OT, S>,
    I: Input,
    M: Mutator<I, S>,
    O: MapObserver,
    OT: ObserversTuple<I, S>,
    S: HasClientPerfMonitor + HasCorpus<I> + HasMetadata,
    Z: Evaluator<E, EM, I, S>,
{
    map_observer_name: String,
    mutator: M,
    /// The employed power schedule strategy
    strat: PowerSchedule,
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(E, EM, I, O, OT, S, T, Z)>,
}

impl<E, EM, I, M, O, OT, S, T, Z> MutationalStage<E, EM, I, M, S, Z>
    for PowerMutationalStage<E, EM, I, M, O, OT, S, T, Z>
where
    T: PrimInt + Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned + Debug,
    E: Executor<EM, I, S, Z> + HasObservers<I, OT, S>,
    I: Input,
    M: Mutator<I, S>,
    O: MapObserver,
    OT: ObserversTuple<I, S>,
    S: HasClientPerfMonitor + HasCorpus<I> + HasMetadata,
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
        let psmeta = state
            .metadata()
            .get::<PowerScheduleMetadata>()
            .ok_or_else(|| Error::KeyNotFound("PowerScheduleMetadata not found".to_string()))?;

        let mut fuzz_mu = 0.0;
        if self.strat == PowerSchedule::COE {
            fuzz_mu = self.fuzz_mu(state, psmeta)?;
        }
        let mut testcase = state.corpus().get(corpus_idx)?.borrow_mut();

        // 1 + state.rand_mut().below(DEFAULT_MUTATIONAL_MAX_ITERATIONS) as usize
        self.calculate_score(&mut testcase, psmeta, fuzz_mu)
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

            let (_, corpus_idx) = fuzzer.evaluate_input(state, executor, manager, input)?;

            let observer = executor
                .observers()
                .match_name::<O>(&self.map_observer_name)
                .ok_or_else(|| Error::KeyNotFound("MapObserver not found".to_string()))?;

            let mut hash = observer.hash() as usize;

            let psmeta = state
                .metadata_mut()
                .get_mut::<PowerScheduleMetadata>()
                .ok_or_else(|| Error::KeyNotFound("PowerScheduleMetadata not found".to_string()))?;

            hash %= psmeta.n_fuzz().len();
            // Update the path frequency
            psmeta.n_fuzz_mut()[hash] = psmeta.n_fuzz()[hash].saturating_add(1);

            if let Some(idx) = corpus_idx {
                state
                    .corpus()
                    .get(idx)?
                    .borrow_mut()
                    .metadata_mut()
                    .get_mut::<PowerScheduleTestcaseMetaData>()
                    .ok_or_else(|| {
                        Error::KeyNotFound("PowerScheduleTestData not found".to_string())
                    })?
                    .set_n_fuzz_entry(hash);
            }

            self.mutator_mut().post_exec(state, i as i32, corpus_idx)?;
        }

        Ok(())
    }
}

impl<E, EM, I, M, O, OT, S, T, Z> Stage<E, EM, S, Z>
    for PowerMutationalStage<E, EM, I, M, O, OT, S, T, Z>
where
    T: PrimInt + Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned + Debug,
    E: Executor<EM, I, S, Z> + HasObservers<I, OT, S>,
    I: Input,
    M: Mutator<I, S>,
    O: MapObserver,
    OT: ObserversTuple<I, S>,
    S: HasClientPerfMonitor + HasCorpus<I> + HasMetadata,
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

impl<E, EM, I, M, O, OT, S, T, Z> PowerMutationalStage<E, EM, I, M, O, OT, S, T, Z>
where
    T: PrimInt + Default + Copy + 'static + serde::Serialize + serde::de::DeserializeOwned + Debug,
    E: Executor<EM, I, S, Z> + HasObservers<I, OT, S>,
    I: Input,
    M: Mutator<I, S>,
    O: MapObserver,
    OT: ObserversTuple<I, S>,
    S: HasClientPerfMonitor + HasCorpus<I> + HasMetadata,
    Z: Evaluator<E, EM, I, S>,
{
    /// Creates a new [`PowerMutationalStage`]
    pub fn new(mutator: M, strat: PowerSchedule, map_observer_name: &O) -> Self {
        Self {
            map_observer_name: map_observer_name.name().to_string(),
            mutator,
            strat,
            phantom: PhantomData,
        }
    }

    /// Compute the parameter `μ` used in the COE schedule.
    #[inline]
    #[allow(clippy::unused_self)]
    pub fn fuzz_mu(&self, state: &S, psmeta: &PowerScheduleMetadata) -> Result<f64, Error> {
        let corpus = state.corpus();
        let mut n_paths = 0;
        let mut fuzz_mu = 0.0;
        for idx in 0..corpus.count() {
            let n_fuzz_entry = corpus
                .get(idx)?
                .borrow()
                .metadata()
                .get::<PowerScheduleTestcaseMetaData>()
                .ok_or_else(|| Error::KeyNotFound("PowerScheduleTestData not found".to_string()))?
                .n_fuzz_entry();
            fuzz_mu += libm::log2(f64::from(psmeta.n_fuzz()[n_fuzz_entry]));
            n_paths += 1;
        }

        if n_paths == 0 {
            return Err(Error::Unknown(String::from("Queue state corrput")));
        }

        fuzz_mu /= f64::from(n_paths);
        Ok(fuzz_mu)
    }

    /// Compute the `power` we assign to each corpus entry
    #[inline]
    #[allow(
        clippy::cast_precision_loss,
        clippy::too_many_lines,
        clippy::cast_sign_loss
    )]
    fn calculate_score(
        &self,
        testcase: &mut Testcase<I>,
        psmeta: &PowerScheduleMetadata,
        fuzz_mu: f64,
    ) -> Result<usize, Error> {
        let mut perf_score = 100.0;
        let q_exec_us = testcase
            .exec_time()
            .ok_or_else(|| Error::KeyNotFound("exec_time not set".to_string()))?
            .as_nanos() as f64;

        let avg_exec_us = psmeta.exec_time().as_nanos() as f64 / psmeta.cycles() as f64;
        let avg_bitmap_size = psmeta.bitmap_size() / psmeta.bitmap_entries();

        let favored = testcase.has_metadata::<IsFavoredMetadata>();
        let tcmeta = testcase
            .metadata_mut()
            .get_mut::<PowerScheduleTestcaseMetaData>()
            .ok_or_else(|| Error::KeyNotFound("PowerScheduleTestData not found".to_string()))?;

        if q_exec_us * 0.1 > avg_exec_us {
            perf_score = 10.0;
        } else if q_exec_us * 0.2 > avg_exec_us {
            perf_score = 25.0;
        } else if q_exec_us * 0.5 > avg_exec_us {
            perf_score = 50.0;
        } else if q_exec_us * 0.75 > avg_exec_us {
            perf_score = 75.0;
        } else if q_exec_us * 4.0 < avg_exec_us {
            perf_score = 300.0;
        } else if q_exec_us * 3.0 < avg_exec_us {
            perf_score = 200.0;
        } else if q_exec_us * 2.0 < avg_exec_us {
            perf_score = 150.0;
        }

        let q_bitmap_size = tcmeta.bitmap_size() as f64;
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

        if tcmeta.handicap() >= 4 {
            perf_score *= 4.0;
            tcmeta.set_handicap(tcmeta.handicap() - 4);
        } else if tcmeta.handicap() > 0 {
            perf_score *= 2.0;
            tcmeta.set_handicap(tcmeta.handicap() - 1);
        }

        if tcmeta.depth() >= 4 && tcmeta.depth() < 8 {
            perf_score *= 2.0;
        } else if tcmeta.depth() >= 8 && tcmeta.depth() < 14 {
            perf_score *= 3.0;
        } else if tcmeta.depth() >= 14 && tcmeta.depth() < 25 {
            perf_score *= 4.0;
        } else if tcmeta.depth() >= 25 {
            perf_score *= 5.0;
        }

        let mut factor: f64 = 1.0;

        // COE and Fast schedule are fairly different from what are described in the original thesis,
        // This implementation follows the changes made in this pull request https://github.com/AFLplusplus/AFLplusplus/pull/568
        match &self.strat {
            PowerSchedule::EXPLORE => {
                // Nothing happens in EXPLORE
            }
            PowerSchedule::EXPLOIT => {
                factor = MAX_FACTOR;
            }
            PowerSchedule::COE => {
                if libm::log2(f64::from(psmeta.n_fuzz()[tcmeta.n_fuzz_entry()])) > fuzz_mu
                    && !favored
                {
                    // Never skip favorites.
                    factor = 0.0;
                }
            }
            PowerSchedule::FAST => {
                if tcmeta.fuzz_level() != 0 {
                    let lg = libm::log2(f64::from(psmeta.n_fuzz()[tcmeta.n_fuzz_entry()]));

                    match lg {
                        f if f < 2.0 => {
                            factor = 4.0;
                        }
                        f if (2.0..4.0).contains(&f) => {
                            factor = 3.0;
                        }
                        f if (4.0..5.0).contains(&f) => {
                            factor = 2.0;
                        }
                        f if (6.0..7.0).contains(&f) => {
                            if !favored {
                                factor = 0.8;
                            }
                        }
                        f if (7.0..8.0).contains(&f) => {
                            if !favored {
                                factor = 0.6;
                            }
                        }
                        f if f >= 8.0 => {
                            if !favored {
                                factor = 0.4;
                            }
                        }
                        _ => {
                            factor = 1.0;
                        }
                    }

                    if favored {
                        factor *= 1.15;
                    }
                }
            }
            PowerSchedule::LIN => {
                factor = (tcmeta.fuzz_level() as f64)
                    / f64::from(psmeta.n_fuzz()[tcmeta.n_fuzz_entry()] + 1);
            }
            PowerSchedule::QUAD => {
                factor = ((tcmeta.fuzz_level() * tcmeta.fuzz_level()) as f64)
                    / f64::from(psmeta.n_fuzz()[tcmeta.n_fuzz_entry()] + 1);
            }
        }

        if self.strat != PowerSchedule::EXPLORE {
            if factor > MAX_FACTOR {
                factor = MAX_FACTOR;
            }

            perf_score *= factor / POWER_BETA;
        }

        // Lower bound if the strat is not COE.
        if self.strat == PowerSchedule::COE && perf_score < 1.0 {
            perf_score = 1.0;
        }

        // Upper bound
        if perf_score > HAVOC_MAX_MULT * 100.0 {
            perf_score = HAVOC_MAX_MULT * 100.0;
        }

        Ok(perf_score as usize)
    }
}
