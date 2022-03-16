//! The power schedules. This stage should be invoked after the calibration stage.

use alloc::string::{String, ToString};
use core::{fmt::Debug, marker::PhantomData};

use crate::{
    corpus::{Corpus, PowerScheduleTestcaseMetaData, Testcase},
    executors::{Executor, HasObservers},
    fuzzer::Evaluator,
    inputs::Input,
    mutators::Mutator,
    observers::{MapObserver, ObserversTuple},
    schedulers::minimizer::IsFavoredMetadata,
    stages::{MutationalStage, Stage},
    state::{HasClientPerfMonitor, HasCorpus, HasMetadata},
    Error,
};
use core::time::Duration;
use serde::{Deserialize, Serialize};

/// The n fuzz size
pub const N_FUZZ_SIZE: usize = 1 << 21;

/// The metadata used for power schedules
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PowerScheduleMetadata {
    /// Powerschedule strategy
    strat: PowerSchedule,
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
    pub fn new(strat: PowerSchedule) -> Self {
        Self {
            strat: strat,
            exec_time: Duration::from_millis(0),
            cycles: 0,
            bitmap_size: 0,
            bitmap_entries: 0,
            queue_cycles: 0,
            n_fuzz: vec![0; N_FUZZ_SIZE],
        }
    }

    /// The powerschedule strategy
    #[must_use]
    pub fn strat(&self) -> PowerSchedule {
        self.strat
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

/// The power schedule to use
#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
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
pub struct PowerMutationalStage<E, EM, I, M, O, OT, S, Z>
where
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
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(E, EM, I, O, OT, S, Z)>,
}

impl<E, EM, I, M, O, OT, S, Z> MutationalStage<E, EM, I, M, S, Z>
    for PowerMutationalStage<E, EM, I, M, O, OT, S, Z>
where
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
        if psmeta.strat == PowerSchedule::COE {
            fuzz_mu = self.fuzz_mu(state, psmeta)?;
        }
        let mut testcase = state.corpus().get(corpus_idx)?.borrow_mut();

        // 1 + state.rand_mut().below(DEFAULT_MUTATIONAL_MAX_ITERATIONS) as usize
        testcase.calculate_score(psmeta, fuzz_mu)
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

impl<E, EM, I, M, O, OT, S, Z> Stage<E, EM, S, Z> for PowerMutationalStage<E, EM, I, M, O, OT, S, Z>
where
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

impl<E, EM, I, M, O, OT, S, Z> PowerMutationalStage<E, EM, I, M, O, OT, S, Z>
where
    E: Executor<EM, I, S, Z> + HasObservers<I, OT, S>,
    I: Input,
    M: Mutator<I, S>,
    O: MapObserver,
    OT: ObserversTuple<I, S>,
    S: HasClientPerfMonitor + HasCorpus<I> + HasMetadata,
    Z: Evaluator<E, EM, I, S>,
{
    /// Creates a new [`PowerMutationalStage`]
    pub fn new(mutator: M, map_observer_name: &O) -> Self {
        Self {
            map_observer_name: map_observer_name.name().to_string(),
            mutator,
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
}
