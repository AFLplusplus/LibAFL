//! The queue corpus scheduler with weighted queue item selection from aflpp (`https://github.com/AFLplusplus/AFLplusplus/blob/1d4f1e48797c064ee71441ba555b29fc3f467983/src/afl-fuzz-queue.c#L32`)
//! This queue corpus scheduler needs calibration stage.

use alloc::string::{String, ToString};
use core::marker::PhantomData;

use hashbrown::HashMap;
use libafl_bolts::rands::Rand;
use serde::{Deserialize, Serialize};

use crate::{
    corpus::{Corpus, CorpusId, HasTestcase, Testcase},
    inputs::UsesInput,
    observers::{MapObserver, ObserversTuple},
    random_corpus_id,
    schedulers::{
        powersched::{PowerSchedule, SchedulerMetadata},
        testcase_score::{CorpusWeightTestcaseScore, TestcaseScore},
        HasAFLRemovableScheduler, HasAFLSchedulerMetadata, RemovableScheduler, Scheduler,
    },
    state::{HasCorpus, HasMetadata, HasRand, State, UsesState},
    Error,
};

/// The Metadata for `WeightedScheduler`
#[cfg_attr(
    any(not(feature = "serdeany_autoreg"), miri),
    allow(clippy::unsafe_derive_deserialize)
)] // for SerdeAny
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WeightedScheduleMetadata {
    /// The fuzzer execution spent in the current cycles
    runs_in_current_cycle: usize,
    /// Alias table for weighted queue entry selection
    alias_table: HashMap<CorpusId, CorpusId>,
    /// Probability for which queue entry is selected
    alias_probability: HashMap<CorpusId, f64>,
}

impl Default for WeightedScheduleMetadata {
    fn default() -> Self {
        Self::new()
    }
}

impl WeightedScheduleMetadata {
    /// Constructor for `WeightedScheduleMetadata`
    #[must_use]
    pub fn new() -> Self {
        Self {
            runs_in_current_cycle: 0,
            alias_table: HashMap::default(),
            alias_probability: HashMap::default(),
        }
    }

    /// The getter for `runs_in_current_cycle`
    #[must_use]
    pub fn runs_in_current_cycle(&self) -> usize {
        self.runs_in_current_cycle
    }

    /// The setter for `runs_in_current_cycle`
    pub fn set_runs_current_cycle(&mut self, cycles: usize) {
        self.runs_in_current_cycle = cycles;
    }

    /// The getter for `alias_table`
    #[must_use]
    pub fn alias_table(&self) -> &HashMap<CorpusId, CorpusId> {
        &self.alias_table
    }

    /// The setter for `alias_table`
    pub fn set_alias_table(&mut self, table: HashMap<CorpusId, CorpusId>) {
        self.alias_table = table;
    }

    /// The getter for `alias_probability`
    #[must_use]
    pub fn alias_probability(&self) -> &HashMap<CorpusId, f64> {
        &self.alias_probability
    }

    /// The setter for `alias_probability`
    pub fn set_alias_probability(&mut self, probability: HashMap<CorpusId, f64>) {
        self.alias_probability = probability;
    }
}

libafl_bolts::impl_serdeany!(WeightedScheduleMetadata);

/// A corpus scheduler using power schedules with weighted queue item selection algo.
#[derive(Clone, Debug)]
pub struct WeightedScheduler<F, O, S> {
    strat: Option<PowerSchedule>,
    map_observer_name: String,
    last_hash: usize,
    phantom: PhantomData<(F, O, S)>,
}

impl<F, O, S> WeightedScheduler<F, O, S>
where
    F: TestcaseScore<S>,
    O: MapObserver,
    S: HasCorpus + HasMetadata + HasRand,
{
    /// Create a new [`WeightedScheduler`] without any power schedule
    #[must_use]
    pub fn new(state: &mut S, map_observer: &O) -> Self {
        Self::with_schedule(state, map_observer, None)
    }

    /// Create a new [`WeightedScheduler`]
    #[must_use]
    pub fn with_schedule(state: &mut S, map_observer: &O, strat: Option<PowerSchedule>) -> Self {
        let _ = state.metadata_or_insert_with(|| SchedulerMetadata::new(strat));
        let _ = state.metadata_or_insert_with(WeightedScheduleMetadata::new);

        Self {
            strat,
            map_observer_name: map_observer.name().to_string(),
            last_hash: 0,
            phantom: PhantomData,
        }
    }

    #[must_use]
    /// Getter for `strat`
    pub fn strat(&self) -> &Option<PowerSchedule> {
        &self.strat
    }

    /// Create a new alias table when the fuzzer finds a new corpus entry
    #[allow(
        clippy::unused_self,
        clippy::similar_names,
        clippy::cast_precision_loss,
        clippy::cast_lossless
    )]
    pub fn create_alias_table(&self, state: &mut S) -> Result<(), Error> {
        let n = state.corpus().count();

        let mut alias_table: HashMap<CorpusId, CorpusId> = HashMap::default();
        let mut alias_probability: HashMap<CorpusId, f64> = HashMap::default();
        let mut weights: HashMap<CorpusId, f64> = HashMap::default();

        let mut p_arr: HashMap<CorpusId, f64> = HashMap::default();
        let mut s_arr: HashMap<usize, CorpusId> = HashMap::default();
        let mut l_arr: HashMap<usize, CorpusId> = HashMap::default();

        let mut sum: f64 = 0.0;

        for i in state.corpus().ids() {
            let mut testcase = state.corpus().get(i)?.borrow_mut();
            let weight = F::compute(state, &mut *testcase)?;
            weights.insert(i, weight);
            sum += weight;
        }

        for (i, w) in &weights {
            p_arr.insert(*i, w * (n as f64) / sum);
        }

        // # of items in queue S
        let mut n_s = 0;

        // # of items in queue L
        let mut n_l = 0;
        // Divide P into two queues, S and L
        for s in state.corpus().ids().rev() {
            if *p_arr.get(&s).unwrap() < 1.0 {
                s_arr.insert(n_s, s);
                n_s += 1;
            } else {
                l_arr.insert(n_l, s);
                n_l += 1;
            }
        }

        while n_s > 0 && n_l > 0 {
            n_s -= 1;
            n_l -= 1;
            let a = *s_arr.get(&n_s).unwrap();
            let g = *l_arr.get(&n_l).unwrap();

            alias_probability.insert(a, *p_arr.get(&a).unwrap());
            alias_table.insert(a, g);
            *p_arr.get_mut(&g).unwrap() += p_arr.get(&a).unwrap() - 1.0;

            if *p_arr.get(&g).unwrap() < 1.0 {
                *s_arr.get_mut(&n_s).unwrap() = g;
                n_s += 1;
            } else {
                *l_arr.get_mut(&n_l).unwrap() = g;
                n_l += 1;
            }
        }

        while n_l > 0 {
            n_l -= 1;
            alias_probability.insert(*l_arr.get(&n_l).unwrap(), 1.0);
        }

        while n_s > 0 {
            n_s -= 1;
            alias_probability.insert(*s_arr.get(&n_s).unwrap(), 1.0);
        }

        let wsmeta = state.metadata_mut::<WeightedScheduleMetadata>()?;

        // Update metadata
        wsmeta.set_alias_probability(alias_probability);
        wsmeta.set_alias_table(alias_table);
        Ok(())
    }
}

impl<F, O, S> UsesState for WeightedScheduler<F, O, S>
where
    S: State,
{
    type State = S;
}

impl<F, O, S> HasAFLRemovableScheduler for WeightedScheduler<F, O, S>
where
    F: TestcaseScore<S>,
    S: State + HasTestcase + HasMetadata + HasCorpus + HasRand,
    O: MapObserver,
{
}

impl<F, O, S> RemovableScheduler for WeightedScheduler<F, O, S>
where
    F: TestcaseScore<S>,
    O: MapObserver,
    S: HasCorpus + HasMetadata + HasRand + HasTestcase + State,
{
    fn on_remove(
        &mut self,
        state: &mut Self::State,
        idx: CorpusId,
        prev: &Option<Testcase<<Self::State as UsesInput>::Input>>,
    ) -> Result<(), Error> {
        self.on_remove_metadata(state, idx, prev)
    }

    fn on_replace(
        &mut self,
        state: &mut Self::State,
        idx: CorpusId,
        prev: &Testcase<<Self::State as UsesInput>::Input>,
    ) -> Result<(), Error> {
        self.on_replace_metadata(state, idx, prev)
    }
}

impl<F, O, S> HasAFLSchedulerMetadata<O, S> for WeightedScheduler<F, O, S>
where
    F: TestcaseScore<S>,
    S: HasCorpus + HasMetadata + HasTestcase + HasRand + State,
    O: MapObserver,
{
    fn last_hash(&self) -> usize {
        self.last_hash
    }

    fn set_last_hash(&mut self, hash: usize) {
        self.last_hash = hash;
    }

    fn map_observer_name(&self) -> &str {
        &self.map_observer_name
    }
}

impl<F, O, S> Scheduler for WeightedScheduler<F, O, S>
where
    F: TestcaseScore<S>,
    O: MapObserver,
    S: HasCorpus + HasMetadata + HasRand + HasTestcase + State,
{
    /// Called when a [`Testcase`] is added to the corpus
    fn on_add(&mut self, state: &mut S, idx: CorpusId) -> Result<(), Error> {
        self.on_add_metadata(state, idx)?;
        self.create_alias_table(state)
    }

    fn on_evaluation<OT>(
        &mut self,
        state: &mut Self::State,
        input: &<Self::State as UsesInput>::Input,
        observers: &OT,
    ) -> Result<(), Error>
    where
        OT: ObserversTuple<Self::State>,
    {
        self.on_evaluation_metadata(state, input, observers)
    }

    #[allow(clippy::similar_names, clippy::cast_precision_loss)]
    fn next(&mut self, state: &mut S) -> Result<CorpusId, Error> {
        let corpus_counts = state.corpus().count();
        if corpus_counts == 0 {
            Err(Error::empty(String::from(
                "No entries in corpus. This often implies the target is not properly instrumented.",
            )))
        } else {
            let s = random_corpus_id!(state.corpus(), state.rand_mut());

            // Choose a random value between 0.000000000 and 1.000000000
            let probability = state.rand_mut().between(0, 1000000000) as f64 / 1000000000_f64;

            let wsmeta = state.metadata_mut::<WeightedScheduleMetadata>()?;

            let current_cycles = wsmeta.runs_in_current_cycle();

            // TODO deal with corpus_counts decreasing due to removals
            if current_cycles >= corpus_counts {
                wsmeta.set_runs_current_cycle(0);
            } else {
                wsmeta.set_runs_current_cycle(current_cycles + 1);
            }

            let idx = if probability < *wsmeta.alias_probability().get(&s).unwrap() {
                s
            } else {
                *wsmeta.alias_table().get(&s).unwrap()
            };

            // Update depth
            if current_cycles > corpus_counts {
                let psmeta = state.metadata_mut::<SchedulerMetadata>()?;
                psmeta.set_queue_cycles(psmeta.queue_cycles() + 1);
            }

            self.set_current_scheduled(state, Some(idx))?;
            Ok(idx)
        }
    }

    /// Set current fuzzed corpus id and `scheduled_count`
    fn set_current_scheduled(
        &mut self,
        state: &mut Self::State,
        next_idx: Option<CorpusId>,
    ) -> Result<(), Error> {
        self.on_next_metadata(state, next_idx)?;

        *state.corpus_mut().current_mut() = next_idx;
        Ok(())
    }
}

/// The standard corpus weight, same as aflpp
pub type StdWeightedScheduler<O, S> = WeightedScheduler<CorpusWeightTestcaseScore<S>, O, S>;
