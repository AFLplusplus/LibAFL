//! The queue corpus scheduler with weighted queue item selection from aflpp (`https://github.com/AFLplusplus/AFLplusplus/blob/1d4f1e48797c064ee71441ba555b29fc3f467983/src/afl-fuzz-queue.c#L32`)
//! This queue corpus scheduler needs calibration stage.

use alloc::string::{String, ToString};
use core::marker::PhantomData;

use hashbrown::HashMap;
use serde::{Deserialize, Serialize};

use crate::{
    bolts::rands::Rand,
    corpus::{Corpus, CorpusId, SchedulerTestcaseMetaData, Testcase},
    inputs::UsesInput,
    random_corpus_id,
    schedulers::{
        powersched::{PowerSchedule, SchedulerMetadata},
        testcase_score::{CorpusWeightTestcaseScore, TestcaseScore},
        Scheduler,
    },
    state::{HasCorpus, HasMetadata, HasRand, UsesState},
    Error,
};

#[derive(Serialize, Deserialize, Clone, Debug)]

/// The Metadata for `WeightedScheduler`
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

crate::impl_serdeany!(WeightedScheduleMetadata);

/// A corpus scheduler using power schedules with weighted queue item selection algo.
#[derive(Clone, Debug)]
pub struct WeightedScheduler<F, S> {
    strat: Option<PowerSchedule>,
    phantom: PhantomData<(F, S)>,
}

impl<F, S> Default for WeightedScheduler<F, S>
where
    F: TestcaseScore<S>,
    S: HasCorpus + HasMetadata + HasRand,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<F, S> WeightedScheduler<F, S>
where
    F: TestcaseScore<S>,
    S: HasCorpus + HasMetadata + HasRand,
{
    /// Create a new [`WeightedScheduler`] without any scheduling strategy
    #[must_use]
    pub fn new() -> Self {
        Self {
            strat: None,
            phantom: PhantomData,
        }
    }

    /// Create a new [`WeightedScheduler`]
    #[must_use]
    pub fn with_schedule(strat: PowerSchedule) -> Self {
        Self {
            strat: Some(strat),
            phantom: PhantomData,
        }
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
            let weight = F::compute(&mut *testcase, state)?;
            weights.insert(i, weight);
            sum += weight;
        }

        for (i, w) in weights.iter() {
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

        let wsmeta = state
            .metadata_mut()
            .get_mut::<WeightedScheduleMetadata>()
            .ok_or_else(|| {
                Error::key_not_found("WeigthedScheduleMetadata not found".to_string())
            })?;

        // Update metadata
        wsmeta.set_alias_probability(alias_probability);
        wsmeta.set_alias_table(alias_table);
        Ok(())
    }
}

impl<F, S> UsesState for WeightedScheduler<F, S>
where
    S: UsesInput,
{
    type State = S;
}

impl<F, S> Scheduler for WeightedScheduler<F, S>
where
    F: TestcaseScore<S>,
    S: HasCorpus + HasMetadata + HasRand,
{
    /// Add an entry to the corpus and return its index
    fn on_add(&self, state: &mut S, idx: CorpusId) -> Result<(), Error> {
        if !state.has_metadata::<SchedulerMetadata>() {
            state.add_metadata(SchedulerMetadata::new(self.strat));
        }

        if !state.has_metadata::<WeightedScheduleMetadata>() {
            state.add_metadata(WeightedScheduleMetadata::new());
        }

        let current_idx = *state.corpus().current();

        let mut depth = match current_idx {
            Some(parent_idx) => state
                .corpus()
                .get(parent_idx)?
                .borrow_mut()
                .metadata_mut()
                .get_mut::<SchedulerTestcaseMetaData>()
                .ok_or_else(|| {
                    Error::key_not_found("SchedulerTestcaseMetaData not found".to_string())
                })?
                .depth(),
            None => 0,
        };

        // Attach a `SchedulerTestcaseMetaData` to the queue entry.
        depth += 1;
        state
            .corpus()
            .get(idx)?
            .borrow_mut()
            .add_metadata(SchedulerTestcaseMetaData::new(depth));

        // Recreate the alias table
        self.create_alias_table(state)?;
        Ok(())
    }

    fn on_replace(
        &self,
        state: &mut S,
        idx: CorpusId,
        _testcase: &Testcase<S::Input>,
    ) -> Result<(), Error> {
        // Recreate the alias table
        self.on_add(state, idx)
    }

    fn on_remove(
        &self,
        state: &mut S,
        _idx: CorpusId,
        _testcase: &Option<Testcase<S::Input>>,
    ) -> Result<(), Error> {
        // Recreate the alias table
        self.create_alias_table(state)?;
        Ok(())
    }

    #[allow(clippy::similar_names, clippy::cast_precision_loss)]
    fn next(&self, state: &mut S) -> Result<CorpusId, Error> {
        let corpus_counts = state.corpus().count();
        if corpus_counts == 0 {
            Err(Error::empty(String::from("No entries in corpus")))
        } else {
            let s = random_corpus_id!(state.corpus(), state.rand_mut());

            // Choose a random value between 0.000000000 and 1.000000000
            let probability = state.rand_mut().between(0, 1000000000) as f64 / 1000000000_f64;

            let wsmeta = state
                .metadata_mut()
                .get_mut::<WeightedScheduleMetadata>()
                .ok_or_else(|| {
                    Error::key_not_found("WeigthedScheduleMetadata not found".to_string())
                })?;

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
                let psmeta = state
                    .metadata_mut()
                    .get_mut::<SchedulerMetadata>()
                    .ok_or_else(|| {
                        Error::key_not_found("SchedulerMetadata not found".to_string())
                    })?;
                psmeta.set_queue_cycles(psmeta.queue_cycles() + 1);
            }
            *state.corpus_mut().current_mut() = Some(idx);

            // Update the handicap
            let mut testcase = state.corpus().get(idx)?.borrow_mut();
            let tcmeta = testcase
                .metadata_mut()
                .get_mut::<SchedulerTestcaseMetaData>()
                .ok_or_else(|| {
                    Error::key_not_found("SchedulerTestcaseMetaData not found".to_string())
                })?;

            if tcmeta.handicap() >= 4 {
                tcmeta.set_handicap(tcmeta.handicap() - 4);
            } else if tcmeta.handicap() > 0 {
                tcmeta.set_handicap(tcmeta.handicap() - 1);
            }
            Ok(idx)
        }
    }
}

/// The standard corpus weight, same as aflpp
pub type StdWeightedScheduler<S> = WeightedScheduler<CorpusWeightTestcaseScore<S>, S>;
