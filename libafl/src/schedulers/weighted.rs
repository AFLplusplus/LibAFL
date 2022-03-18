//! The queue corpus scheduler with weighted queue item selection from aflpp (https://github.com/AFLplusplus/AFLplusplus/blob/1d4f1e48797c064ee71441ba555b29fc3f467983/src/afl-fuzz-queue.c#L32)
//! This queue corpus scheduler needs calibration stage and the power schedule stage.

use alloc::string::{String, ToString};

use crate::{
    bolts::rands::Rand,
    corpus::{Corpus, PowerScheduleTestcaseMetaData},
    inputs::Input,
    schedulers::{Scheduler, powersched::{PowerScheduleMetadata, PowerSchedule}},
    state::{HasCorpus, HasMetadata, HasRand},
    Error,
};
use core::marker::PhantomData;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]

/// The Metadata for `WeightedScheduler`
pub struct WeightedScheduleMetadata {
    /// The fuzzer execution spent in the current cycles
    runs_in_current_cycle: usize,
    /// Alias table for weighted queue entry selection
    alias_table: Vec<usize>,
    /// Probability for which queue entry is selected
    alias_probability: Vec<f64>,
    /// Cache the perf_score
    perf_scores: Vec<f64>,
}

impl WeightedScheduleMetadata {
    /// Constructor for `WeightedScheduleMetadata`
    pub fn new() -> Self {
        Self {
            runs_in_current_cycle: 0,
            alias_table: vec![0],
            alias_probability: vec![0.0],
            perf_scores: vec![0.0],
        }
    }

    /// The getter for `runs_in_current_cycle`
    pub fn runs_in_current_cycle(&self) -> usize {
        self.runs_in_current_cycle
    }

    /// The setter for `runs_in_current_cycle`
    pub fn set_runs_current_cycle(&mut self, cycles: usize) {
        self.runs_in_current_cycle = cycles;
    }

    /// The getter for `alias_table`
    pub fn alias_table(&self) -> &[usize] {
        &self.alias_table
    }

    /// The setter for `alias_table`
    pub fn set_alias_table(&mut self, table: Vec<usize>) {
        self.alias_table = table;
    }

    /// The getter for `alias_probability`
    pub fn alias_probability(&self) -> &[f64] {
        &self.alias_probability
    }

    /// The setter for `alias_probability`
    pub fn set_alias_probability(&mut self, probability: Vec<f64>) {
        self.alias_probability = probability;
    }

    /// The getter for `perf_scores`
    pub fn perf_scores(&self) -> &[f64] {
        &self.perf_scores
    }

    /// The setter for `perf_scores`
    pub fn set_perf_scores(&mut self, perf_scores: Vec<f64>) {
        self.perf_scores = perf_scores
    }
}


crate::impl_serdeany!(WeightedScheduleMetadata);

/// A corpus scheduler using power schedules with weighted queue item selection algo.
#[derive(Clone, Debug)]
pub struct WeightedScheduler<I, S> {
    phantom: PhantomData<(I, S)>
}

impl<I, S> Default for WeightedScheduler<I, S>
where
    I: Input,
    S: HasCorpus<I> + HasMetadata + HasRand,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<I, S> WeightedScheduler<I, S> 
where
    I: Input,
    S: HasCorpus<I> + HasMetadata + HasRand,
{
    /// Create a new [`PowerQueueScheduler`]
    #[must_use]
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }

    /// Create a new alias table when the fuzzer finds a new corpus entry
    pub fn create_alias_table(&self, state: &mut S) -> Result<(), Error> 
    {
        let n = state.corpus().count();

        let mut alias_table : Vec<usize> = vec![0; n];
        let mut alias_probability: Vec<f64> = vec![0.0; n];
        let mut perf_scores: Vec<f64> = vec![0.0; n];
        let mut weights : Vec<f64> = vec![0.0; n];

        let mut P : Vec<f64> = vec![0.0; n];
        let mut S : Vec<usize> = vec![0; n];
        let mut L : Vec<usize> = vec![0; n];

        let mut sum : f64 = 0.0;

        let psmeta = state
            .metadata()
            .get::<PowerScheduleMetadata>()
            .ok_or_else(|| {
                Error::KeyNotFound("PowerScheduleMetadata not found".to_string())
            })?;

        let fuzz_mu = if psmeta.strat() == PowerSchedule::COE {
            let corpus = state.corpus();
            let mut n_paths = 0;
            let mut v = 0.0;
            for idx in 0..corpus.count() {
                let n_fuzz_entry = corpus
                    .get(idx)?
                    .borrow()
                    .metadata()
                    .get::<PowerScheduleTestcaseMetaData>()
                    .ok_or_else(|| Error::KeyNotFound("PowerScheduleTestData not found".to_string()))?
                    .n_fuzz_entry();
                v += libm::log2(f64::from(psmeta.n_fuzz()[n_fuzz_entry]));
                n_paths += 1;
            }
    
            if n_paths == 0 {
                return Err(Error::Unknown(String::from("Queue state corrput")));
            }
    
            v /= f64::from(n_paths);
            v
        }
        else{
            0.0
        };

        for i in 0..n {
            let mut testcase = state.corpus().get(i)?.borrow_mut();
            let weight = testcase.compute_weight(psmeta)?;
            let perf_score = testcase.calculate_score(psmeta, fuzz_mu)? as f64;
            perf_scores[i] = perf_score;
            weights[i] = weight;
            sum += perf_score;
        }

        for i in 0..n {
            P[i] = weights[i] * (n as f64) / sum;
        }

        // # of items in queue S
        let mut nS = 0;

        // # of items in queue L
        let mut nL = 0;
        // Divide P into two queues, S and L
        for s in (0..n).rev() {
            if P[s] < 1.0 {
                S[nS] = s;
                nS += 1;
            }
            else{
                L[nL] = s;
                nL += 1
            }
        }

        while (nS > 0 && nL > 0) {
            nS -= 1;
            nL -= 1;
            let a = S[nS];
            let g = L[nL];

            alias_probability[a]= P[a];
            alias_table[a] = g;
            P[g] = P[a] + P[a] - 1.0;

            if P[g] < 1.0 {
                S[nS] = g;
                nS += 1;
            }
            else {
                L[nL] = g;
                nL += 1;
            }
        }

        while nL > 0 {
            nL -= 1;
            alias_probability[L[nL]] = 1.0;
        }

        while nS > 0 {
            nS -= 1;
            alias_probability[S[nS]] = 1.0;
        }


        let wsmeta = state
            .metadata_mut()
            .get_mut::<WeightedScheduleMetadata>()
            .ok_or_else(|| {
                Error::KeyNotFound("WeigthedScheduleMetadata not found".to_string())
            })?;


        // Update metadata
        wsmeta.set_alias_probability(alias_probability);
        wsmeta.set_alias_table(alias_table);
        wsmeta.set_perf_scores(perf_scores);
        Ok(())
    }
}



impl<I, S> Scheduler<I, S> for WeightedScheduler<I, S>
where
    S: HasCorpus<I> + HasMetadata + HasRand,
    I: Input,
{
    /// Add an entry to the corpus and return its index
    fn on_add(&self, state: &mut S, idx: usize) -> Result<(), Error> {
        let current_idx = *state.corpus().current();

        let mut depth = match current_idx {
            Some(parent_idx) => state
                .corpus()
                .get(parent_idx)?
                .borrow_mut()
                .metadata_mut()
                .get_mut::<PowerScheduleTestcaseMetaData>()
                .ok_or_else(|| Error::KeyNotFound("PowerScheduleTestData not found".to_string()))?
                .depth(),
            None => 0,
        };

        // Attach a `PowerScheduleTestData` to the queue entry.
        depth += 1;
        state
            .corpus()
            .get(idx)?
            .borrow_mut()
            .add_metadata(PowerScheduleTestcaseMetaData::new(depth));

        // Recrate the alias table
        self.create_alias_table(state)?;
        Ok(())
    }

    fn next(&self, state: &mut S) -> Result<usize, Error> {
        if state.corpus().count() == 0 {
            Err(Error::Empty(String::from("No entries in corpus")))
        } else {
            let corpus_counts = state.corpus().count();
            let s = state.rand().below(corpus_counts as u64) as usize;
            // Choose a random value between 0.000000000 and 1.000000000
            let probability = state.rand().between(0, 1000000000 ) as f64 / 1000000000 as f64;

            let wsmeta = state
                .metadata_mut()
                .get_mut::<WeightedScheduleMetadata>()
                .ok_or_else(|| {
                    Error::KeyNotFound("WeigthedScheduleMetadata not found".to_string())
                })?;
            
            let current_cycles = wsmeta.runs_in_current_cycle();

            if current_cycles > corpus_counts {
                wsmeta.set_runs_current_cycle(0);
            }
            else{
                wsmeta.set_runs_current_cycle(current_cycles + 1);
            }

            let idx = if probability < wsmeta.alias_probability()[s] {
                s
            }
            else{
                wsmeta.alias_table()[s]
            };

            // Update depth
            if current_cycles > corpus_counts {
                let psmeta = state
                    .metadata_mut()
                    .get_mut::<PowerScheduleMetadata>()
                    .ok_or_else(|| {
                        Error::KeyNotFound("PowerScheduleMetadata not found".to_string())
                    })?;
                psmeta.set_queue_cycles(psmeta.queue_cycles() + 1);
            }

            Ok(idx)
        }
    }
}
