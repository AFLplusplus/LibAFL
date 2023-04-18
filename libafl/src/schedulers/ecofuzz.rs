//! The corpus scheduler from `EcoFuzz` (`https://www.usenix.org/conference/usenixsecurity20/presentation/yue`)

use alloc::string::{String, ToString};
use core::marker::PhantomData;

use serde::{Deserialize, Serialize};

use crate::{
    corpus::{Corpus, CorpusId, HasTestcase, SchedulerTestcaseMetadata, Testcase},
    inputs::UsesInput,
    observers::{MapObserver, ObserversTuple},
    schedulers::{powersched::SchedulerMetadata, testcase_score::TestcaseScore, Scheduler},
    state::{HasCorpus, HasExecutions, HasMetadata, HasRand, UsesState},
    Error,
};

fn integer_sqrt(val: u64) -> u64 {
    let mut i = 0;
    let mut r = 0;
    while r <= val {
        r = i * i;
        i += 1;
    }
    i - 1
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Copy, Default)]
/// The state of the `EcoFuzz` scheduling algorithm
pub enum EcoState {
    /// Initial state
    #[default]
    None = 0,
    /// Same probability scheduling
    Exploration = 1,
    /// Focused fuzzing scheduling
    Exploitation = 2,
}

/// The testcase Metadata for `EcoScheduler`
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct EcoTestcaseMetadata {
    mutation_num: u64,
    exec_num: u64,
    exec_by_mutation: u64,
    last_found: usize,
    line: u64,
    last_energy: u64,
    state: EcoState,
    serial: u64,
    computed_score: f64,
}

crate::impl_serdeany!(EcoTestcaseMetadata);

/// The state Metadata for `EcoScheduler`
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct EcoMetadata {
    state: EcoState,
    initial_corpus_count: Option<usize>,
    last_mutation_num: u64,
    last_corpus_count: usize,
    last_executions: usize,
    last_find_iteration: usize,
    calculate_coe: u64,
    rate: f64,
}

crate::impl_serdeany!(EcoMetadata);

/// A corpus scheduler implementing `EcoFuzz` (`https://www.usenix.org/conference/usenixsecurity20/presentation/yue`)
#[derive(Clone, Debug)]
pub struct EcoScheduler<O, S> {
    map_observer_name: String,
    last_hash: usize,
    phantom: PhantomData<(O, S)>,
}

impl<O, S> EcoScheduler<O, S>
where
    S: HasCorpus + HasMetadata + HasRand + HasExecutions + HasTestcase,
    O: MapObserver,
{
    /// Create a new [`EcoScheduler`] without any power schedule
    #[must_use]
    pub fn new(state: &mut S, map_observer: &O) -> Self {
        if !state.has_metadata::<SchedulerMetadata>() {
            state.add_metadata(SchedulerMetadata::new(None));
        }
        if !state.has_metadata::<EcoMetadata>() {
            state.add_metadata(EcoMetadata::default());
        }
        Self {
            map_observer_name: map_observer.name().to_string(),
            last_hash: 0,
            phantom: PhantomData,
        }
    }

    #[allow(clippy::cast_precision_loss)]
    fn handle_previous(id: CorpusId, state: &mut S) -> Result<(), Error> {
        let count = state.corpus().count();

        let (last_mutation_num, last_corpus_count) = {
            let meta = state.metadata::<EcoMetadata>()?;
            (meta.last_mutation_num, meta.last_corpus_count)
        };

        let computed_score = {
            let mut testcase = state.testcase_mut(id)?;

            let meta = testcase.metadata_mut::<EcoTestcaseMetadata>()?;

            // Set was_fuzzed for the old current
            meta.last_found = count - last_corpus_count;
            meta.last_energy = meta.mutation_num - last_mutation_num;
            meta.computed_score
        };

        let meta = state.metadata_mut::<EcoMetadata>()?;

        let mut regret = meta.last_find_iteration as f64 / computed_score;
        if regret == 0.0 {
            regret = 1.1;
        }

        meta.rate =
            ((meta.rate * meta.calculate_coe as f64) + regret) / (meta.calculate_coe as f64 + 1.0);

        meta.calculate_coe += 1;
        if meta.calculate_coe > count as u64 / 100 {
            meta.calculate_coe = count as u64 / 100;
        }

        if meta.rate > 1.5 {
            meta.rate = 1.5;
        } else if meta.rate < 0.1 {
            meta.rate = 0.1;
        }

        Ok(())
    }

    fn first_iteration(state: &mut S) -> Result<(), Error> {
        let count = state.corpus().count();
        state
            .metadata_mut::<EcoMetadata>()?
            .initial_corpus_count
            .get_or_insert(count);
        Ok(())
    }

    /// Create a new alias table when the fuzzer finds a new corpus entry
    fn schedule(state: &mut S) -> Result<CorpusId, Error> {
        let mut selection = None;
        for id in state.corpus().ids() {
            let was_fuzzed = state.testcase(id)?.scheduled_count() > 0;
            if was_fuzzed {
                selection = Some(id);
                break;
            }
        }

        for id in state.corpus().ids() {
            let was_fuzzed = state.testcase(id)?.scheduled_count() > 0;
            if was_fuzzed {
                state.metadata_mut::<EcoMetadata>()?.state = EcoState::Exploration;
                return Ok(selection.expect("Error in the algorithm, this cannot be None"));
            }
        }

        state.metadata_mut::<EcoMetadata>()?.state = EcoState::Exploitation;

        let mut cur = state.corpus().first();
        while let Some(id) = cur {
            let testcase_state = state.testcase(id)?.metadata::<EcoTestcaseMetadata>()?.state;

            if testcase_state != EcoState::Exploitation {
                break;
            }
            cur = state.corpus().next(id);
        }

        if cur.is_none() {
            for id in state.corpus().ids() {
                state
                    .testcase_mut(id)?
                    .metadata_mut::<EcoTestcaseMetadata>()?
                    .state = EcoState::None;
            }

            cur = state.corpus().first();
        }

        let mut selection = cur.unwrap();
        let mut selection_meta = state
            .testcase(selection)?
            .metadata::<EcoTestcaseMetadata>()?
            .clone();

        for id in state.corpus().ids() {
            let testcase = state.testcase(id)?;
            let meta = testcase.metadata::<EcoTestcaseMetadata>()?;

            if meta.exec_by_mutation
                * selection_meta.mutation_num
                * integer_sqrt(selection_meta.serial)
                < selection_meta.exec_by_mutation * meta.mutation_num * integer_sqrt(meta.serial)
                && meta.state == EcoState::None
            {
                selection = id;
                selection_meta = meta.clone();
            }
        }

        Ok(selection)
    }
}

impl<O, S> UsesState for EcoScheduler<O, S>
where
    S: UsesInput,
{
    type State = S;
}

impl<O, S> Scheduler for EcoScheduler<O, S>
where
    S: HasCorpus + HasMetadata + HasRand + HasExecutions + HasTestcase,
    O: MapObserver,
{
    /// Add an entry to the corpus and return its index
    fn on_add(&mut self, state: &mut S, idx: CorpusId) -> Result<(), Error> {
        let current_idx = *state.corpus().current();

        let mut depth = match current_idx {
            Some(parent_idx) => state
                .testcase_mut(parent_idx)?
                .metadata_mut::<SchedulerTestcaseMetadata>()?
                .depth(),
            None => 0,
        };

        // Attach a `SchedulerTestcaseMetadata` to the queue entry.
        depth += 1;
        {
            let mut testcase = state.testcase_mut(idx)?;
            testcase.add_metadata(SchedulerTestcaseMetadata::with_n_fuzz_entry(
                depth,
                self.last_hash,
            ));
            testcase.set_parent_id_optional(current_idx);
        }
        // Add the testcase metadata for this scheduler
        state
            .testcase_mut(idx)?
            .add_metadata(EcoTestcaseMetadata::default());

        let executions = *state.executions();
        let meta = state.metadata_mut::<EcoMetadata>()?;

        let last_find_iteration = executions - meta.last_executions + 1;
        meta.last_find_iteration = last_find_iteration;

        Ok(())
    }

    fn on_evaluation<OT>(
        &mut self,
        state: &mut S,
        _input: &S::Input,
        observers: &OT,
    ) -> Result<(), Error>
    where
        OT: ObserversTuple<Self::State>,
    {
        let observer = observers
            .match_name::<O>(&self.map_observer_name)
            .ok_or_else(|| Error::key_not_found("MapObserver not found".to_string()))?;

        let mut hash = observer.hash() as usize;

        let psmeta = state.metadata_mut::<SchedulerMetadata>()?;

        hash %= psmeta.n_fuzz().len();
        // Update the path frequency
        psmeta.n_fuzz_mut()[hash] = psmeta.n_fuzz()[hash].saturating_add(1);

        if let Some(id) = *state.corpus().current() {
            state
                .testcase_mut(id)?
                .metadata_mut::<EcoTestcaseMetadata>()?
                .mutation_num += 1;

            let entry = state
                .testcase(id)?
                .metadata::<SchedulerTestcaseMetadata>()?
                .n_fuzz_entry();
            if entry == hash {
                state
                    .testcase_mut(id)?
                    .metadata_mut::<EcoTestcaseMetadata>()?
                    .exec_by_mutation += 1;
            }
        }

        self.last_hash = hash;

        Ok(())
    }

    fn next(&mut self, state: &mut S) -> Result<CorpusId, Error> {
        if let Some(id) = *state.corpus().current() {
            Self::handle_previous(id, state)?;
        } else {
            Self::first_iteration(state)?;
        }

        let id = Self::schedule(state)?;
        self.set_current_scheduled(state, Some(id))?;

        let mutation_num = state
            .testcase_mut(id)?
            .metadata_mut::<EcoTestcaseMetadata>()?
            .mutation_num;
        let count = state.corpus().count();
        let executions = *state.executions();

        let meta = state.metadata_mut::<EcoMetadata>()?;
        meta.last_mutation_num = mutation_num;
        meta.last_corpus_count = count;
        // TODO in theory it should be assigned at the beginning of the mutational stage
        // we must not count executions done in other stages
        meta.last_executions = executions;

        Ok(id)
    }

    /// Set current fuzzed corpus id and `scheduled_count`
    fn set_current_scheduled(
        &mut self,
        state: &mut Self::State,
        next_idx: Option<CorpusId>,
    ) -> Result<(), Error> {
        let current_idx = *state.corpus().current();

        if let Some(idx) = current_idx {
            let mut testcase = state.testcase_mut(idx)?;
            let scheduled_count = testcase.scheduled_count();

            // increase scheduled count, this was fuzz_level in afl
            testcase.set_scheduled_count(scheduled_count + 1);
        }

        *state.corpus_mut().current_mut() = next_idx;
        Ok(())
    }
}

/// The weight for each corpus entry
/// This result is used for corpus scheduling
#[derive(Debug, Clone)]
pub struct EcoTestcaseScore<S> {
    phantom: PhantomData<S>,
}

impl<S> TestcaseScore<S> for EcoTestcaseScore<S>
where
    S: HasCorpus + HasMetadata + HasExecutions,
{
    /// Compute the `weight` used in weighted corpus entry selection algo
    #[allow(clippy::cast_precision_loss, clippy::cast_lossless)]
    fn compute(state: &S, entry: &mut Testcase<S::Input>) -> Result<f64, Error> {
        // subtract # initial inputs to the corpus count
        let mut energy = 0;
        let mut average_cost = (state.corpus().count() / state.executions()) as u64;
        if average_cost == 0 {
            average_cost = 1024;
        }

        let (cur_state, rate) = {
            let meta = state.metadata::<EcoMetadata>()?;
            (meta.state, meta.rate)
        };

        let meta = entry.metadata_mut::<EcoTestcaseMetadata>()?;

        if cur_state == EcoState::Exploitation {
            meta.state = EcoState::Exploitation;
            if meta.last_found == 0 {
                energy = core::cmp::min(2 * meta.last_energy, 16 * average_cost);
            } else {
                energy = core::cmp::min(meta.last_energy, 16 * average_cost);
            }
        }

        if energy == 0 {
            if meta.exec_num > average_cost {
                energy = average_cost / 4;
            } else if meta.exec_num > average_cost / 2 {
                energy = average_cost / 2;
            } else {
                energy = average_cost;
            }
        }

        let score = energy as f64 * rate;
        meta.computed_score = score;

        Ok(score)
    }
}
