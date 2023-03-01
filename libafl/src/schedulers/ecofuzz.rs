//! The corpus scheduler from `EcoFuzz` (`https://www.usenix.org/conference/usenixsecurity20/presentation/yue`)

use alloc::string::{String, ToString};
use core::marker::PhantomData;

use serde::{Deserialize, Serialize};

use crate::{
    corpus::{Corpus, CorpusId, SchedulerTestcaseMetaData, Testcase},
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
    was_fuzzed: bool,
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
    S: HasCorpus + HasMetadata + HasRand + HasExecutions,
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
            let meta = state
                .metadata()
                .get::<EcoMetadata>()
                .ok_or_else(|| Error::key_not_found("EcoMetadata not found".to_string()))?;
            (meta.last_mutation_num, meta.last_corpus_count)
        };

        let computed_score = {
            let mut testcase = state.corpus().get(id)?.borrow_mut();

            let meta = testcase
                .metadata_mut()
                .get_mut::<EcoTestcaseMetadata>()
                .ok_or_else(|| Error::key_not_found("EcoTestcaseMetadata not found".to_string()))?;
            // Set was_fuzzed for the old current
            meta.was_fuzzed = true;
            meta.last_found = count - last_corpus_count;
            meta.last_energy = meta.mutation_num - last_mutation_num;
            meta.computed_score
        };

        let meta = state
            .metadata_mut()
            .get_mut::<EcoMetadata>()
            .ok_or_else(|| Error::key_not_found("EcoMetadata not found".to_string()))?;

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
            .metadata_mut()
            .get_mut::<EcoMetadata>()
            .ok_or_else(|| Error::key_not_found("EcoMetadata not found".to_string()))?
            .initial_corpus_count
            .get_or_insert(count);
        Ok(())
    }

    /// Create a new alias table when the fuzzer finds a new corpus entry
    fn schedule(state: &mut S) -> Result<CorpusId, Error> {
        let mut selection = None;
        for id in state.corpus().ids() {
            let was_fuzzed = state
                .corpus()
                .get(id)?
                .borrow()
                .metadata()
                .get::<EcoTestcaseMetadata>()
                .ok_or_else(|| Error::key_not_found("EcoTestcaseMetadata not found".to_string()))?
                .was_fuzzed;
            if !was_fuzzed {
                selection = Some(id);
                break;
            }
        }

        for id in state.corpus().ids() {
            let was_fuzzed = state
                .corpus()
                .get(id)?
                .borrow()
                .metadata()
                .get::<EcoTestcaseMetadata>()
                .ok_or_else(|| Error::key_not_found("EcoTestcaseMetadata not found".to_string()))?
                .was_fuzzed;
            if was_fuzzed {
                state
                    .metadata_mut()
                    .get_mut::<EcoMetadata>()
                    .ok_or_else(|| Error::key_not_found("EcoMetadata not found".to_string()))?
                    .state = EcoState::Exploration;
                return Ok(selection.expect("Error in the algorithm, this cannot be None"));
            }
        }

        state
            .metadata_mut()
            .get_mut::<EcoMetadata>()
            .ok_or_else(|| Error::key_not_found("EcoMetadata not found".to_string()))?
            .state = EcoState::Exploitation;

        let mut cur = state.corpus().first();
        while let Some(id) = cur {
            let testcase_state = state
                .corpus()
                .get(id)?
                .borrow()
                .metadata()
                .get::<EcoTestcaseMetadata>()
                .ok_or_else(|| Error::key_not_found("EcoTestcaseMetadata not found".to_string()))?
                .state;
            if testcase_state != EcoState::Exploitation {
                break;
            }
            cur = state.corpus().next(id);
        }

        if cur.is_none() {
            for id in state.corpus().ids() {
                state
                    .corpus()
                    .get(id)?
                    .borrow_mut()
                    .metadata_mut()
                    .get_mut::<EcoTestcaseMetadata>()
                    .ok_or_else(|| {
                        Error::key_not_found("EcoTestcaseMetadata not found".to_string())
                    })?
                    .state = EcoState::None;
            }

            cur = state.corpus().first();
        }

        let mut selection = cur.unwrap();
        let mut selection_meta = state
            .corpus()
            .get(selection)?
            .borrow()
            .metadata()
            .get::<EcoTestcaseMetadata>()
            .ok_or_else(|| Error::key_not_found("EcoTestcaseMetadata not found".to_string()))?
            .clone();

        for id in state.corpus().ids() {
            let testcase = state.corpus().get(id)?.borrow();
            let meta = testcase
                .metadata()
                .get::<EcoTestcaseMetadata>()
                .ok_or_else(|| Error::key_not_found("EcoTestcaseMetadata not found".to_string()))?;

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
    S: HasCorpus + HasMetadata + HasRand + HasExecutions,
    O: MapObserver,
{
    /// Add an entry to the corpus and return its index
    fn on_add(&mut self, state: &mut S, idx: CorpusId) -> Result<(), Error> {
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
        state.corpus().get(idx)?.borrow_mut().add_metadata(
            SchedulerTestcaseMetaData::with_n_fuzz_entry(depth, self.last_hash),
        );

        // Add the testcase metadata for this scheduler
        state
            .corpus()
            .get(idx)?
            .borrow_mut()
            .add_metadata(EcoTestcaseMetadata::default());

        let executions = *state.executions();
        let meta = state
            .metadata_mut()
            .get_mut::<EcoMetadata>()
            .ok_or_else(|| Error::key_not_found("EcoMetadata not found".to_string()))?;

        let last_find_iteration = executions - meta.last_executions + 1;
        meta.last_find_iteration = last_find_iteration;

        Ok(())
    }

    fn on_replace(
        &mut self,
        state: &mut S,
        idx: CorpusId,
        _testcase: &Testcase<S::Input>,
    ) -> Result<(), Error> {
        self.on_add(state, idx)
    }

    #[allow(clippy::unused_self)]
    fn on_remove(
        &mut self,
        _state: &mut S,
        _idx: CorpusId,
        _testcase: &Option<Testcase<S::Input>>,
    ) -> Result<(), Error> {
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

        let psmeta = state
            .metadata_mut()
            .get_mut::<SchedulerMetadata>()
            .ok_or_else(|| Error::key_not_found("SchedulerMetadata not found".to_string()))?;

        hash %= psmeta.n_fuzz().len();
        // Update the path frequency
        psmeta.n_fuzz_mut()[hash] = psmeta.n_fuzz()[hash].saturating_add(1);

        if let Some(id) = *state.corpus().current() {
            state
                .corpus()
                .get(id)?
                .borrow_mut()
                .metadata_mut()
                .get_mut::<EcoTestcaseMetadata>()
                .ok_or_else(|| Error::key_not_found("EcoTestcaseMetadata not found".to_string()))?
                .mutation_num += 1;

            let entry = state
                .corpus()
                .get(id)?
                .borrow()
                .metadata()
                .get::<SchedulerTestcaseMetaData>()
                .ok_or_else(|| {
                    Error::key_not_found("SchedulerTestcaseMetaData not found".to_string())
                })?
                .n_fuzz_entry();
            if entry == hash {
                state
                    .corpus()
                    .get(id)?
                    .borrow_mut()
                    .metadata_mut()
                    .get_mut::<EcoTestcaseMetadata>()
                    .ok_or_else(|| {
                        Error::key_not_found("EcoTestcaseMetadata not found".to_string())
                    })?
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
        *state.corpus_mut().current_mut() = Some(id);

        let mutation_num = state
            .corpus()
            .get(id)?
            .borrow_mut()
            .metadata_mut()
            .get_mut::<EcoTestcaseMetadata>()
            .ok_or_else(|| Error::key_not_found("EcoTestcaseMetadata not found".to_string()))?
            .mutation_num;
        let count = state.corpus().count();
        let executions = *state.executions();

        let meta = state
            .metadata_mut()
            .get_mut::<EcoMetadata>()
            .ok_or_else(|| Error::key_not_found("EcoMetadata not found".to_string()))?;
        meta.last_mutation_num = mutation_num;
        meta.last_corpus_count = count;
        // TODO in theory it should be assigned at the beginning of the mutational stage
        // we must not count executions done in other stages
        meta.last_executions = executions;

        Ok(id)
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
    fn compute(entry: &mut Testcase<S::Input>, state: &S) -> Result<f64, Error> {
        // subtract # initial inputs to the corpus count
        let mut energy = 0;
        let mut average_cost = (state.corpus().count() / state.executions()) as u64;
        if average_cost == 0 {
            average_cost = 1024;
        }

        let (cur_state, rate) = {
            let meta = state
                .metadata()
                .get::<EcoMetadata>()
                .ok_or_else(|| Error::key_not_found("EcoMetadata not found".to_string()))?;
            (meta.state, meta.rate)
        };

        let meta = entry
            .metadata_mut()
            .get_mut::<EcoTestcaseMetadata>()
            .ok_or_else(|| Error::key_not_found("EcoTestcaseMetadata not found".to_string()))?;

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
