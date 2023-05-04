//! The queue corpus scheduler for power schedules.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::{marker::PhantomData, time::Duration};

use serde::{Deserialize, Serialize};

use crate::{
    corpus::{Corpus, CorpusId, HasTestcase, SchedulerTestcaseMetadata, Testcase},
    inputs::UsesInput,
    observers::{MapObserver, ObserversTuple},
    schedulers::{RemovableScheduler, Scheduler},
    state::{HasCorpus, HasMetadata, UsesState},
    Error,
};

/// The n fuzz size
pub const N_FUZZ_SIZE: usize = 1 << 21;

crate::impl_serdeany!(SchedulerMetadata);

/// The metadata used for power schedules
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SchedulerMetadata {
    /// Powerschedule strategy
    strat: Option<PowerSchedule>,
    /// Measured exec time during calibration
    exec_time: Duration,
    /// Calibration cycles
    cycles: u64,
    /// Size of the observer map
    bitmap_size: u64,
    /// Sum of log(bitmap_size)
    bitmap_size_log: f64,
    /// Number of filled map entries
    bitmap_entries: u64,
    /// Queue cycles
    queue_cycles: u64,
    /// The vector to contain the frequency of each execution path.
    n_fuzz: Vec<u32>,
}

/// The metadata for runs in the calibration stage.
impl SchedulerMetadata {
    /// Creates a new [`struct@SchedulerMetadata`]
    #[must_use]
    pub fn new(strat: Option<PowerSchedule>) -> Self {
        Self {
            strat,
            exec_time: Duration::from_millis(0),
            cycles: 0,
            bitmap_size: 0,
            bitmap_size_log: 0.0,
            bitmap_entries: 0,
            queue_cycles: 0,
            n_fuzz: vec![0; N_FUZZ_SIZE],
        }
    }

    /// The powerschedule strategy
    #[must_use]
    pub fn strat(&self) -> Option<PowerSchedule> {
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

    #[must_use]
    /// The sum of log(`bitmap_size`)
    pub fn bitmap_size_log(&self) -> f64 {
        self.bitmap_size_log
    }

    /// Setts the sum of log(`bitmap_size`)
    pub fn set_bitmap_size_log(&mut self, val: f64) {
        self.bitmap_size_log = val;
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
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum PowerSchedule {
    /// The `explore` power schedule
    EXPLORE,
    /// The `exploit` power schedule
    EXPLOIT,
    /// The `fast` power schedule
    FAST,
    /// The `coe` power schedule
    COE,
    /// The `lin` power schedule
    LIN,
    /// The `quad` power schedule
    QUAD,
}

/// A corpus scheduler using power schedules
#[derive(Clone, Debug)]
pub struct PowerQueueScheduler<O, S> {
    strat: PowerSchedule,
    map_observer_name: String,
    last_hash: usize,
    phantom: PhantomData<(O, S)>,
}

impl<O, S> UsesState for PowerQueueScheduler<O, S>
where
    S: UsesInput,
{
    type State = S;
}

impl<O, S> RemovableScheduler for PowerQueueScheduler<O, S>
where
    S: HasCorpus + HasMetadata + HasTestcase,
    O: MapObserver,
{
    #[allow(clippy::cast_precision_loss)]
    fn on_replace(
        &mut self,
        state: &mut Self::State,
        idx: CorpusId,
        prev: &Testcase<<Self::State as UsesInput>::Input>,
    ) -> Result<(), Error> {
        let prev_meta = prev.metadata::<SchedulerTestcaseMetadata>()?;

        // Next depth is + 1
        let prev_depth = prev_meta.depth() + 1;

        // Use these to adjust `SchedulerMetadata`
        let (prev_total_time, prev_cycles) = prev_meta.cycle_and_time();
        let prev_bitmap_size = prev_meta.bitmap_size();
        let prev_bitmap_size_log = libm::log2(prev_bitmap_size as f64);

        let psmeta = state.metadata_mut::<SchedulerMetadata>()?;

        // We won't add new one because it'll get added when it gets executed in calirbation next time.
        psmeta.set_exec_time(psmeta.exec_time() - prev_total_time);
        psmeta.set_cycles(psmeta.cycles() - (prev_cycles as u64));
        psmeta.set_bitmap_size(psmeta.bitmap_size() - prev_bitmap_size);
        psmeta.set_bitmap_size_log(psmeta.bitmap_size_log() - prev_bitmap_size_log);
        psmeta.set_bitmap_entries(psmeta.bitmap_entries() - 1);

        state
            .testcase_mut(idx)?
            .add_metadata(SchedulerTestcaseMetadata::new(prev_depth));
        Ok(())
    }

    #[allow(clippy::cast_precision_loss)]
    fn on_remove(
        &mut self,
        state: &mut Self::State,
        _idx: CorpusId,
        prev: &Option<Testcase<<Self::State as UsesInput>::Input>>,
    ) -> Result<(), Error> {
        let prev = prev.as_ref().ok_or_else(|| {
            Error::illegal_argument(
                "Power schedulers must be aware of the removed corpus entry for reweighting.",
            )
        })?;

        let prev_meta = prev.metadata::<SchedulerTestcaseMetadata>()?;

        // Use these to adjust `SchedulerMetadata`
        let (prev_total_time, prev_cycles) = prev_meta.cycle_and_time();
        let prev_bitmap_size = prev_meta.bitmap_size();
        let prev_bitmap_size_log = libm::log2(prev_bitmap_size as f64);

        let psmeta = state.metadata_mut::<SchedulerMetadata>()?;

        psmeta.set_exec_time(psmeta.exec_time() - prev_total_time);
        psmeta.set_cycles(psmeta.cycles() - (prev_cycles as u64));
        psmeta.set_bitmap_size(psmeta.bitmap_size() - prev_bitmap_size);
        psmeta.set_bitmap_size_log(psmeta.bitmap_size_log() - prev_bitmap_size_log);
        psmeta.set_bitmap_entries(psmeta.bitmap_entries() - 1);

        Ok(())
    }
}

impl<O, S> Scheduler for PowerQueueScheduler<O, S>
where
    S: HasCorpus + HasMetadata + HasTestcase,
    O: MapObserver,
{
    /// Add an entry to the corpus and return its index
    fn on_add(&mut self, state: &mut Self::State, idx: CorpusId) -> Result<(), Error> {
        let current_idx = *state.corpus().current();

        let mut depth = match current_idx {
            Some(parent_idx) => state
                .testcase(parent_idx)?
                .metadata::<SchedulerTestcaseMetadata>()?
                .depth(),
            None => 0,
        };

        // TODO increase perf_score when finding new things like in AFL
        // https://github.com/google/AFL/blob/master/afl-fuzz.c#L6547

        // Attach a `SchedulerTestcaseMetadata` to the queue entry.
        depth += 1;
        let mut testcase = state.testcase_mut(idx)?;
        testcase.add_metadata(SchedulerTestcaseMetadata::with_n_fuzz_entry(
            depth,
            self.last_hash,
        ));
        testcase.set_parent_id_optional(current_idx);
        Ok(())
    }

    fn on_evaluation<OT>(
        &mut self,
        state: &mut Self::State,
        _input: &<Self::State as UsesInput>::Input,
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

        self.last_hash = hash;

        Ok(())
    }

    fn next(&mut self, state: &mut Self::State) -> Result<CorpusId, Error> {
        if state.corpus().count() == 0 {
            Err(Error::empty(String::from("No entries in corpus")))
        } else {
            let id = match state.corpus().current() {
                Some(cur) => {
                    if let Some(next) = state.corpus().next(*cur) {
                        next
                    } else {
                        let psmeta = state.metadata_mut::<SchedulerMetadata>()?;
                        psmeta.set_queue_cycles(psmeta.queue_cycles() + 1);
                        state.corpus().first().unwrap()
                    }
                }
                None => state.corpus().first().unwrap(),
            };
            self.set_current_scheduled(state, Some(id))?;

            Ok(id)
        }
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
            let tcmeta = testcase.metadata_mut::<SchedulerTestcaseMetadata>()?;

            if tcmeta.handicap() >= 4 {
                tcmeta.set_handicap(tcmeta.handicap() - 4);
            } else if tcmeta.handicap() > 0 {
                tcmeta.set_handicap(tcmeta.handicap() - 1);
            }
        }

        *state.corpus_mut().current_mut() = next_idx;
        Ok(())
    }
}

impl<O, S> PowerQueueScheduler<O, S>
where
    S: HasMetadata,
    O: MapObserver,
{
    /// Create a new [`PowerQueueScheduler`]
    #[must_use]
    pub fn new(state: &mut S, map_observer: &O, strat: PowerSchedule) -> Self {
        if !state.has_metadata::<SchedulerMetadata>() {
            state.add_metadata::<SchedulerMetadata>(SchedulerMetadata::new(Some(strat)));
        }
        PowerQueueScheduler {
            strat,
            map_observer_name: map_observer.name().to_string(),
            last_hash: 0,
            phantom: PhantomData,
        }
    }

    /// Getter for `strat`
    #[must_use]
    pub fn strat(&self) -> &PowerSchedule {
        &self.strat
    }
}
