//! The fuzzer, and state are the core pieces of every good fuzzer

use alloc::vec::Vec;
use core::{
    borrow::BorrowMut,
    cell::{Ref, RefMut},
    fmt::Debug,
    marker::PhantomData,
    time::Duration,
};
#[cfg(feature = "std")]
use std::{
    fs,
    path::{Path, PathBuf},
};

#[cfg(feature = "std")]
use libafl_bolts::core_affinity::{CoreId, Cores};
use libafl_bolts::{
    rands::{Rand, StdRand},
    serdeany::{NamedSerdeAnyMap, SerdeAnyMap},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

mod stack;
pub use stack::StageStack;

#[cfg(feature = "introspection")]
use crate::monitors::stats::ClientPerfStats;
use crate::{
    Error, HasMetadata, HasNamedMetadata,
    corpus::{Corpus, CorpusId, HasCurrentCorpusId, HasTestcase, InMemoryCorpus, Testcase},
    events::{Event, EventFirer, EventWithStats, LogSeverity},
    executors::ExitKind,
    feedbacks::StateInitializer,
    fuzzer::{Evaluator, ExecuteInputResult, ExecutionMode, ExecutionTag},
    generators::Generator,
    inputs::{Input, NopInput},
    stages::StageId,
};
/// The maximum size of a testcase
pub const DEFAULT_MAX_SIZE: usize = 1_048_576;

/// Trait for elements offering a corpus
pub trait HasCorpus<I> {
    /// The associated type implementing [`Corpus`].
    type Corpus: Corpus<I>;

    /// The testcase corpus
    fn corpus(&self) -> &Self::Corpus;
    /// The testcase corpus (mutable)
    fn corpus_mut(&mut self) -> &mut Self::Corpus;
}

/// The trait that implements the very standard capability of a state.
/// This state contains important information about the current run
/// and can be used to restart the fuzzing process at any time.
///
/// You don't need to implement this completely, but instead can
/// implement indiviual traits that fit your usecase.
pub trait State:
    Serialize
    + DeserializeOwned
    + MaybeHasClientPerfMonitor
    + HasCurrentCorpusId
    + HasCurrentStageId
    + Stoppable
{
}

impl<C, I, R, SC> State for StdState<C, I, R, SC>
where
    C: Serialize + DeserializeOwned,
    R: Rand + Serialize + for<'de> Deserialize<'de>,
    SC: Serialize + DeserializeOwned,
    I: Serialize + DeserializeOwned,
{
}

/// Interact with the maximum size
pub trait HasMaxSize {
    /// The maximum size hint for items and mutations returned
    fn max_size(&self) -> usize;
    /// Sets the maximum size hint for the items and mutations
    fn set_max_size(&mut self, max_size: usize);
}

/// Trait for elements offering a corpus of solutions
pub trait HasSolutions<I> {
    /// The associated type implementing [`Corpus`] for solutions
    type Solutions: Corpus<I>;

    /// The solutions corpus
    fn solutions(&self) -> &Self::Solutions;
    /// The solutions corpus (mutable)
    fn solutions_mut(&mut self) -> &mut Self::Solutions;
}

/// Trait for elements offering a rand
pub trait HasRand {
    /// The associated type implementing [`Rand`]
    type Rand: Rand;
    /// The rand instance
    fn rand(&self) -> &Self::Rand;
    /// The rand instance (mutable)
    fn rand_mut(&mut self) -> &mut Self::Rand;
}

#[cfg(feature = "introspection")]
/// Trait for offering a [`ClientPerfStats`]
pub trait HasClientPerfMonitor {
    /// [`ClientPerfStats`] itself
    fn introspection_stats(&self) -> &ClientPerfStats;

    /// Mutatable ref to [`ClientPerfStats`]
    fn introspection_stats_mut(&mut self) -> &mut ClientPerfStats;
}

/// Intermediate trait for `HasClientPerfMonitor`
#[cfg(feature = "introspection")]
pub trait MaybeHasClientPerfMonitor: HasClientPerfMonitor {}

/// Intermediate trait for `HasClientPerfmonitor`
#[cfg(not(feature = "introspection"))]
pub trait MaybeHasClientPerfMonitor {}

#[cfg(not(feature = "introspection"))]
impl<T> MaybeHasClientPerfMonitor for T {}

#[cfg(feature = "introspection")]
impl<T> MaybeHasClientPerfMonitor for T where T: HasClientPerfMonitor {}

/// Trait for the execution counter
pub trait HasExecutions {
    /// The executions counter
    fn executions(&self) -> &u64;

    /// The executions counter (mutable)
    fn executions_mut(&mut self) -> &mut u64;
}

/// Trait for some stats of AFL
pub trait HasImported {
    ///the imported testcases counter
    fn imported(&self) -> &usize;

    ///the imported testcases counter (mutable)
    fn imported_mut(&mut self) -> &mut usize;
}

/// Trait for the starting time
pub trait HasStartTime {
    /// The starting time
    fn start_time(&self) -> &Duration;

    /// The starting time (mutable)
    fn start_time_mut(&mut self) -> &mut Duration;
}

/// Trait for the last report time, the last time this node reported progress
pub trait HasLastFoundTime {
    /// The last time we found something by ourselves
    fn last_found_time(&self) -> &Duration;

    /// The last time we found something by ourselves (mutable)
    fn last_found_time_mut(&mut self) -> &mut Duration;
}

/// Trait for the last report time, the last time this node reported progress
pub trait HasLastReportTime {
    /// The last time we reported progress,if available/used.
    /// This information is used by fuzzer `maybe_report_progress`.
    fn last_report_time(&self) -> &Option<Duration>;

    /// The last time we reported progress,if available/used (mutable).
    /// This information is used by fuzzer `maybe_report_progress`.
    fn last_report_time_mut(&mut self) -> &mut Option<Duration>;
}

/// Trait for states holding the current execution mode tag.
pub trait HasExecutionMode {
    /// The [`ExecutionMode`] the target executor should currently run inputs in.
    fn execution_mode(&self) -> ExecutionMode;

    /// Set the current [`ExecutionMode`].
    fn set_execution_mode(&mut self, mode: ExecutionMode);
}

/// Trait for states holding the exit kind of the last target execution.
pub trait HasLastExitKind {
    /// Get the exit kind of the last target execution.
    fn last_exit_kind(&self) -> Option<ExitKind>;

    /// Set the exit kind of the last target execution.
    fn set_last_exit_kind(&mut self, exit_kind: Option<ExitKind>);
}

/// Struct that holds the options for input loading
#[cfg(feature = "std")]
pub struct LoadConfig<'a, I, S, Z> {
    /// Load Input even if it was deemed "uninteresting" by the fuzzer
    forced: bool,
    /// Function to load input from a Path
    loader: &'a mut dyn FnMut(&mut Z, &mut S, &Path) -> Result<I, Error>,
    /// Error if Input leads to a Solution.
    exit_on_solution: bool,
}

#[cfg(feature = "std")]
impl<I, S, Z> Debug for LoadConfig<'_, I, S, Z> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "LoadConfig {{}}")
    }
}

/// Upper bound on concurrently in-flight (scheduled but not-yet-retired) inputs tracked in
/// [`StdState::active_inputs`].
///
/// In correct operation, inputs are retired promptly (via report/reconcile after execution), so
/// this map stays small — bounded by the scheduling window. Exceeding this bound signals an
/// input-retirement bug (a leak); we surface it loudly instead of silently discarding tracking
/// state, which would corrupt in-process crash/timeout recovery.
const MAX_ACTIVE_INFLIGHT_INPUTS: usize = 1 << 20;

/// The state a fuzz run.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(bound = "
        C: serde::Serialize + for<'a> serde::Deserialize<'a>,
        R: serde::Serialize + for<'a> serde::Deserialize<'a>,
        SC: serde::Serialize + for<'a> serde::Deserialize<'a>,
        I: serde::Serialize + for<'a> serde::Deserialize<'a>,
    ")]
pub struct StdState<C, I, R, SC> {
    /// RNG instance
    rand: R,
    /// How many times the executor ran the harness/target
    executions: u64,
    /// At what time the fuzzing started
    start_time: Duration,
    /// the number of new paths that imported from other fuzzers
    imported: usize,
    /// The corpus
    corpus: C,
    // Solutions corpus
    solutions: SC,
    /// Metadata stored for this state by one of the components
    metadata: SerdeAnyMap,
    /// Metadata stored with names
    named_metadata: NamedSerdeAnyMap,
    /// `MaxSize` testcase size for mutators that appreciate it
    max_size: usize,
    /// Performance statistics for this fuzzer
    #[cfg(feature = "introspection")]
    introspection_stats: ClientPerfStats,
    #[cfg(feature = "std")]
    /// Remaining initial inputs to load, if any
    remaining_initial_files: Option<Vec<PathBuf>>,
    #[cfg(feature = "std")]
    /// symlinks we have already traversed when loading `remaining_initial_files`
    dont_reenter: Option<Vec<PathBuf>>,
    #[cfg(feature = "std")]
    /// If inputs have been processed for multicore loading
    /// relevant only for `load_initial_inputs_multicore`
    multicore_inputs_processed: Option<bool>,
    /// The last time we reported progress (if available/used).
    /// This information is used by fuzzer `maybe_report_progress`.
    last_report_time: Option<Duration>,
    /// The last time something was added to the corpus
    last_found_time: Duration,
    /// The current index of the corpus; used to record for resumable fuzzing.
    corpus_id: Option<CorpusId>,
    /// Request the fuzzer to stop at the start of the next stage
    /// or at the beginning of the next fuzzing iteration
    stop_requested: bool,
    stage_stack: StageStack,
    /// Current execution mode requested for the target executor
    #[serde(default)]
    execution_mode: ExecutionMode,
    /// Staged inputs currently scheduled or in-flight for execution
    #[serde(default)]
    current_inputs: Vec<I>,
    /// Index of the currently executing input within `current_inputs` (for exact batch resumption after crash/restart)
    #[serde(default)]
    current_input_idx: usize,
    /// Active in-flight inputs tracked by monotonic execution handle `id`
    #[serde(default)]
    active_inputs: hashbrown::HashMap<u64, I>,
    /// Next monotonic execution handle ID
    #[serde(default = "default_next_execution_id")]
    next_execution_id: u64,
    /// Starting execution handle ID of the currently staged batch
    #[serde(default = "default_next_execution_id")]
    current_batch_start_id: u64,
    /// Structured execution tag of the currently staged batch (persisted for stage routing across restart)
    #[serde(default)]
    current_batch_tag: Option<ExecutionTag>,
    /// Exit kind of the last target execution
    #[serde(default)]
    last_exit_kind: Option<ExitKind>,
    #[serde(default)]
    pending_exit_kind: Option<ExitKind>,
    #[serde(default)]
    pending_exec_time: Option<Duration>,
    phantom: PhantomData<I>,
}

const fn default_next_execution_id() -> u64 {
    1
}

/// Trait for states that hold the current batch of inputs staged for execution.
pub trait HasCurrentInputs<I> {
    /// Borrow the current batch of inputs staged for execution.
    fn current_inputs(&self) -> &[I];

    /// Mutable borrow to the current batch of inputs staged for execution.
    fn current_inputs_mut(&mut self) -> &mut Vec<I>;

    /// Get the index of the currently executing input within `current_inputs`.
    fn current_input_idx(&self) -> usize;

    /// Set the index of the currently executing input within `current_inputs`.
    fn set_current_input_idx(&mut self, idx: usize);

    /// Set the current batch of inputs staged for execution.
    fn set_current_inputs(&mut self, inputs: Vec<I>) {
        *self.current_inputs_mut() = inputs;
        self.set_current_input_idx(0);
    }

    /// Set the current batch of inputs from a slice, reusing existing element allocations in-place.
    fn set_current_inputs_slice(&mut self, inputs: &[I])
    where
        I: Clone,
    {
        let buf = self.current_inputs_mut();
        let common = core::cmp::min(buf.len(), inputs.len());
        for i in 0..common {
            buf[i].clone_from(&inputs[i]);
        }
        if inputs.len() > common {
            buf.extend_from_slice(&inputs[common..]);
        } else {
            buf.truncate(inputs.len());
        }
        self.set_current_input_idx(0);
    }

    /// Clear the current batch of staged inputs.
    fn clear_current_inputs(&mut self) {
        self.current_inputs_mut().clear();
        self.set_current_input_idx(0);
    }
}

/// Trait for states that track in-flight execution handles for the push fuzzing engine.
///
/// In-flight tracking covers the monotonic execution-id allocator, the active (scheduled but
/// not-yet-retired) input map, the current batch's start id/tag, and the pending exit kind/time
/// recorded by an in-process crash/timeout signal handler before restart. It extends
/// [`HasCurrentInputs`] because completing an in-flight input advances the staging cursor.
pub trait HasInFlightExecutions<I>: HasCurrentInputs<I> {
    /// Get the starting execution ID of the currently staged batch.
    fn current_batch_start_id(&self) -> u64;

    /// Set the starting execution ID of the currently staged batch.
    fn set_current_batch_start_id(&mut self, start_id: u64);

    /// Get the structured execution tag of the currently staged batch.
    fn current_batch_tag(&self) -> Option<ExecutionTag>;

    /// Set the structured execution tag of the currently staged batch.
    fn set_current_batch_tag(&mut self, tag: Option<ExecutionTag>);

    /// Allocate and return the next monotonic execution handle ID.
    fn next_execution_id(&mut self) -> u64;

    /// Allocate a block of `count` monotonic execution handle IDs, returning the start ID.
    #[inline]
    fn allocate_execution_ids(&mut self, count: usize) -> u64 {
        let start = self.next_execution_id();
        for _ in 1..count {
            let _ = self.next_execution_id();
        }
        start
    }

    /// Insert an active in-flight input by handle `id` into the state.
    fn insert_active_input(&mut self, id: u64, input: I);

    /// Check whether an active in-flight input is already tracked under handle `id`.
    #[inline]
    fn has_active_input(&self, _id: u64) -> bool {
        false
    }

    /// Remove and return an active in-flight input by handle `id` from the state.
    fn take_active_input(&mut self, id: u64) -> Option<I>;

    /// Return the number of active in-flight inputs tracked in the state.
    fn active_inputs_count(&self) -> usize;

    /// Clear all active in-flight inputs tracked in the state.
    fn clear_active_inputs(&mut self);

    /// Get the pending exit kind recorded by an in-process crash/timeout signal handler before restart.
    fn pending_exit_kind(&self) -> Option<ExitKind>;

    /// Set or clear the pending exit kind recorded before restart.
    fn set_pending_exit_kind(&mut self, exit_kind: Option<ExitKind>);

    /// Get the pending execution duration recorded before restart.
    fn pending_exec_time(&self) -> Option<Duration>;

    /// Set or clear the pending execution duration recorded before restart.
    fn set_pending_exec_time(&mut self, exec_time: Option<Duration>);

    /// Mark the currently executing in-flight input as completed and advance `current_input_idx`.
    fn mark_in_flight_input_completed(&mut self) {
        if self.active_inputs_count() == 0 {
            let idx = self.current_input_idx();
            if idx < self.current_inputs().len() {
                self.set_current_input_idx(idx + 1);
            }
        }
    }
}

/// Everything a [`FuzzingEngine`](crate::fuzzer::FuzzingEngine) requires of its state.
///
/// This exists purely to name the set of capabilities the engine needs in one place, instead of
/// repeating the same ten bounds on every engine method. It is implemented automatically for any
/// state that satisfies them, so states never implement it by hand.
pub trait FuzzerState<I>:
    HasCorpus<I>
    + HasSolutions<I>
    + HasExecutions
    + HasLastFoundTime
    + HasCurrentTestcase<I>
    + HasCurrentCorpusId
    + HasInFlightExecutions<I>
    + HasTestcase<I>
    + HasCurrentStageId
    + Stoppable
{
}

impl<I, S> FuzzerState<I> for S where
    S: HasCorpus<I>
        + HasSolutions<I>
        + HasExecutions
        + HasLastFoundTime
        + HasCurrentTestcase<I>
        + HasCurrentCorpusId
        + HasInFlightExecutions<I>
        + HasTestcase<I>
        + HasCurrentStageId
        + Stoppable
{
}

impl<C, I, R, SC> HasCurrentInputs<I> for StdState<C, I, R, SC> {
    #[inline]
    fn current_inputs(&self) -> &[I] {
        &self.current_inputs
    }

    #[inline]
    fn current_inputs_mut(&mut self) -> &mut Vec<I> {
        &mut self.current_inputs
    }

    #[inline]
    fn current_input_idx(&self) -> usize {
        self.current_input_idx
    }

    #[inline]
    fn set_current_input_idx(&mut self, idx: usize) {
        self.current_input_idx = idx;
    }
}

impl<C, I, R, SC> HasInFlightExecutions<I> for StdState<C, I, R, SC> {
    #[inline]
    fn current_batch_start_id(&self) -> u64 {
        self.current_batch_start_id
    }

    #[inline]
    fn set_current_batch_start_id(&mut self, start_id: u64) {
        self.current_batch_start_id = start_id;
    }

    #[inline]
    fn current_batch_tag(&self) -> Option<ExecutionTag> {
        self.current_batch_tag
    }

    #[inline]
    fn set_current_batch_tag(&mut self, tag: Option<ExecutionTag>) {
        self.current_batch_tag = tag;
    }

    #[inline]
    fn next_execution_id(&mut self) -> u64 {
        let id = self.next_execution_id;
        self.next_execution_id = self.next_execution_id.wrapping_add(1);
        id
    }

    #[inline]
    fn allocate_execution_ids(&mut self, count: usize) -> u64 {
        if count == 0 {
            return self.next_execution_id;
        }
        let start = self.next_execution_id;
        self.next_execution_id = self.next_execution_id.wrapping_add(count as u64);
        start
    }

    #[inline]
    fn insert_active_input(&mut self, id: u64, input: I) {
        assert!(
            self.active_inputs.len() < MAX_ACTIVE_INFLIGHT_INPUTS,
            "in-flight input tracking exceeded {MAX_ACTIVE_INFLIGHT_INPUTS} entries; this indicates \
             an input-retirement bug (leak) in the fuzzing engine",
        );
        self.active_inputs.insert(id, input);
    }

    #[inline]
    fn has_active_input(&self, id: u64) -> bool {
        self.active_inputs.contains_key(&id)
    }

    #[inline]
    fn take_active_input(&mut self, id: u64) -> Option<I> {
        self.active_inputs.remove(&id)
    }

    #[inline]
    fn active_inputs_count(&self) -> usize {
        self.active_inputs.len()
    }

    #[inline]
    fn clear_active_inputs(&mut self) {
        self.active_inputs.clear();
    }

    fn pending_exit_kind(&self) -> Option<ExitKind> {
        self.pending_exit_kind
    }

    fn set_pending_exit_kind(&mut self, exit_kind: Option<ExitKind>) {
        self.pending_exit_kind = exit_kind;
    }

    fn pending_exec_time(&self) -> Option<Duration> {
        self.pending_exec_time
    }

    fn set_pending_exec_time(&mut self, exec_time: Option<Duration>) {
        self.pending_exec_time = exec_time;
    }
}

impl<C, I, R, SC> HasExecutionMode for StdState<C, I, R, SC> {
    #[inline]
    fn execution_mode(&self) -> ExecutionMode {
        self.execution_mode
    }

    #[inline]
    fn set_execution_mode(&mut self, mode: ExecutionMode) {
        self.execution_mode = mode;
    }
}

impl<C, I, R, SC> HasLastExitKind for StdState<C, I, R, SC> {
    #[inline]
    fn last_exit_kind(&self) -> Option<ExitKind> {
        self.last_exit_kind
    }

    #[inline]
    fn set_last_exit_kind(&mut self, exit_kind: Option<ExitKind>) {
        self.last_exit_kind = exit_kind;
    }
}

impl<C, I, R, SC> HasRand for StdState<C, I, R, SC>
where
    R: Rand,
{
    type Rand = R;

    /// The rand instance
    #[inline]
    fn rand(&self) -> &Self::Rand {
        &self.rand
    }

    /// The rand instance (mutable)
    #[inline]
    fn rand_mut(&mut self) -> &mut Self::Rand {
        &mut self.rand
    }
}

impl<C, I, R, SC> HasCorpus<I> for StdState<C, I, R, SC>
where
    C: Corpus<I>,
{
    type Corpus = C;

    /// Returns the corpus
    #[inline]
    fn corpus(&self) -> &Self::Corpus {
        &self.corpus
    }

    /// Returns the mutable corpus
    #[inline]
    fn corpus_mut(&mut self) -> &mut Self::Corpus {
        &mut self.corpus
    }
}

impl<C, I, R, SC> HasTestcase<I> for StdState<C, I, R, SC>
where
    C: Corpus<I>,
{
    /// To get the testcase
    fn testcase(&self, id: CorpusId) -> Result<Ref<'_, Testcase<I>>, Error> {
        Ok(self.corpus().get(id)?.borrow())
    }

    /// To get mutable testcase
    fn testcase_mut(&self, id: CorpusId) -> Result<RefMut<'_, Testcase<I>>, Error> {
        Ok(self.corpus().get(id)?.borrow_mut())
    }
}

impl<C, I, R, SC> HasSolutions<I> for StdState<C, I, R, SC>
where
    C: Corpus<I>,
    I: Input,
    SC: Corpus<I>,
{
    type Solutions = SC;

    /// Returns the solutions corpus
    #[inline]
    fn solutions(&self) -> &SC {
        &self.solutions
    }

    /// Returns the solutions corpus (mutable)
    #[inline]
    fn solutions_mut(&mut self) -> &mut SC {
        &mut self.solutions
    }
}

impl<C, I, R, SC> HasMetadata for StdState<C, I, R, SC> {
    /// Get all the metadata into an [`hashbrown::HashMap`]
    #[inline]
    fn metadata_map(&self) -> &SerdeAnyMap {
        &self.metadata
    }

    /// Get all the metadata into an [`hashbrown::HashMap`] (mutable)
    #[inline]
    fn metadata_map_mut(&mut self) -> &mut SerdeAnyMap {
        &mut self.metadata
    }
}

impl<C, I, R, SC> HasNamedMetadata for StdState<C, I, R, SC> {
    /// Get all the metadata into an [`hashbrown::HashMap`]
    #[inline]
    fn named_metadata_map(&self) -> &NamedSerdeAnyMap {
        &self.named_metadata
    }

    /// Get all the metadata into an [`hashbrown::HashMap`] (mutable)
    #[inline]
    fn named_metadata_map_mut(&mut self) -> &mut NamedSerdeAnyMap {
        &mut self.named_metadata
    }
}

impl<C, I, R, SC> HasExecutions for StdState<C, I, R, SC> {
    /// The executions counter
    #[inline]
    fn executions(&self) -> &u64 {
        &self.executions
    }

    /// The executions counter (mutable)
    #[inline]
    fn executions_mut(&mut self) -> &mut u64 {
        &mut self.executions
    }
}

impl<C, I, R, SC> HasImported for StdState<C, I, R, SC> {
    /// Return the number of new paths that imported from other fuzzers
    #[inline]
    fn imported(&self) -> &usize {
        &self.imported
    }

    /// Return the number of new paths that imported from other fuzzers
    #[inline]
    fn imported_mut(&mut self) -> &mut usize {
        &mut self.imported
    }
}

impl<C, I, R, SC> HasLastFoundTime for StdState<C, I, R, SC> {
    /// Return the number of new paths that imported from other fuzzers
    #[inline]
    fn last_found_time(&self) -> &Duration {
        &self.last_found_time
    }

    /// Return the number of new paths that imported from other fuzzers
    #[inline]
    fn last_found_time_mut(&mut self) -> &mut Duration {
        &mut self.last_found_time
    }
}

impl<C, I, R, SC> HasLastReportTime for StdState<C, I, R, SC> {
    /// The last time we reported progress,if available/used.
    /// This information is used by fuzzer `maybe_report_progress`.
    fn last_report_time(&self) -> &Option<Duration> {
        &self.last_report_time
    }

    /// The last time we reported progress,if available/used (mutable).
    /// This information is used by fuzzer `maybe_report_progress`.
    fn last_report_time_mut(&mut self) -> &mut Option<Duration> {
        &mut self.last_report_time
    }
}

impl<C, I, R, SC> HasMaxSize for StdState<C, I, R, SC> {
    fn max_size(&self) -> usize {
        self.max_size
    }

    fn set_max_size(&mut self, max_size: usize) {
        self.max_size = max_size;
    }
}

impl<C, I, R, SC> HasStartTime for StdState<C, I, R, SC> {
    /// The starting time
    #[inline]
    fn start_time(&self) -> &Duration {
        &self.start_time
    }

    /// The starting time (mutable)
    #[inline]
    fn start_time_mut(&mut self) -> &mut Duration {
        &mut self.start_time
    }
}

impl<C, I, R, SC> HasCurrentCorpusId for StdState<C, I, R, SC> {
    fn set_corpus_id(&mut self, id: CorpusId) -> Result<(), Error> {
        self.corpus_id = Some(id);
        Ok(())
    }

    fn clear_corpus_id(&mut self) -> Result<(), Error> {
        self.corpus_id = None;
        Ok(())
    }

    fn current_corpus_id(&self) -> Result<Option<CorpusId>, Error> {
        Ok(self.corpus_id)
    }
}

/// Has information about the current [`Testcase`] we are fuzzing
pub trait HasCurrentTestcase<I>: HasCorpus<I> {
    /// Gets the current [`Testcase`] we are fuzzing
    ///
    /// Will return [`Error::key_not_found`] if no `corpus_id` is currently set.
    fn current_testcase(&self) -> Result<Ref<'_, Testcase<I>>, Error>;
    //fn current_testcase(&self) -> Result<&Testcase<I>, Error>;

    /// Gets the current [`Testcase`] we are fuzzing (mut)
    ///
    /// Will return [`Error::key_not_found`] if no `corpus_id` is currently set.
    fn current_testcase_mut(&self) -> Result<RefMut<'_, Testcase<I>>, Error>;
    //fn current_testcase_mut(&self) -> Result<&mut Testcase<I>, Error>;

    /// Gets a cloned representation of the current [`Testcase`].
    ///
    /// Will return [`Error::key_not_found`] if no `corpus_id` is currently set.
    ///
    /// # Note
    /// This allocates memory and copies the contents!
    /// For performance reasons, if you just need to access the testcase, use [`Self::current_testcase`] instead.
    fn current_input_cloned(&self) -> Result<I, Error>;
}

impl<I, T> HasCurrentTestcase<I> for T
where
    T: HasCorpus<I> + HasCurrentCorpusId,
    I: Clone,
{
    fn current_testcase(&self) -> Result<Ref<'_, Testcase<I>>, Error> {
        let Some(corpus_id) = self.current_corpus_id()? else {
            return Err(Error::key_not_found(
                "We are not currently processing a testcase",
            ));
        };

        Ok(self.corpus().get(corpus_id)?.borrow())
    }

    fn current_testcase_mut(&self) -> Result<RefMut<'_, Testcase<I>>, Error> {
        let Some(corpus_id) = self.current_corpus_id()? else {
            return Err(Error::illegal_state(
                "We are not currently processing a testcase",
            ));
        };

        Ok(self.corpus().get(corpus_id)?.borrow_mut())
    }

    fn current_input_cloned(&self) -> Result<I, Error> {
        let mut testcase = self.current_testcase_mut()?;
        Ok(testcase.borrow_mut().load_input(self.corpus())?.clone())
    }
}

/// A trait for types that want to expose a stop API
pub trait Stoppable {
    /// Check if stop is requested
    fn stop_requested(&self) -> bool;

    /// Request to stop
    fn request_stop(&mut self);

    /// Discard the stop request
    fn discard_stop_request(&mut self);
}

impl<C, I, R, SC> Stoppable for StdState<C, I, R, SC> {
    fn request_stop(&mut self) {
        self.stop_requested = true;
    }

    fn discard_stop_request(&mut self) {
        self.stop_requested = false;
    }

    fn stop_requested(&self) -> bool {
        self.stop_requested
    }
}

impl<C, I, R, SC> HasCurrentStageId for StdState<C, I, R, SC> {
    fn set_current_stage_id(&mut self, idx: StageId) -> Result<(), Error> {
        self.stage_stack.set_current_stage_id(idx)
    }

    fn clear_stage_id(&mut self) -> Result<(), Error> {
        self.stage_stack.clear_stage_id()
    }

    fn current_stage_id(&self) -> Result<Option<StageId>, Error> {
        self.stage_stack.current_stage_id()
    }

    fn on_restart(&mut self) -> Result<(), Error> {
        self.stage_stack.on_restart()
    }
}

/// Trait for types which track the current stage
pub trait HasCurrentStageId {
    /// Set the current stage; we have started processing this stage
    fn set_current_stage_id(&mut self, id: StageId) -> Result<(), Error>;

    /// Clear the current stage; we are done processing this stage
    fn clear_stage_id(&mut self) -> Result<(), Error>;

    /// Fetch the current stage -- typically used after a state recovery or transfer
    fn current_stage_id(&self) -> Result<Option<StageId>, Error>;

    /// Notify of a reset from which we may recover
    fn on_restart(&mut self) -> Result<(), Error> {
        Ok(())
    }
}

/// Trait for types which track nested stages. Stages which themselves contain stage tuples should
/// ensure that they constrain the state with this trait accordingly.
pub trait HasNestedStage: HasCurrentStageId {
    /// Enter a stage scope, potentially resuming to an inner stage status.
    fn enter_inner_stage(&mut self) -> Result<(), Error>;

    /// Exit a stage scope
    fn exit_inner_stage(&mut self) -> Result<(), Error>;
}

impl<C, I, R, SC> HasNestedStage for StdState<C, I, R, SC> {
    fn enter_inner_stage(&mut self) -> Result<(), Error> {
        self.stage_stack.enter_inner_stage()
    }

    fn exit_inner_stage(&mut self) -> Result<(), Error> {
        self.stage_stack.exit_inner_stage()
    }
}

#[cfg(feature = "std")]
impl<C, I, R, SC> StdState<C, I, R, SC>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
    SC: Corpus<I>,
{
    /// Decide if the state must load the inputs
    pub fn must_load_initial_inputs(&self) -> bool {
        self.corpus().count() == 0
            || (self.remaining_initial_files.is_some()
                && !self.remaining_initial_files.as_ref().unwrap().is_empty())
    }

    /// List initial inputs from a directory.
    fn next_file(&mut self) -> Result<PathBuf, Error> {
        loop {
            if let Some(path) = self.remaining_initial_files.as_mut().and_then(Vec::pop) {
                let filename = path.file_name().unwrap().to_string_lossy();
                if filename.starts_with('.')
                // || filename
                //     .rsplit_once('-')
                //     .is_some_and(|(_, s)| u64::from_str(s).is_ok())
                {
                    continue;
                }

                let attributes = fs::metadata(&path);

                if attributes.is_err() {
                    continue;
                }

                let attr = attributes?;

                if attr.is_file() && attr.len() > 0 {
                    return Ok(path);
                } else if attr.is_dir() {
                    let files = self.remaining_initial_files.as_mut().unwrap();
                    path.read_dir()?
                        .try_for_each(|entry| entry.map(|e| files.push(e.path())))?;
                } else if attr.is_symlink() {
                    let path = fs::canonicalize(path)?;
                    let dont_reenter = self.dont_reenter.get_or_insert_with(Default::default);
                    if dont_reenter.iter().any(|p| path.starts_with(p)) {
                        continue;
                    }
                    if path.is_dir() {
                        dont_reenter.push(path.clone());
                    }
                    let files = self.remaining_initial_files.as_mut().unwrap();
                    files.push(path);
                }
            } else {
                return Err(Error::iterator_end("No remaining files to load."));
            }
        }
    }

    /// Resets the state of initial files.
    fn reset_initial_files_state(&mut self) {
        self.remaining_initial_files = None;
        self.dont_reenter = None;
    }

    /// Sets canonical paths for provided inputs
    fn canonicalize_input_dirs(&mut self, in_dirs: &[PathBuf]) -> Result<(), Error> {
        if let Some(remaining) = self.remaining_initial_files.as_ref() {
            // everything was loaded
            if remaining.is_empty() {
                return Ok(());
            }
        } else {
            let files = in_dirs.iter().try_fold(Vec::new(), |mut res, file| {
                file.canonicalize().map(|canonicalized| {
                    res.push(canonicalized);
                    res
                })
            })?;
            self.dont_reenter = Some(files.clone());
            self.remaining_initial_files = Some(files);
        }
        Ok(())
    }

    /// Loads initial inputs from the passed-in `in_dirs`.
    /// If `forced` is true, will add all testcases, no matter what.
    /// This method takes a list of files.
    fn load_initial_inputs_custom_by_filenames<E, EM, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        manager: &mut EM,
        file_list: &[PathBuf],
        load_config: LoadConfig<I, Self, Z>,
    ) -> Result<(), Error>
    where
        EM: EventFirer<I, Self>,
        Z: Evaluator<E, EM, I, Self>,
    {
        if let Some(remaining) = self.remaining_initial_files.as_ref() {
            // everything was loaded
            if remaining.is_empty() {
                return Ok(());
            }
        } else {
            self.remaining_initial_files = Some(file_list.to_vec());
        }

        self.continue_loading_initial_inputs_custom(fuzzer, executor, manager, load_config)
    }

    fn load_file<E, EM, Z>(
        &mut self,
        path: &Path,
        manager: &mut EM,
        fuzzer: &mut Z,
        executor: &mut E,
        config: &mut LoadConfig<I, Self, Z>,
    ) -> Result<ExecuteInputResult, Error>
    where
        EM: EventFirer<I, Self>,
        Z: Evaluator<E, EM, I, Self>,
    {
        log::info!("Loading file {} ...", path.display());
        let input = match (config.loader)(fuzzer, self, path) {
            Ok(input) => input,
            Err(err) => {
                log::error!(
                    "Skipping input that we could not load from {}: {err:?}",
                    path.display()
                );
                return Ok(ExecuteInputResult::None);
            }
        };
        if config.forced {
            let _ = fuzzer.add_input(self, executor, manager, input)?;
            Ok(ExecuteInputResult::Corpus)
        } else {
            let (res, _) = fuzzer.evaluate_input(self, executor, manager, &input)?;
            if res == ExecuteInputResult::None {
                fuzzer.add_disabled_input(self, input)?;
                log::warn!(
                    "Input {} was not interesting, adding as disabled.",
                    path.display()
                );
            }
            Ok(res)
        }
    }
    /// Loads initial inputs from the passed-in `in_dirs`.
    /// This method takes a list of files and a `LoadConfig`
    /// which specifies the special handling of initial inputs
    fn continue_loading_initial_inputs_custom<E, EM, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        manager: &mut EM,
        mut config: LoadConfig<I, Self, Z>,
    ) -> Result<(), Error>
    where
        EM: EventFirer<I, Self>,
        Z: Evaluator<E, EM, I, Self>,
    {
        loop {
            match self.next_file() {
                Ok(path) => {
                    let res = self.load_file(&path, manager, fuzzer, executor, &mut config)?;
                    if config.exit_on_solution && matches!(res, ExecuteInputResult::Solution) {
                        return Err(Error::invalid_corpus(format!(
                            "Input {} resulted in a solution.",
                            path.display()
                        )));
                    }
                }
                Err(Error::IteratorEnd(_, _)) => break,
                Err(e) => return Err(e),
            }
        }

        manager.fire(
            self,
            EventWithStats::with_current_time(
                Event::Log {
                    severity_level: LogSeverity::Debug,
                    message: format!("Loaded {} initial testcases.", self.corpus().count()), // get corpus count
                    phantom: PhantomData::<I>,
                },
                *self.executions(),
            ),
        )?;
        Ok(())
    }

    /// Recursively walk supplied corpus directories
    pub fn walk_initial_inputs<F>(
        &mut self,
        in_dirs: &[PathBuf],
        mut closure: F,
    ) -> Result<(), Error>
    where
        F: FnMut(&PathBuf) -> Result<(), Error>,
    {
        self.canonicalize_input_dirs(in_dirs)?;
        loop {
            match self.next_file() {
                Ok(path) => {
                    closure(&path)?;
                }
                Err(Error::IteratorEnd(_, _)) => break,
                Err(e) => return Err(e),
            }
        }
        self.reset_initial_files_state();
        Ok(())
    }
    /// Loads all intial inputs, even if they are not considered `interesting`.
    /// This is rarely the right method, use `load_initial_inputs`,
    /// and potentially fix your `Feedback`, instead.
    /// This method takes a list of files, instead of folders.
    pub fn load_initial_inputs_by_filenames<E, EM, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        manager: &mut EM,
        file_list: &[PathBuf],
    ) -> Result<(), Error>
    where
        EM: EventFirer<I, Self>,
        Z: Evaluator<E, EM, I, Self>,
    {
        self.load_initial_inputs_custom_by_filenames(
            fuzzer,
            executor,
            manager,
            file_list,
            LoadConfig {
                loader: &mut |_, _, path| I::from_file(path),
                forced: false,
                exit_on_solution: false,
            },
        )
    }

    /// Loads all intial inputs, even if they are not considered `interesting`.
    /// This is rarely the right method, use `load_initial_inputs`,
    /// and potentially fix your `Feedback`, instead.
    pub fn load_initial_inputs_forced<E, EM, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        manager: &mut EM,
        in_dirs: &[PathBuf],
    ) -> Result<(), Error>
    where
        EM: EventFirer<I, Self>,
        Z: Evaluator<E, EM, I, Self>,
    {
        self.canonicalize_input_dirs(in_dirs)?;
        self.continue_loading_initial_inputs_custom(
            fuzzer,
            executor,
            manager,
            LoadConfig {
                loader: &mut |_, _, path| I::from_file(path),
                forced: true,
                exit_on_solution: false,
            },
        )
    }
    /// Loads initial inputs from the passed-in `in_dirs`.
    /// If `forced` is true, will add all testcases, no matter what.
    /// This method takes a list of files, instead of folders.
    pub fn load_initial_inputs_by_filenames_forced<E, EM, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        manager: &mut EM,
        file_list: &[PathBuf],
    ) -> Result<(), Error>
    where
        EM: EventFirer<I, Self>,
        Z: Evaluator<E, EM, I, Self>,
    {
        self.load_initial_inputs_custom_by_filenames(
            fuzzer,
            executor,
            manager,
            file_list,
            LoadConfig {
                loader: &mut |_, _, path| I::from_file(path),
                forced: true,
                exit_on_solution: false,
            },
        )
    }

    /// Loads initial inputs from the passed-in `in_dirs`.
    pub fn load_initial_inputs<E, EM, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        manager: &mut EM,
        in_dirs: &[PathBuf],
    ) -> Result<(), Error>
    where
        EM: EventFirer<I, Self>,
        Z: Evaluator<E, EM, I, Self>,
    {
        self.canonicalize_input_dirs(in_dirs)?;
        self.continue_loading_initial_inputs_custom(
            fuzzer,
            executor,
            manager,
            LoadConfig {
                loader: &mut |_, _, path| I::from_file(path),
                forced: false,
                exit_on_solution: false,
            },
        )
    }

    /// Loads initial inputs from the passed-in `in_dirs`.
    /// Will return a `CorpusError` if a solution is found
    pub fn load_initial_inputs_disallow_solution<E, EM, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        manager: &mut EM,
        in_dirs: &[PathBuf],
    ) -> Result<(), Error>
    where
        EM: EventFirer<I, Self>,
        Z: Evaluator<E, EM, I, Self>,
    {
        self.canonicalize_input_dirs(in_dirs)?;
        self.continue_loading_initial_inputs_custom(
            fuzzer,
            executor,
            manager,
            LoadConfig {
                loader: &mut |_, _, path| I::from_file(path),
                forced: false,
                exit_on_solution: true,
            },
        )
    }

    fn calculate_corpus_size(&mut self) -> Result<usize, Error> {
        let mut count: usize = 0;
        loop {
            match self.next_file() {
                Ok(_) => {
                    count = count.saturating_add(1);
                }
                Err(Error::IteratorEnd(_, _)) => break,
                Err(e) => return Err(e),
            }
        }
        Ok(count)
    }
    /// Loads initial inputs by dividing the from the passed-in `in_dirs`
    /// in a multicore fashion. Divides the corpus in chunks spread across cores.
    pub fn load_initial_inputs_multicore<E, EM, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        manager: &mut EM,
        in_dirs: &[PathBuf],
        core_id: &CoreId,
        cores: &Cores,
    ) -> Result<(), Error>
    where
        EM: EventFirer<I, Self>,
        Z: Evaluator<E, EM, I, Self>,
    {
        if self.multicore_inputs_processed.unwrap_or(false) {
            self.continue_loading_initial_inputs_custom(
                fuzzer,
                executor,
                manager,
                LoadConfig {
                    loader: &mut |_, _, path| I::from_file(path),
                    forced: false,
                    exit_on_solution: false,
                },
            )?;
        } else {
            self.canonicalize_input_dirs(in_dirs)?;
            let corpus_size = self.calculate_corpus_size()?;
            log::info!(
                "{} total_corpus_size, {} cores",
                corpus_size,
                cores.ids.len()
            );
            self.reset_initial_files_state();
            self.canonicalize_input_dirs(in_dirs)?;
            if cores.ids.len() > corpus_size {
                log::info!("low intial corpus count ({corpus_size}), no parallelism required.");
            } else {
                let core_index = cores
                    .ids
                    .iter()
                    .enumerate()
                    .find(|(_, c)| *c == core_id)
                    .unwrap_or_else(|| panic!("core id {} not in cores list", core_id.0))
                    .0;
                let chunk_size = corpus_size.saturating_div(cores.ids.len());
                let mut skip = core_index.saturating_mul(chunk_size);
                let mut inputs_todo = chunk_size;
                let mut collected_inputs = Vec::new();
                log::info!(
                    "core = {}, core_index = {}, chunk_size = {}, skip = {}",
                    core_id.0,
                    core_index,
                    chunk_size,
                    skip
                );
                loop {
                    match self.next_file() {
                        Ok(path) => {
                            if skip != 0 {
                                skip = skip.saturating_sub(1);
                                continue;
                            }
                            if inputs_todo == 0 {
                                break;
                            }
                            collected_inputs.push(path);
                            inputs_todo = inputs_todo.saturating_sub(1);
                        }
                        Err(Error::IteratorEnd(_, _)) => break,
                        Err(e) => {
                            return Err(e);
                        }
                    }
                }
                self.remaining_initial_files = Some(collected_inputs);
            }
            self.multicore_inputs_processed = Some(true);
            return self
                .load_initial_inputs_multicore(fuzzer, executor, manager, in_dirs, core_id, cores);
        }
        Ok(())
    }
}

impl<C, I, R, SC> StdState<C, I, R, SC>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
    SC: Corpus<I>,
{
    fn generate_initial_internal<G, E, EM, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        generator: &mut G,
        manager: &mut EM,
        num: usize,
        forced: bool,
    ) -> Result<(), Error>
    where
        EM: EventFirer<I, Self>,
        G: Generator<I, Self>,
        Z: Evaluator<E, EM, I, Self>,
    {
        let mut added = 0;
        for _ in 0..num {
            let input = generator.generate(self)?;
            if forced {
                let _ = fuzzer.add_input(self, executor, manager, input)?;
                added += 1;
            } else {
                let (res, _) = fuzzer.evaluate_input(self, executor, manager, &input)?;
                if res != ExecuteInputResult::None {
                    added += 1;
                }
            }
        }
        manager.fire(
            self,
            EventWithStats::with_current_time(
                Event::Log {
                    severity_level: LogSeverity::Debug,
                    message: format!("Loaded {added} over {num} initial testcases"),
                    phantom: PhantomData,
                },
                *self.executions(),
            ),
        )?;
        Ok(())
    }

    /// Generate `num` initial inputs, using the passed-in generator and force the addition to corpus.
    pub fn generate_initial_inputs_forced<G, E, EM, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        generator: &mut G,
        manager: &mut EM,
        num: usize,
    ) -> Result<(), Error>
    where
        EM: EventFirer<I, Self>,
        G: Generator<I, Self>,
        Z: Evaluator<E, EM, I, Self>,
    {
        self.generate_initial_internal(fuzzer, executor, generator, manager, num, true)
    }

    /// Generate `num` initial inputs, using the passed-in generator.
    pub fn generate_initial_inputs<G, E, EM, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        generator: &mut G,
        manager: &mut EM,
        num: usize,
    ) -> Result<(), Error>
    where
        EM: EventFirer<I, Self>,
        G: Generator<I, Self>,
        Z: Evaluator<E, EM, I, Self>,
    {
        self.generate_initial_internal(fuzzer, executor, generator, manager, num, false)
    }
}

impl<C, I, R, SC> StdState<C, I, R, SC>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
    SC: Corpus<I>,
{
    /// Creates a new `State`, taking ownership of all of the individual components during fuzzing.
    pub fn new<F, O>(
        rand: R,
        corpus: C,
        solutions: SC,
        feedback: &mut F,
        objective: &mut O,
    ) -> Result<Self, Error>
    where
        F: StateInitializer<Self>,
        O: StateInitializer<Self>,
        C: Serialize + DeserializeOwned,
        SC: Serialize + DeserializeOwned,
    {
        let mut state = Self {
            rand,
            executions: 0,
            imported: 0,
            start_time: libafl_bolts::current_time(),
            metadata: SerdeAnyMap::default(),
            named_metadata: NamedSerdeAnyMap::default(),
            corpus,
            solutions,
            max_size: DEFAULT_MAX_SIZE,
            stop_requested: false,
            #[cfg(feature = "introspection")]
            introspection_stats: ClientPerfStats::new(),
            #[cfg(feature = "std")]
            remaining_initial_files: None,
            #[cfg(feature = "std")]
            dont_reenter: None,
            last_report_time: None,
            last_found_time: libafl_bolts::current_time(),
            corpus_id: None,
            stage_stack: StageStack::default(),
            execution_mode: ExecutionMode::Normal,
            current_inputs: Vec::new(),
            current_input_idx: 0,
            active_inputs: hashbrown::HashMap::new(),
            next_execution_id: 1,
            current_batch_start_id: 1,
            current_batch_tag: None,
            last_exit_kind: None,
            pending_exit_kind: None,
            pending_exec_time: None,
            phantom: PhantomData,
            #[cfg(feature = "std")]
            multicore_inputs_processed: None,
        };
        feedback.init_state(&mut state)?;
        objective.init_state(&mut state)?;
        Ok(state)
    }
}

impl StdState<InMemoryCorpus<NopInput>, NopInput, StdRand, InMemoryCorpus<NopInput>> {
    /// Create an empty [`StdState`] that has very minimal uses.
    /// Potentially good for testing.
    pub fn nop() -> Result<
        StdState<InMemoryCorpus<NopInput>, NopInput, StdRand, InMemoryCorpus<NopInput>>,
        Error,
    > {
        StdState::new(
            StdRand::with_seed(0),
            InMemoryCorpus::<NopInput>::new(),
            InMemoryCorpus::new(),
            &mut (),
            &mut (),
        )
    }
}

#[cfg(feature = "introspection")]
impl<C, I, R, SC> HasClientPerfMonitor for StdState<C, I, R, SC> {
    fn introspection_stats(&self) -> &ClientPerfStats {
        &self.introspection_stats
    }

    fn introspection_stats_mut(&mut self) -> &mut ClientPerfStats {
        &mut self.introspection_stats
    }
}

/// A very simple state without any bells or whistles, for testing.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NopState<I> {
    metadata: SerdeAnyMap,
    named_metadata: NamedSerdeAnyMap,
    execution: u64,
    stop_requested: bool,
    rand: StdRand,
    current_inputs: Vec<I>,
    phantom: PhantomData<I>,
}

impl<I> NopState<I> {
    /// Create a new State that does nothing (for tests)
    #[must_use]
    pub fn new() -> Self {
        NopState {
            metadata: SerdeAnyMap::new(),
            named_metadata: NamedSerdeAnyMap::new(),
            execution: 0,
            rand: StdRand::default(),
            stop_requested: false,
            current_inputs: Vec::new(),
            phantom: PhantomData,
        }
    }
}

impl<I> HasMaxSize for NopState<I> {
    fn max_size(&self) -> usize {
        16_384
    }

    fn set_max_size(&mut self, _max_size: usize) {
        unimplemented!("NopState doesn't allow setting a max size")
    }
}

impl<I> HasCorpus<I> for NopState<I> {
    type Corpus = InMemoryCorpus<I>;

    fn corpus(&self) -> &Self::Corpus {
        unimplemented!("Unimplemented for NopState!");
    }

    fn corpus_mut(&mut self) -> &mut Self::Corpus {
        unimplemented!("Unimplemented for No[State!");
    }
}

impl<I> HasExecutions for NopState<I> {
    fn executions(&self) -> &u64 {
        &self.execution
    }

    fn executions_mut(&mut self) -> &mut u64 {
        &mut self.execution
    }
}

impl<I> Stoppable for NopState<I> {
    fn request_stop(&mut self) {
        self.stop_requested = true;
    }

    fn discard_stop_request(&mut self) {
        self.stop_requested = false;
    }

    fn stop_requested(&self) -> bool {
        self.stop_requested
    }
}

impl<I> HasLastReportTime for NopState<I> {
    fn last_report_time(&self) -> &Option<Duration> {
        unimplemented!();
    }

    fn last_report_time_mut(&mut self) -> &mut Option<Duration> {
        unimplemented!();
    }
}

impl<I> HasMetadata for NopState<I> {
    fn metadata_map(&self) -> &SerdeAnyMap {
        &self.metadata
    }

    fn metadata_map_mut(&mut self) -> &mut SerdeAnyMap {
        &mut self.metadata
    }
}

impl<I> HasNamedMetadata for NopState<I> {
    fn named_metadata_map(&self) -> &NamedSerdeAnyMap {
        &self.named_metadata
    }

    fn named_metadata_map_mut(&mut self) -> &mut NamedSerdeAnyMap {
        &mut self.named_metadata
    }
}

impl<I> HasRand for NopState<I> {
    type Rand = StdRand;

    fn rand(&self) -> &Self::Rand {
        &self.rand
    }

    fn rand_mut(&mut self) -> &mut Self::Rand {
        &mut self.rand
    }
}

impl<I> HasCurrentCorpusId for NopState<I> {
    fn set_corpus_id(&mut self, _id: CorpusId) -> Result<(), Error> {
        Ok(())
    }

    fn clear_corpus_id(&mut self) -> Result<(), Error> {
        Ok(())
    }

    fn current_corpus_id(&self) -> Result<Option<CorpusId>, Error> {
        Ok(None)
    }
}

impl<I: Input + Clone> HasCurrentInputs<I> for NopState<I> {
    fn current_inputs(&self) -> &[I] {
        &self.current_inputs
    }
    fn current_inputs_mut(&mut self) -> &mut Vec<I> {
        &mut self.current_inputs
    }
    fn current_input_idx(&self) -> usize {
        0
    }
    fn set_current_input_idx(&mut self, _idx: usize) {}
    fn set_current_inputs(&mut self, _inputs: Vec<I>) {}
    fn set_current_inputs_slice(&mut self, _inputs: &[I]) {}
    fn clear_current_inputs(&mut self) {}
}

impl<I: Input + Clone> HasInFlightExecutions<I> for NopState<I> {
    fn current_batch_start_id(&self) -> u64 {
        0
    }
    fn set_current_batch_start_id(&mut self, _start_id: u64) {}
    fn current_batch_tag(&self) -> Option<ExecutionTag> {
        None
    }
    fn set_current_batch_tag(&mut self, _tag: Option<ExecutionTag>) {}
    fn next_execution_id(&mut self) -> u64 {
        0
    }
    fn allocate_execution_ids(&mut self, _count: usize) -> u64 {
        0
    }
    fn insert_active_input(&mut self, _id: u64, _input: I) {}
    fn take_active_input(&mut self, _id: u64) -> Option<I> {
        None
    }
    fn active_inputs_count(&self) -> usize {
        0
    }
    fn clear_active_inputs(&mut self) {}
    fn pending_exit_kind(&self) -> Option<ExitKind> {
        None
    }
    fn set_pending_exit_kind(&mut self, _exit_kind: Option<ExitKind>) {}
    fn pending_exec_time(&self) -> Option<Duration> {
        None
    }
    fn set_pending_exec_time(&mut self, _exec_time: Option<Duration>) {}
}

impl<I> HasCurrentStageId for NopState<I> {
    fn set_current_stage_id(&mut self, _idx: StageId) -> Result<(), Error> {
        Ok(())
    }

    fn clear_stage_id(&mut self) -> Result<(), Error> {
        Ok(())
    }

    fn current_stage_id(&self) -> Result<Option<StageId>, Error> {
        Ok(None)
    }
}

#[cfg(feature = "introspection")]
impl<I> HasClientPerfMonitor for NopState<I> {
    fn introspection_stats(&self) -> &ClientPerfStats {
        unimplemented!();
    }

    fn introspection_stats_mut(&mut self) -> &mut ClientPerfStats {
        unimplemented!();
    }
}

#[cfg(test)]
mod test {
    use crate::state::StdState;

    #[test]
    fn test_std_state() {
        StdState::nop().expect("couldn't instantiate the test state");
    }
}
