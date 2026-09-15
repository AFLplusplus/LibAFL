//! The pure fuzzing engine architecture for `LibAFL`.
//!
//! Unlike the traditional fuzzer which drives the execution loop, the [`FuzzingEngine`] is a pure
//! step-based state machine. It takes the mutable state, event manager, and execution observations
//! from previously requested executions, processes feedback, and yields [`EngineStep`] instructions
//! (such as new inputs to execute with an optional mode tag).

use alloc::vec::Vec;
use core::fmt::Debug;

use libafl_bolts::{Error, current_time};
use serde::{Deserialize, Serialize};

use crate::{
    corpus::{Corpus, CorpusId, HasCurrentCorpusId, HasTestcase, Testcase},
    events::{Event, EventConfig, EventFirer, EventWithStats, SendExiting},
    executors::{ExitKind, HasObservers},
    feedbacks::Feedback,
    inputs::Input,
    observers::ObserversTuple,
    schedulers::Scheduler,
    stages::{StageStep, StagesTuple},
    state::{
        FuzzerState, HasCorpus, HasCurrentStageId, HasCurrentTestcase, HasExecutions,
        HasLastFoundTime, HasSolutions, Stoppable,
    },
};
pub use crate::{
    executors::target::{
        DualTargetExecutor, FuzzLoop, FuzzLoopStep, IntoTargetExecutor, StdTargetExecutor,
        TargetExecutor,
    },
    state::HasExecutionMode,
};

/// How a single input should be executed by the target executor.
///
/// This is the routing property carried by every [`ExecutionTag`]: it tells a
/// [`DualTargetExecutor`] (or any other mode-aware executor) *which* instrumented build of the
/// target an input belongs to. It is [`Copy`], allocation free and comparable in `const` context,
/// so it is cheap enough to live on the fuzzing hot path.
///
/// Downstream crates that need a mode which is not modelled here use
/// [`ExecutionMode::custom`], keeping their own `const` for the slot they own:
///
/// ```
/// use libafl::fuzzer::ExecutionMode;
///
/// const MY_INSTRUMENTATION: ExecutionMode = ExecutionMode::custom(0);
/// assert_ne!(MY_INSTRUMENTATION, ExecutionMode::Normal);
/// ```
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExecutionMode {
    /// The plain, coverage-instrumented target build.
    #[default]
    Normal,
    /// The `AFL++ CmpLog` instrumented build, recording comparison operands.
    CmpLog,
    /// A tracing build, recording a full execution trace.
    Tracing,
    /// An `AddressSanitizer` instrumented build.
    Asan,
    /// A concolic / symbolic execution build.
    Concolic,
    /// A re-execution used to confirm that a recorded timeout reproduces.
    VerifyTimeouts,
    /// A downstream-defined mode, identified by a slot the downstream crate owns.
    Custom(u16),
}

impl ExecutionMode {
    /// Marks a [`ExecutionMode::Custom`] slot in the [`ExecutionMode::to_raw`] encoding.
    const CUSTOM_RAW_TAG: u32 = 1 << 16;

    /// Create a downstream-defined execution mode from the slot it owns.
    #[must_use]
    pub const fn custom(slot: u16) -> Self {
        Self::Custom(slot)
    }

    /// Whether this is the plain, unmodified execution mode.
    #[must_use]
    pub const fn is_normal(self) -> bool {
        matches!(self, Self::Normal)
    }

    /// A stable integer encoding, for carrying the mode across a process or FFI boundary
    /// (shared memory, forkserver handshakes, ...). Round-trips through
    /// [`ExecutionMode::from_raw`].
    #[must_use]
    pub const fn to_raw(self) -> u32 {
        match self {
            Self::Normal => 0,
            Self::CmpLog => 1,
            Self::Tracing => 2,
            Self::Asan => 3,
            Self::Concolic => 4,
            Self::VerifyTimeouts => 5,
            Self::Custom(slot) => Self::CUSTOM_RAW_TAG | slot as u32,
        }
    }

    /// Decode an [`ExecutionMode::to_raw`] value, returning `None` for unknown encodings.
    #[must_use]
    pub const fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            0 => Some(Self::Normal),
            1 => Some(Self::CmpLog),
            2 => Some(Self::Tracing),
            3 => Some(Self::Asan),
            4 => Some(Self::Concolic),
            5 => Some(Self::VerifyTimeouts),
            _ if raw & Self::CUSTOM_RAW_TAG != 0
                && raw & !Self::CUSTOM_RAW_TAG <= u16::MAX as u32 =>
            {
                Some(Self::Custom((raw & !Self::CUSTOM_RAW_TAG) as u16))
            }
            _ => None,
        }
    }
}

impl core::fmt::Display for ExecutionMode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Normal => f.write_str("normal"),
            Self::CmpLog => f.write_str("cmplog"),
            Self::Tracing => f.write_str("tracing"),
            Self::Asan => f.write_str("asan"),
            Self::Concolic => f.write_str("concolic"),
            Self::VerifyTimeouts => f.write_str("verify_timeouts"),
            Self::Custom(slot) => write!(f, "custom({slot})"),
        }
    }
}

/// Uniquely identifies an in-flight execution task across stages, testcases, and batches,
/// and carries the properties (such as the [`ExecutionMode`]) the executor needs to run it.
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExecutionTag {
    /// Index of the generating stage
    pub stage_idx: usize,
    /// Corpus testcase ID this input was generated from (if any)
    pub corpus_id: Option<CorpusId>,
    /// Monotonic input ID
    pub input_id: u64,
    /// Monotonic batch ID
    pub batch_id: u64,
    /// How the tagged input must be executed.
    pub mode: ExecutionMode,
}

impl ExecutionTag {
    /// Create a new [`ExecutionTag`] running in [`ExecutionMode::Normal`].
    #[must_use]
    pub const fn new(stage_idx: usize, input_id: u64) -> Self {
        Self {
            stage_idx,
            corpus_id: None,
            input_id,
            batch_id: 0,
            mode: ExecutionMode::Normal,
        }
    }

    /// Create a new [`ExecutionTag`] with corpus ID and batch ID.
    #[must_use]
    pub const fn with_details(
        stage_idx: usize,
        corpus_id: Option<CorpusId>,
        input_id: u64,
        batch_id: u64,
    ) -> Self {
        Self {
            stage_idx,
            corpus_id,
            input_id,
            batch_id,
            mode: ExecutionMode::Normal,
        }
    }

    /// Return this tag, routed to the given [`ExecutionMode`].
    #[must_use]
    pub const fn with_mode(mut self, mode: ExecutionMode) -> Self {
        self.mode = mode;
        self
    }
}

/// Inputs container for an [`ExecutionRequest`], optimizing the common single-input case
/// to eliminate heap allocations in the fuzzing hot loop.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequestInputs<I> {
    /// A single input held inline without heap allocation.
    Single(I),
    /// A batch of multiple inputs on the heap.
    Batch(Vec<I>),
}

impl<I> RequestInputs<I> {
    /// Return the slice of inputs.
    #[inline]
    #[must_use]
    pub fn as_slice(&self) -> &[I] {
        match self {
            Self::Single(input) => core::slice::from_ref(input),
            Self::Batch(inputs) => inputs.as_slice(),
        }
    }

    /// Return the mutable slice of inputs.
    #[inline]
    #[must_use]
    pub fn as_mut_slice(&mut self) -> &mut [I] {
        match self {
            Self::Single(input) => core::slice::from_mut(input),
            Self::Batch(inputs) => inputs.as_mut_slice(),
        }
    }

    /// Return the number of inputs.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            Self::Single(_) => 1,
            Self::Batch(inputs) => inputs.len(),
        }
    }

    /// Return `true` if empty.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        match self {
            Self::Single(_) => false,
            Self::Batch(inputs) => inputs.is_empty(),
        }
    }

    /// Return an iterator over borrowed inputs.
    #[inline]
    pub fn iter(&self) -> core::slice::Iter<'_, I> {
        self.as_slice().iter()
    }

    /// Return an iterator over mutable borrowed inputs.
    #[inline]
    pub fn iter_mut(&mut self) -> core::slice::IterMut<'_, I> {
        self.as_mut_slice().iter_mut()
    }

    /// Convert into an owned `Vec<I>`.
    #[must_use]
    pub fn into_vec(self) -> Vec<I> {
        match self {
            Self::Single(input) => alloc::vec![input],
            Self::Batch(inputs) => inputs,
        }
    }
}

impl<I> core::ops::Deref for RequestInputs<I> {
    type Target = [I];

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl<I> core::ops::DerefMut for RequestInputs<I> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut_slice()
    }
}

impl<'a, I> IntoIterator for &'a RequestInputs<I> {
    type Item = &'a I;
    type IntoIter = core::slice::Iter<'a, I>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a, I> IntoIterator for &'a mut RequestInputs<I> {
    type Item = &'a mut I;
    type IntoIter = core::slice::IterMut<'a, I>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter_mut()
    }
}

impl<I> IntoIterator for RequestInputs<I> {
    type Item = I;
    type IntoIter = RequestInputsIntoIter<I>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        match self {
            Self::Single(input) => RequestInputsIntoIter::Single(Some(input)),
            Self::Batch(inputs) => RequestInputsIntoIter::Batch(inputs.into_iter()),
        }
    }
}

/// Consuming iterator over [`RequestInputs`].
#[derive(Debug)]
pub enum RequestInputsIntoIter<I> {
    /// Iterator over a single inline input.
    Single(Option<I>),
    /// Iterator over a batch of inputs.
    Batch(alloc::vec::IntoIter<I>),
}

impl<I> Iterator for RequestInputsIntoIter<I> {
    type Item = I;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Single(opt) => opt.take(),
            Self::Batch(iter) => iter.next(),
        }
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            Self::Single(opt) => {
                let len = usize::from(opt.is_some());
                (len, Some(len))
            }
            Self::Batch(iter) => iter.size_hint(),
        }
    }
}

impl<I> ExactSizeIterator for RequestInputsIntoIter<I> {}

impl<I> From<I> for RequestInputs<I> {
    #[inline]
    fn from(input: I) -> Self {
        Self::Single(input)
    }
}

impl<I> From<Vec<I>> for RequestInputs<I> {
    #[inline]
    fn from(mut inputs: Vec<I>) -> Self {
        if inputs.len() == 1 {
            Self::Single(inputs.pop().unwrap())
        } else {
            Self::Batch(inputs)
        }
    }
}

impl<I> From<RequestInputs<I>> for Vec<I> {
    #[inline]
    fn from(inputs: RequestInputs<I>) -> Self {
        inputs.into_vec()
    }
}

impl<I: PartialEq> PartialEq<[I]> for RequestInputs<I> {
    #[inline]
    fn eq(&self, other: &[I]) -> bool {
        self.as_slice() == other
    }
}

impl<I: PartialEq> PartialEq<RequestInputs<I>> for [I] {
    #[inline]
    fn eq(&self, other: &RequestInputs<I>) -> bool {
        self == other.as_slice()
    }
}

impl<I: PartialEq> PartialEq<Vec<I>> for RequestInputs<I> {
    #[inline]
    fn eq(&self, other: &Vec<I>) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl<I: PartialEq> PartialEq<RequestInputs<I>> for Vec<I> {
    #[inline]
    fn eq(&self, other: &RequestInputs<I>) -> bool {
        self.as_slice() == other.as_slice()
    }
}

/// Request yielded by the fuzzing engine to the runner/executor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionRequest<I> {
    /// Batch of 1..N inputs to execute (inline for single inputs to eliminate heap allocation).
    pub inputs: RequestInputs<I>,
    /// Optional starting execution ID for this batch of inputs (for correlating out-of-order async executions).
    pub start_id: Option<u64>,
    /// Optional structured execution tag, carrying the [`ExecutionMode`] these inputs run in.
    pub tag: Option<ExecutionTag>,
}

impl<I> ExecutionRequest<I> {
    /// The [`ExecutionMode`] these inputs must be executed in.
    #[must_use]
    pub fn mode(&self) -> ExecutionMode {
        self.tag.map_or(ExecutionMode::Normal, |tag| tag.mode)
    }

    /// Route this request to the given [`ExecutionMode`], creating a tag if it has none.
    #[must_use]
    pub fn with_mode(mut self, mode: ExecutionMode) -> Self {
        self.tag.get_or_insert_default().mode = mode;
        self
    }

    /// Create a new execution request with an explicit starting ID.
    #[must_use]
    pub fn with_id(start_id: u64, inputs: Vec<I>) -> Self {
        Self {
            inputs: RequestInputs::from(inputs),
            start_id: Some(start_id),
            tag: None,
        }
    }

    /// Create a new execution request with an explicit tag.
    #[must_use]
    pub fn with_tag(tag: ExecutionTag, inputs: Vec<I>) -> Self {
        Self {
            start_id: Some(tag.input_id),
            tag: Some(tag),
            inputs: RequestInputs::from(inputs),
        }
    }

    /// Create a new execution request for a single input without heap allocation.
    #[must_use]
    pub fn single(input: I) -> Self {
        Self {
            inputs: RequestInputs::Single(input),
            start_id: None,
            tag: None,
        }
    }

    /// Create a new standard execution request for a batch of inputs.
    #[must_use]
    pub fn batch(inputs: Vec<I>) -> Self {
        Self {
            inputs: RequestInputs::from(inputs),
            start_id: None,
            tag: None,
        }
    }
}

impl<I> From<I> for ExecutionRequest<I> {
    fn from(input: I) -> Self {
        Self::single(input)
    }
}

impl<I> From<Vec<I>> for ExecutionRequest<I> {
    fn from(inputs: Vec<I>) -> Self {
        Self::batch(inputs)
    }
}

impl<I> From<RequestInputs<I>> for ExecutionRequest<I> {
    fn from(inputs: RequestInputs<I>) -> Self {
        Self {
            inputs,
            start_id: None,
            tag: None,
        }
    }
}

/// Observations collected by the executor for a single executed input.
#[derive(Debug, Clone)]
pub struct ExecutionObservation<OT> {
    /// Exit status of the target execution.
    pub exit_kind: ExitKind,
    /// Observers populated during target execution.
    pub observers: OT,
    /// Optional execution / request ID for correlating out-of-order async executions.
    pub id: Option<u64>,
    /// Optional structured execution tag for routing.
    pub tag: Option<ExecutionTag>,
    /// Optional execution duration measured by the target executor.
    pub exec_time: Option<core::time::Duration>,
}

impl<OT> ExecutionObservation<OT> {
    /// Create a new execution observation without explicit ID (matched positionally).
    #[must_use]
    pub fn new(exit_kind: ExitKind, observers: OT) -> Self {
        Self {
            exit_kind,
            observers,
            id: None,
            tag: None,
            exec_time: None,
        }
    }

    /// Create a new execution observation with an explicit execution / request ID.
    #[must_use]
    pub fn with_id(id: u64, exit_kind: ExitKind, observers: OT) -> Self {
        Self {
            exit_kind,
            observers,
            id: Some(id),
            tag: None,
            exec_time: None,
        }
    }

    /// Create a new execution observation with an explicit execution tag.
    #[must_use]
    pub fn with_tag(tag: ExecutionTag, exit_kind: ExitKind, observers: OT) -> Self {
        Self {
            exit_kind,
            observers,
            id: Some(tag.input_id),
            tag: Some(tag),
            exec_time: None,
        }
    }

    /// Attach an explicit execution duration to this observation.
    #[must_use]
    pub const fn with_exec_time(mut self, exec_time: core::time::Duration) -> Self {
        self.exec_time = Some(exec_time);
        self
    }

    /// Attach an explicit ID and optional stage tag to this observation.
    #[must_use]
    pub const fn with_id_and_tag(mut self, id: u64, tag: Option<ExecutionTag>) -> Self {
        self.id = Some(id);
        self.tag = tag;
        self
    }

    /// Create a zero-copy [`BorrowedObservation`] referencing this observation and a borrowed input.
    #[must_use]
    pub const fn as_borrowed<'a, I>(&'a self, input: &'a I) -> BorrowedObservation<'a, I, OT> {
        BorrowedObservation {
            input,
            observers: &self.observers,
            exit_kind: self.exit_kind,
            id: self.id,
            tag: self.tag,
            exec_time: self.exec_time,
        }
    }
}

/// A zero-copy borrowed view of a single target execution outcome.
#[derive(Debug)]
pub struct BorrowedObservation<'a, I, OT> {
    /// The executed input.
    pub input: &'a I,
    /// The observers tuple recorded during execution.
    pub observers: &'a OT,
    /// The exit kind of the target execution.
    pub exit_kind: ExitKind,
    /// Optional execution ID.
    pub id: Option<u64>,
    /// Optional execution tag.
    pub tag: Option<ExecutionTag>,
    /// Optional execution duration measured by the target executor.
    pub exec_time: Option<core::time::Duration>,
}

impl<I, OT> BorrowedObservation<'_, I, OT> {
    /// Attach an explicit execution duration to this borrowed observation.
    #[must_use]
    pub const fn with_exec_time(mut self, exec_time: core::time::Duration) -> Self {
        self.exec_time = Some(exec_time);
        self
    }
}

impl<I, OT> Copy for BorrowedObservation<'_, I, OT> {}

impl<I, OT> Clone for BorrowedObservation<'_, I, OT> {
    fn clone(&self) -> Self {
        *self
    }
}

/// An input handed out for asynchronous/parallel execution with its unique handle (`id`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledInput<I> {
    /// Unique handle (`ExecutionId`) identifying this in-flight execution.
    pub id: u64,
    /// Optional stage routing tag.
    pub tag: Option<ExecutionTag>,
    /// The input to execute.
    pub input: I,
}

impl<I> ScheduledInput<I> {
    /// Create a new [`ScheduledInput`] with `Normal` mode and no stage tag.
    #[must_use]
    pub const fn new(id: u64, input: I) -> Self {
        Self {
            id,
            tag: None,
            input,
        }
    }

    /// Create a new [`ScheduledInput`] with an explicit [`ExecutionMode`].
    #[must_use]
    pub const fn with_mode(id: u64, input: I, mode: ExecutionMode) -> Self {
        Self {
            id,
            tag: Some(ExecutionTag::new(0, id).with_mode(mode)),
            input,
        }
    }

    /// The [`ExecutionMode`] this input must be executed in.
    #[must_use]
    pub fn mode(&self) -> ExecutionMode {
        self.tag.map_or(ExecutionMode::Normal, |tag| tag.mode)
    }
}

/// The result of harness execution evaluation.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum PushExecuteResult {
    /// No special feedback triggered.
    None,
    /// This input should be stored in the corpus.
    Corpus(CorpusId),
    /// This input led to an objective solution (e.g. crash).
    Solution(CorpusId),
}

/// The step result returned by the pure fuzzing engine.
#[derive(Debug, Clone)]
pub enum EngineStep<I> {
    /// The engine requires the harness to run the given inputs.
    Execute(ExecutionRequest<I>),
    /// A stage or testcase completed; ready for next cycle.
    Progress,
    /// Campaign finished or stop requested.
    Completed,
}

/// Pure Fuzzing Engine Trait
pub trait FuzzingEngine<EM, I, OT, S> {
    /// Advance the fuzzer state machine.
    ///
    /// Queries the scheduler and active stage and generates the next batch of execution requests.
    fn step(&mut self, state: &mut S, manager: &mut EM) -> Result<EngineStep<I>, Error>;

    /// Process a batch of execution observations directly against feedbacks, objectives, and stages.
    fn report_observations(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        observations: &[ExecutionObservation<OT>],
    ) -> Result<(), Error>;

    /// Notify the active stage's `post_exec` after an in-process crash/timeout restart without
    /// re-evaluating objectives.
    fn post_exec_after_restart(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        observation: BorrowedObservation<'_, I, OT>,
    ) -> Result<(), Error>;

    /// Process a single execution observation immediately after target execution completes,
    /// without allocating or cloning the observers tuple.
    fn process_execution(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        observation: BorrowedObservation<'_, I, OT>,
    ) -> Result<(), Error>;

    // ---------------------------------------------------------------------------------------
    // The "machine" interface: ask for inputs, hand back observations.
    //
    // Everything below is derived from [`FuzzingEngine::step`] and
    // [`FuzzingEngine::report_observations`], so engines only implement those two and get the
    // whole pull/report protocol -- including out-of-order completion -- for free.
    // ---------------------------------------------------------------------------------------

    /// Pull the next scheduled input for execution, tagged with its unique handle (`id`).
    ///
    /// Automatically advances stages and corpus scheduling across boundaries. Returns `Ok(None)`
    /// when the campaign finishes or stop is requested.
    fn next(&mut self, state: &mut S, manager: &mut EM) -> Result<Option<ScheduledInput<I>>, Error>
    where
        I: Clone,
        S: FuzzerState<I>,
    {
        let curr_idx = state.current_input_idx();
        if curr_idx < state.current_inputs().len() {
            state.set_current_input_idx(curr_idx + 1);
            let id = state.current_batch_start_id() + curr_idx as u64;
            return Ok(Some(Self::take_scheduled_input(state, id, curr_idx)));
        }

        loop {
            match self.step(state, manager)? {
                EngineStep::Execute(req) => {
                    let start_id = req.start_id.unwrap_or(state.current_batch_start_id());
                    state.set_current_batch_start_id(start_id);
                    state.set_current_batch_tag(req.tag);
                    if state.current_inputs().is_empty() {
                        continue;
                    }
                    // `self.step()` already populated `state.current_inputs()` for crash resumption
                    // and returned `req.inputs` by value. Move `req.inputs` directly into
                    // `state.active_inputs` instead of dropping it, eliminating the redundant clone
                    // when `take_scheduled_input` hands out items from this batch.
                    // Only the input actually handed out right now (`idx = 0`) becomes active;
                    // any remaining items stay staged in `state.current_inputs()` until `next()`
                    // hands them out.
                    match req.inputs {
                        RequestInputs::Single(input) => state.insert_active_input(start_id, input),
                        RequestInputs::Batch(inputs) => {
                            if let Some(first) = inputs.into_iter().next() {
                                state.insert_active_input(start_id, first);
                            }
                        }
                    }
                    state.set_current_input_idx(1);
                    return Ok(Some(Self::take_scheduled_input(state, start_id, 0)));
                }
                EngineStep::Progress => {}
                EngineStep::Completed => return Ok(None),
            }
        }
    }

    /// Hand out the staged input at `idx` under handle `id`, recording it as in-flight so it
    /// survives the staging buffer being replaced by the next batch.
    #[doc(hidden)]
    fn take_scheduled_input(state: &mut S, id: u64, idx: usize) -> ScheduledInput<I>
    where
        I: Clone,
        S: FuzzerState<I>,
    {
        let input = state.current_inputs()[idx].clone();
        let tag = state.current_batch_tag().map(|tag| ExecutionTag {
            input_id: id,
            ..tag
        });
        if !state.has_active_input(id) {
            state.insert_active_input(id, input.clone());
        }
        ScheduledInput { id, tag, input }
    }

    /// Pull up to `n` scheduled inputs for parallel execution, each tagged with its unique
    /// handle (`id`). Returns fewer than `n` (possibly none) once the campaign runs dry.
    fn next_n(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        n: usize,
    ) -> Result<Vec<ScheduledInput<I>>, Error>
    where
        I: Clone,
        S: FuzzerState<I>,
    {
        let mut batch = Vec::with_capacity(n);
        for _ in 0..n {
            match self.next(state, manager)? {
                Some(item) => batch.push(item),
                None => break,
            }
        }
        Ok(batch)
    }

    /// Report the execution outcome for a previously scheduled input (matched by handle `obs.id`).
    ///
    /// Evaluates objectives and feedbacks and retires `obs.id` from the in-flight table without
    /// advancing stage generation.
    fn report(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        obs: &ExecutionObservation<OT>,
    ) -> Result<(), Error> {
        self.report_observations(state, manager, core::slice::from_ref(obs))
    }

    /// Report a batch of completed execution observations (matched by handle `obs.id`) and
    /// return up to `completed.len()` new scheduled inputs to immediately refill the worker pool.
    fn report_batch(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        completed: &[ExecutionObservation<OT>],
    ) -> Result<Vec<ScheduledInput<I>>, Error>
    where
        I: Clone,
        S: FuzzerState<I>,
    {
        self.report_and_next(state, manager, completed, completed.len())
    }

    /// Report a batch of completed execution observations (matched by handle `obs.id`) and
    /// return up to `max_next` new scheduled inputs for execution.
    fn report_and_next(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        completed: &[ExecutionObservation<OT>],
        max_next: usize,
    ) -> Result<Vec<ScheduledInput<I>>, Error>
    where
        I: Clone,
        S: FuzzerState<I>,
    {
        self.report_observations(state, manager, completed)?;
        if max_next == 0 {
            Ok(Vec::new())
        } else {
            self.next_n(state, manager, max_next)
        }
    }

    /// Submit completed execution observations (matched by handle `obs.id`) and hand out up to
    /// `max_to_generate` new inputs with assigned handles, without waiting for other in-flight
    /// executions from previous batches to finish.
    fn replenish(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        completed: &[ExecutionObservation<OT>],
        max_to_generate: usize,
    ) -> Result<Vec<ScheduledInput<I>>, Error>
    where
        I: Clone,
        S: FuzzerState<I>,
    {
        self.report_and_next(state, manager, completed, max_to_generate)
    }

    /// Submit completed execution observations (matched by handle `obs.id`) and hand out new
    /// inputs until `target_in_flight` executions are active in parallel.
    fn replenish_to_target(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        completed: &[ExecutionObservation<OT>],
        target_in_flight: usize,
    ) -> Result<Vec<ScheduledInput<I>>, Error>
    where
        I: Clone,
        S: FuzzerState<I>,
    {
        if !completed.is_empty() {
            let _ = self.replenish(state, manager, completed, 0)?;
        }
        let needed = target_in_flight.saturating_sub(state.active_inputs_count());
        self.replenish(state, manager, &[], needed)
    }
}

/// The default fuzzer instance with push stages.
#[derive(Debug)]
pub struct StdFuzzer<
    CS,
    F,
    OF = (),
    ST = (),
    IC = crate::inputs::BytesInputConverter,
    IF = crate::fuzzer::NopInputFilter,
> {
    scheduler: CS,
    feedback: F,
    objective: OF,
    stages: ST,
    share_objectives: bool,
    target_bytes_converter: IC,
    input_filter: IF,
}

impl StdFuzzer<(), (), (), (), crate::inputs::BytesInputConverter, crate::fuzzer::NopInputFilter> {
    /// Creates a new [`StdFuzzerBuilder`](crate::fuzzer::StdFuzzerBuilder) with default types.
    #[must_use]
    pub fn builder() -> crate::fuzzer::StdFuzzerBuilder<
        (),
        (),
        crate::inputs::BytesInputConverter,
        crate::fuzzer::NopInputFilter,
        (),
    > {
        crate::fuzzer::StdFuzzerBuilder::new()
    }
}

impl<CS, F, OF, ST, IC, IF> crate::fuzzer::HasObjective for StdFuzzer<CS, F, OF, ST, IC, IF> {
    type Objective = OF;

    fn objective(&self) -> &Self::Objective {
        &self.objective
    }

    fn objective_mut(&mut self) -> &mut Self::Objective {
        &mut self.objective
    }

    fn share_objectives(&self) -> bool {
        self.share_objectives
    }

    fn set_share_objectives(&mut self, share_objectives: bool) {
        self.share_objectives = share_objectives;
    }
}

impl<CS, F, OF, ST, IC, IF> crate::fuzzer::HasFeedback for StdFuzzer<CS, F, OF, ST, IC, IF> {
    type Feedback = F;

    fn feedback(&self) -> &Self::Feedback {
        &self.feedback
    }

    fn feedback_mut(&mut self) -> &mut Self::Feedback {
        &mut self.feedback
    }
}

impl<CS, F, OF, ST, IC, IF> crate::fuzzer::HasToTargetBytesConverter
    for StdFuzzer<CS, F, OF, ST, IC, IF>
{
    type Converter = IC;

    fn target_bytes_converter(&self) -> &Self::Converter {
        &self.target_bytes_converter
    }

    fn target_bytes_converter_mut(&mut self) -> &mut Self::Converter {
        &mut self.target_bytes_converter
    }
}

impl<CS, F, I, OF, S, ST, IC, IF> crate::fuzzer::HasScheduler<I, S>
    for StdFuzzer<CS, F, OF, ST, IC, IF>
where
    CS: Scheduler<I, S>,
{
    type Scheduler = CS;

    fn scheduler(&self) -> &Self::Scheduler {
        &self.scheduler
    }

    fn scheduler_mut(&mut self) -> &mut Self::Scheduler {
        &mut self.scheduler
    }
}

impl<CS, F, OF, ST>
    StdFuzzer<CS, F, OF, ST, crate::inputs::BytesInputConverter, crate::fuzzer::NopInputFilter>
{
    /// Create a new [`StdFuzzer`] with the default [`BytesInputConverter`](crate::inputs::BytesInputConverter).
    pub fn new(scheduler: CS, feedback: F, objective: OF, stages: ST) -> Self {
        Self::with_converter(
            scheduler,
            feedback,
            objective,
            stages,
            crate::inputs::BytesInputConverter::new(),
        )
    }
}

impl<CS, F, OF, ST, IC> StdFuzzer<CS, F, OF, ST, IC, crate::fuzzer::NopInputFilter> {
    /// Create a new [`StdFuzzer`] with a custom [`ToTargetBytesConverter`](crate::inputs::ToTargetBytesConverter).
    pub fn with_converter(
        scheduler: CS,
        feedback: F,
        objective: OF,
        stages: ST,
        target_bytes_converter: IC,
    ) -> Self {
        Self {
            scheduler,
            feedback,
            objective,
            stages,
            share_objectives: false,
            target_bytes_converter,
            input_filter: crate::fuzzer::NopInputFilter,
        }
    }
}

impl<CS, F, OF, ST, IC, IF> StdFuzzer<CS, F, OF, ST, IC, IF> {
    /// Replace the stages tuple in this [`StdFuzzer`], returning a new fuzzer instance with the new stages.
    #[must_use]
    pub fn with_stages<ST2>(self, stages: ST2) -> StdFuzzer<CS, F, OF, ST2, IC, IF> {
        StdFuzzer {
            scheduler: self.scheduler,
            feedback: self.feedback,
            objective: self.objective,
            stages,
            share_objectives: self.share_objectives,
            target_bytes_converter: self.target_bytes_converter,
            input_filter: self.input_filter,
        }
    }

    /// Replace the input filter, returning a new fuzzer instance with the new filter.
    #[must_use]
    pub fn with_input_filter<IF2>(self, input_filter: IF2) -> StdFuzzer<CS, F, OF, ST, IC, IF2> {
        StdFuzzer {
            scheduler: self.scheduler,
            feedback: self.feedback,
            objective: self.objective,
            stages: self.stages,
            share_objectives: self.share_objectives,
            target_bytes_converter: self.target_bytes_converter,
            input_filter,
        }
    }

    /// Access the scheduler.
    pub fn scheduler(&self) -> &CS {
        &self.scheduler
    }

    /// Access the scheduler (mutable).
    pub fn scheduler_mut(&mut self) -> &mut CS {
        &mut self.scheduler
    }

    /// Access the feedback.
    pub fn feedback(&self) -> &F {
        &self.feedback
    }

    /// Access the feedback (mutable).
    pub fn feedback_mut(&mut self) -> &mut F {
        &mut self.feedback
    }

    /// Access the objective.
    pub fn objective(&self) -> &OF {
        &self.objective
    }

    /// Access the objective (mutable).
    pub fn objective_mut(&mut self) -> &mut OF {
        &mut self.objective
    }

    /// Access the stages.
    pub fn stages(&self) -> &ST {
        &self.stages
    }

    /// Access the stages (mutable).
    pub fn stages_mut(&mut self) -> &mut ST {
        &mut self.stages
    }

    /// Process a batch of execution observations directly against feedbacks and objectives.
    pub fn report_observations<EM, I, OT, S>(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        observations: &[ExecutionObservation<OT>],
    ) -> Result<(), Error>
    where
        CS: Scheduler<I, S>,
        EM: EventFirer<I, S> + SendExiting,
        F: Feedback<EM, I, OT, S>,
        I: Input + Clone,
        OF: Feedback<EM, I, OT, S>,
        OT: ObserversTuple<I, S> + Serialize + Debug,
        S: FuzzerState<I>,
        ST: StagesTuple<EM, I, OT, S>,
    {
        for (idx, obs) in observations.iter().enumerate() {
            let current_input = match obs.id {
                Some(id) => state.take_active_input(id).or_else(|| {
                    let offset = id.wrapping_sub(state.current_batch_start_id()) as usize;
                    if offset < state.current_inputs().len() {
                        state.current_inputs().get(offset).cloned()
                    } else {
                        None
                    }
                }),
                None => None,
            }
            .or_else(|| state.current_inputs().get(idx).cloned())
            .or_else(|| state.current_input_cloned().ok());

            if let Some(input) = current_input {
                Self::evaluate_borrowed_observation_parts(
                    &mut self.scheduler,
                    &mut self.feedback,
                    &mut self.objective,
                    &mut self.stages,
                    self.share_objectives,
                    state,
                    manager,
                    obs.as_borrowed(&input),
                )?;
            }
        }
        Ok(())
    }

    /// Pull the next scheduled input for execution, inferring `OT` from the executor.
    pub fn next_with_executor<E, EM, I, S>(
        &mut self,
        executor: &E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<Option<ScheduledInput<I>>, Error>
    where
        CS: Scheduler<I, S>,
        E: HasObservers,
        E::Observers: ObserversTuple<I, S> + Serialize + Debug,
        EM: EventFirer<I, S> + SendExiting,
        F: Feedback<EM, I, E::Observers, S>,
        I: Input + Clone,
        OF: Feedback<EM, I, E::Observers, S>,
        S: FuzzerState<I>,
        ST: StagesTuple<EM, I, E::Observers, S>,
    {
        FuzzLoop::reconcile_post_restart(self, &*executor.observers(), state, manager)?;
        FuzzingEngine::<EM, I, E::Observers, S>::next(self, state, manager)
    }

    /// Helper to evaluate and add initial generated inputs to the corpus via the pure engine.
    pub fn generate_initial_inputs<E, EM, G, I, OT, S>(
        &mut self,
        target_executor: &mut E,
        generator: &mut G,
        state: &mut S,
        manager: &mut EM,
        num: usize,
    ) -> Result<(), Error>
    where
        E: TargetExecutor<I, OT>,
        EM: EventFirer<I, S> + SendExiting,
        G: crate::generators::Generator<I, S>,
        I: Input + Clone,
        OT: ObserversTuple<I, S> + Serialize + Debug,
        S: FuzzerState<I>,
        CS: Scheduler<I, S>,
        F: Feedback<EM, I, OT, S>,
        OF: Feedback<EM, I, OT, S>,
        ST: StagesTuple<EM, I, OT, S>,
    {
        for _ in 0..num {
            let input = generator.generate(state)?;
            let obs = target_executor.execute_batch(core::slice::from_ref(&input))?;
            state.set_current_inputs(alloc::vec![input]);
            self.report_observations(state, manager, obs)?;
        }
        Ok(())
    }

    /// Helper to evaluate and add initial generated inputs to the corpus using a standard [`Executor`](crate::executors::Executor).
    pub fn generate_initial_inputs_with_executor<E, EM, G, I, S>(
        &mut self,
        executor: &mut E,
        generator: &mut G,
        state: &mut S,
        manager: &mut EM,
        num: usize,
    ) -> Result<(), Error>
    where
        E: HasObservers + crate::executors::Executor<EM, I, S, Self>,
        E::Observers: ObserversTuple<I, S> + Serialize + Debug,
        EM: EventFirer<I, S> + SendExiting,
        G: crate::generators::Generator<I, S>,
        I: Input + Clone,
        S: FuzzerState<I>,
        CS: Scheduler<I, S>,
        F: Feedback<EM, I, E::Observers, S>,
        OF: Feedback<EM, I, E::Observers, S>,
        ST: StagesTuple<EM, I, E::Observers, S>,
    {
        for _ in 0..num {
            let input = generator.generate(state)?;
            let exit_kind = executor.run_target(self, state, manager, &input)?;
            self.process_execution(
                state,
                manager,
                BorrowedObservation {
                    input: &input,
                    observers: &*executor.observers(),
                    exit_kind,
                    id: None,
                    tag: None,
                    exec_time: None,
                },
            )?;
        }
        Ok(())
    }

    /// Run the fuzz loop indefinitely with a standard [`Executor`](crate::executors::Executor).
    pub fn fuzz_loop<E, EM, I, S>(
        &mut self,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<(), Error>
    where
        E: HasObservers + crate::executors::Executor<EM, I, S, Self>,
        E::Observers: ObserversTuple<I, S> + Serialize + Debug,
        EM: EventFirer<I, S> + SendExiting,
        I: Input + Clone,
        S: FuzzerState<I> + crate::state::MaybeHasClientPerfMonitor,
        CS: Scheduler<I, S>,
        F: Feedback<EM, I, E::Observers, S>,
        OF: Feedback<EM, I, E::Observers, S>,
        ST: StagesTuple<EM, I, E::Observers, S>,
    {
        FuzzLoop::run_executor(self, executor, state, manager)
    }

    /// Run the fuzz loop for a given number of iterations with a standard [`Executor`](crate::executors::Executor).
    pub fn fuzz_loop_for<E, EM, I, S>(
        &mut self,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        iters: u64,
    ) -> Result<u64, Error>
    where
        E: HasObservers + crate::executors::Executor<EM, I, S, Self>,
        E::Observers: ObserversTuple<I, S> + Serialize + Debug,
        EM: EventFirer<I, S> + SendExiting,
        I: Input + Clone,
        S: FuzzerState<I> + crate::state::MaybeHasClientPerfMonitor,
        CS: Scheduler<I, S>,
        F: Feedback<EM, I, E::Observers, S>,
        OF: Feedback<EM, I, E::Observers, S>,
        ST: StagesTuple<EM, I, E::Observers, S>,
    {
        FuzzLoop::run_executor_for(self, executor, state, manager, iters)
    }

    /// Run a single iteration of the fuzz loop with a standard [`Executor`](crate::executors::Executor).
    pub fn fuzz_one<E, EM, I, S>(
        &mut self,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<u64, Error>
    where
        E: HasObservers + crate::executors::Executor<EM, I, S, Self>,
        E::Observers: ObserversTuple<I, S> + Serialize + Debug,
        EM: EventFirer<I, S> + SendExiting,
        I: Input + Clone,
        S: FuzzerState<I> + crate::state::MaybeHasClientPerfMonitor,
        CS: Scheduler<I, S>,
        F: Feedback<EM, I, E::Observers, S>,
        OF: Feedback<EM, I, E::Observers, S>,
        ST: StagesTuple<EM, I, E::Observers, S>,
    {
        self.fuzz_loop_for(executor, state, manager, 1)
    }

    /// Evaluate a single borrowed observation against objective and corpus feedbacks and route `post_exec`.
    #[allow(clippy::too_many_arguments)]
    fn evaluate_borrowed_observation_parts<EM, I, OT, S>(
        scheduler: &mut CS,
        feedback: &mut F,
        objective: &mut OF,
        stages: &mut ST,
        share_objectives: bool,
        state: &mut S,
        manager: &mut EM,
        obs: BorrowedObservation<'_, I, OT>,
    ) -> Result<(), Error>
    where
        CS: Scheduler<I, S>,
        EM: EventFirer<I, S> + SendExiting,
        F: Feedback<EM, I, OT, S>,
        I: Input + Clone,
        OF: Feedback<EM, I, OT, S>,
        OT: ObserversTuple<I, S> + Serialize + Debug,
        S: FuzzerState<I>,
        ST: StagesTuple<EM, I, OT, S>,
    {
        *state.executions_mut() += 1;

        let is_solution =
            objective.is_interesting(state, manager, obs.input, obs.observers, &obs.exit_kind)?;

        if is_solution {
            let owned_input = obs.input.clone();
            let mut testcase = Testcase::from(owned_input.clone());
            testcase.set_parent_id_optional(*state.corpus().current());
            if let Ok(mut tc) = state.current_testcase_mut() {
                tc.found_objective();
            }
            #[cfg(feature = "track_hit_feedbacks")]
            objective.append_hit_feedbacks(testcase.hit_objectives_mut())?;
            objective.append_metadata(state, manager, obs.observers, &mut testcase)?;
            let _id = state.solutions_mut().add(testcase)?;

            *state.last_found_time_mut() = current_time();

            if manager.should_send() {
                manager.fire(
                    state,
                    EventWithStats::with_current_time(
                        Event::Objective {
                            input: share_objectives.then_some(owned_input),
                            objective_size: state.solutions().count(),
                        },
                        *state.executions(),
                    ),
                )?;
            }
        } else {
            let is_corpus = feedback.is_interesting(
                state,
                manager,
                obs.input,
                obs.observers,
                &obs.exit_kind,
            )?;

            if is_corpus {
                let owned_input = obs.input.clone();
                let mut testcase = Testcase::from(owned_input.clone());
                testcase.set_parent_id_optional(*state.corpus().current());
                #[cfg(feature = "track_hit_feedbacks")]
                feedback.append_hit_feedbacks(testcase.hit_feedbacks_mut())?;
                feedback.append_metadata(state, manager, obs.observers, &mut testcase)?;
                let id = state.corpus_mut().add(testcase)?;
                scheduler.on_add(state, id)?;

                *state.last_found_time_mut() = current_time();

                if manager.should_send() {
                    let observers_buf = if manager.configuration() == EventConfig::AlwaysUnique {
                        None
                    } else {
                        Some(postcard::to_allocvec(obs.observers)?)
                    };

                    manager.fire(
                        state,
                        EventWithStats::with_current_time(
                            Event::NewTestcase {
                                input: owned_input,
                                observers_buf,
                                exit_kind: obs.exit_kind,
                                corpus_size: state.corpus().count(),
                                client_config: manager.configuration(),
                                forward_id: None,
                                #[cfg(all(unix, feature = "std", feature = "multi_machine"))]
                                node_id: None,
                            },
                            *state.executions(),
                        ),
                    )?;
                }
            }
        }

        if let Some(tag) = obs.tag {
            stages.post_exec_stage(tag.stage_idx, state, manager, obs)?;
        } else if let Ok(Some(stage_id)) = state.current_stage_id()
            && stage_id.0 > 0
        {
            stages.post_exec_stage(stage_id.0 - 1, state, manager, obs)?;
        }

        Ok(())
    }
}

impl<CS, F, OF>
    StdFuzzer<CS, F, OF, (), crate::inputs::BytesInputConverter, crate::fuzzer::NopInputFilter>
{
    /// Create a new [`StdFuzzer`] without stages.
    pub fn without_stages(scheduler: CS, feedback: F, objective: OF) -> Self {
        Self::new(scheduler, feedback, objective, ())
    }
}

impl<CS, F, OF, IC> StdFuzzer<CS, F, OF, (), IC, crate::fuzzer::NopInputFilter> {
    /// Create a new [`StdFuzzer`] without stages and with a custom converter.
    pub fn without_stages_with_converter(
        scheduler: CS,
        feedback: F,
        objective: OF,
        target_bytes_converter: IC,
    ) -> Self {
        Self::with_converter(scheduler, feedback, objective, (), target_bytes_converter)
    }
}

impl<CS, EM, F, I, OF, OT, S, ST, IC, IF> FuzzingEngine<EM, I, OT, S>
    for StdFuzzer<CS, F, OF, ST, IC, IF>
where
    CS: Scheduler<I, S>,
    EM: EventFirer<I, S> + SendExiting,
    F: Feedback<EM, I, OT, S>,
    I: Input + Clone,
    OF: Feedback<EM, I, OT, S>,
    OT: ObserversTuple<I, S> + Serialize + Debug,
    S: FuzzerState<I>,
    ST: StagesTuple<EM, I, OT, S>,
{
    fn step(&mut self, state: &mut S, manager: &mut EM) -> Result<EngineStep<I>, Error> {
        let resume_idx = state.current_input_idx();
        if resume_idx > 0 && resume_idx < state.current_inputs().len() {
            let buf = state.current_inputs_mut();
            buf.drain(0..resume_idx);
            state.set_current_input_idx(0);
            let new_start_id = state.current_batch_start_id() + resume_idx as u64;
            state.set_current_batch_start_id(new_start_id);
            if let Some(mut tag) = state.current_batch_tag() {
                tag.input_id = new_start_id;
                state.set_current_batch_tag(Some(tag));
            }

            let req_inputs = if state.current_inputs().len() == 1 {
                RequestInputs::Single(state.current_inputs()[0].clone())
            } else {
                RequestInputs::Batch(state.current_inputs().to_vec())
            };
            let mut req = ExecutionRequest::from(req_inputs);
            req.start_id = Some(new_start_id);
            req.tag = state.current_batch_tag();
            return Ok(EngineStep::Execute(req));
        } else if resume_idx > 0 {
            state.clear_current_inputs();
        }

        // 1. Ensure we have a current corpus item scheduled
        let corpus_id = if let Some(id) = state.current_corpus_id()? {
            if state.current_stage_id()?.is_none() {
                self.stages.init_all(state, manager)?;
            }
            id
        } else {
            let id = self.scheduler.next(state)?;
            state.set_corpus_id(id)?;
            self.stages.init_all(state, manager)?;
            id
        };

        // 2. Advance stages with buffer reuse and execution ID tracking
        match self.stages.step_all(state, manager)? {
            StageStep::Execute(mut req) => {
                let start_id = state.allocate_execution_ids(req.inputs.len());
                req.start_id = Some(start_id);
                if let Some(ref mut tag) = req.tag {
                    tag.input_id = start_id;
                    tag.corpus_id = state.current_corpus_id().ok().flatten();
                }
                state.set_current_batch_start_id(start_id);
                state.set_current_batch_tag(req.tag);

                state.set_current_inputs_slice(&req.inputs);
                Ok(EngineStep::Execute(req))
            }
            StageStep::Done => {
                state.clear_current_inputs();
                self.stages.deinit_all(state, manager)?;

                if let Ok(mut tc) = state.testcase_mut(corpus_id) {
                    let scheduled = tc.scheduled_count();
                    tc.set_scheduled_count(scheduled + 1);
                }

                state.clear_corpus_id()?;

                if state.stop_requested() {
                    state.discard_stop_request();
                    manager.on_shutdown()?;
                    return Ok(EngineStep::Completed);
                }

                Ok(EngineStep::Progress)
            }
        }
    }

    fn report_observations(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        observations: &[ExecutionObservation<OT>],
    ) -> Result<(), Error> {
        StdFuzzer::report_observations(self, state, manager, observations)
    }

    fn post_exec_after_restart(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        mut observation: BorrowedObservation<'_, I, OT>,
    ) -> Result<(), Error> {
        let tag = observation.tag.or_else(|| {
            state.current_batch_tag().map(|mut t| {
                if let Some(id) = observation.id {
                    t.input_id = id;
                }
                t
            })
        });
        observation.tag = tag;
        let stage_idx = tag
            .map(|t| t.stage_idx)
            .or_else(|| state.current_stage_id().ok().flatten().map(|s| s.0));
        if let Some(s_idx) = stage_idx {
            self.stages
                .post_exec_stage(s_idx, state, manager, observation)?;
        }
        Ok(())
    }

    fn process_execution(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        observation: BorrowedObservation<'_, I, OT>,
    ) -> Result<(), Error> {
        if let Some(id) = observation.id {
            let _ = state.take_active_input(id);
        }
        Self::evaluate_borrowed_observation_parts(
            &mut self.scheduler,
            &mut self.feedback,
            &mut self.objective,
            &mut self.stages,
            self.share_objectives,
            state,
            manager,
            observation,
        )
    }
}

impl<CS, E, EM, F, I, IC, OF, S, ST, IF> crate::fuzzer::ExecutesInput<E, EM, I, S>
    for StdFuzzer<CS, F, OF, ST, IC, IF>
where
    CS: Scheduler<I, S>,
    E: crate::executors::Executor<EM, I, S, Self> + HasObservers,
    E::Observers: ObserversTuple<I, S>,
    S: HasExecutions + HasCorpus<I> + crate::state::MaybeHasClientPerfMonitor,
{
    fn execute_input(
        &mut self,
        state: &mut S,
        executor: &mut E,
        event_mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, Error> {
        #[cfg(feature = "introspection")]
        use crate::monitors::stats::PerfFeature;
        use crate::{mark_feature_time, start_timer};
        start_timer!(state);
        executor.observers_mut().pre_exec_all(state, input)?;
        mark_feature_time!(state, PerfFeature::PreExecObservers);

        start_timer!(state);
        let exit_kind = executor.run_target(self, state, event_mgr, input)?;
        mark_feature_time!(state, PerfFeature::TargetExecution);

        start_timer!(state);
        executor
            .observers_mut()
            .post_exec_all(state, input, &exit_kind)?;
        mark_feature_time!(state, PerfFeature::PostExecObservers);

        Ok(exit_kind)
    }
}

impl<CS, EM, F, I, IC, OF, OT, S, ST, IF> crate::fuzzer::ExecutionProcessor<EM, I, OT, S>
    for StdFuzzer<CS, F, OF, ST, IC, IF>
where
    CS: Scheduler<I, S>,
    EM: EventFirer<I, S>,
    F: Feedback<EM, I, OT, S>,
    I: Input,
    OF: Feedback<EM, I, OT, S>,
    OT: ObserversTuple<I, S> + Serialize,
    S: HasCorpus<I>
        + crate::state::MaybeHasClientPerfMonitor
        + HasExecutions
        + HasCurrentTestcase<I>
        + HasSolutions<I>
        + HasLastFoundTime,
{
    fn check_results(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        input: &I,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<crate::fuzzer::ExecuteInputResult, Error> {
        let mut res = crate::fuzzer::ExecuteInputResult::None;

        #[cfg(not(feature = "introspection"))]
        let is_solution = self
            .objective_mut()
            .is_interesting(state, manager, input, observers, exit_kind)?;

        #[cfg(feature = "introspection")]
        let is_solution = self
            .objective_mut()
            .is_interesting_introspection(state, manager, input, observers, exit_kind)?;

        if is_solution {
            res = crate::fuzzer::ExecuteInputResult::Solution;
        } else {
            #[cfg(not(feature = "introspection"))]
            let corpus_worthy = self
                .feedback_mut()
                .is_interesting(state, manager, input, observers, exit_kind)?;
            #[cfg(feature = "introspection")]
            let corpus_worthy = self
                .feedback_mut()
                .is_interesting_introspection(state, manager, input, observers, exit_kind)?;

            if corpus_worthy {
                res = crate::fuzzer::ExecuteInputResult::Corpus;
            }
        }
        Ok(res)
    }

    fn process_execution(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        input: &I,
        exec_res: &crate::fuzzer::ExecuteInputResult,
        _exit_kind: &ExitKind,
        observers: &OT,
    ) -> Result<Option<CorpusId>, Error> {
        match exec_res {
            crate::fuzzer::ExecuteInputResult::None => Ok(None),
            crate::fuzzer::ExecuteInputResult::Corpus => {
                let mut testcase = Testcase::from(input.clone());
                #[cfg(feature = "track_hit_feedbacks")]
                self.feedback_mut()
                    .append_hit_feedbacks(testcase.hit_feedbacks_mut())?;
                self.feedback_mut()
                    .append_metadata(state, manager, observers, &mut testcase)?;
                let id = state.corpus_mut().add(testcase)?;
                self.scheduler_mut().on_add(state, id)?;
                Ok(Some(id))
            }
            crate::fuzzer::ExecuteInputResult::Solution => {
                let mut testcase = Testcase::from(input.clone());
                testcase.set_parent_id_optional(*state.corpus().current());
                if let Ok(mut tc) = state.current_testcase_mut() {
                    tc.found_objective();
                }
                #[cfg(feature = "track_hit_feedbacks")]
                self.objective_mut()
                    .append_hit_feedbacks(testcase.hit_objectives_mut())?;
                self.objective_mut()
                    .append_metadata(state, manager, observers, &mut testcase)?;
                state.solutions_mut().add(testcase)?;
                Ok(None)
            }
        }
    }

    fn serialize_and_dispatch(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        input: &I,
        exec_res: &crate::fuzzer::ExecuteInputResult,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        let observers_buf = match exec_res {
            crate::fuzzer::ExecuteInputResult::Corpus => {
                if manager.should_send() {
                    if manager.configuration() == EventConfig::AlwaysUnique {
                        None
                    } else {
                        Some(postcard::to_allocvec(observers)?)
                    }
                } else {
                    None
                }
            }
            _ => None,
        };

        self.dispatch_event(state, manager, input, exec_res, observers_buf, exit_kind)?;
        Ok(())
    }

    fn dispatch_event(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        input: &I,
        exec_res: &crate::fuzzer::ExecuteInputResult,
        observers_buf: Option<Vec<u8>>,
        exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        match exec_res {
            crate::fuzzer::ExecuteInputResult::Corpus => {
                if manager.should_send() {
                    manager.fire(
                        state,
                        EventWithStats::with_current_time(
                            Event::NewTestcase {
                                input: input.clone(),
                                observers_buf,
                                exit_kind: *exit_kind,
                                corpus_size: state.corpus().count(),
                                client_config: manager.configuration(),
                                forward_id: None,
                                #[cfg(all(unix, feature = "std", feature = "multi_machine"))]
                                node_id: None,
                            },
                            *state.executions(),
                        ),
                    )?;
                }
            }
            crate::fuzzer::ExecuteInputResult::Solution => {
                if manager.should_send() {
                    manager.fire(
                        state,
                        EventWithStats::with_current_time(
                            Event::Objective {
                                input: self.share_objectives.then_some(input.clone()),
                                objective_size: state.solutions().count(),
                            },
                            *state.executions(),
                        ),
                    )?;
                }
            }
            crate::fuzzer::ExecuteInputResult::None => (),
        }
        Ok(())
    }

    fn evaluate_execution(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        input: &I,
        observers: &OT,
        exit_kind: &ExitKind,
        send_events: bool,
    ) -> Result<(crate::fuzzer::ExecuteInputResult, Option<CorpusId>), Error> {
        let exec_res = self.check_results(state, manager, input, observers, exit_kind)?;
        let corpus_id =
            self.process_execution(state, manager, input, &exec_res, exit_kind, observers)?;
        if send_events {
            self.serialize_and_dispatch(state, manager, input, &exec_res, observers, exit_kind)?;
        }
        if exec_res != crate::fuzzer::ExecuteInputResult::None {
            *state.last_found_time_mut() = current_time();
        }
        Ok((exec_res, corpus_id))
    }
}

impl<CS, E, EM, F, I, IC, OF, S, ST, IF> crate::fuzzer::EvaluatorObservers<E, EM, I, S>
    for StdFuzzer<CS, F, OF, ST, IC, IF>
where
    CS: Scheduler<I, S>,
    E: HasObservers + crate::executors::Executor<EM, I, S, Self>,
    E::Observers: ObserversTuple<I, S> + Serialize,
    EM: EventFirer<I, S>,
    F: Feedback<EM, I, E::Observers, S>,
    OF: Feedback<EM, I, E::Observers, S>,
    S: HasCorpus<I>
        + HasSolutions<I>
        + crate::state::MaybeHasClientPerfMonitor
        + HasCurrentTestcase<I>
        + HasExecutions
        + HasLastFoundTime,
    I: Input,
{
    #[inline]
    fn evaluate_input_with_observers(
        &mut self,
        state: &mut S,
        executor: &mut E,
        manager: &mut EM,
        input: &I,
        send_events: bool,
    ) -> Result<(crate::fuzzer::ExecuteInputResult, Option<CorpusId>), Error> {
        use crate::fuzzer::{ExecutesInput, ExecutionProcessor};
        let exit_kind = self.execute_input(state, executor, manager, input)?;
        let observers = executor.observers();

        self.scheduler.on_evaluation(state, input, &*observers)?;

        self.evaluate_execution(state, manager, input, &*observers, &exit_kind, send_events)
    }
}

impl<CS, E, EM, F, I, IC, OF, S, ST, IF> crate::fuzzer::Evaluator<E, EM, I, S>
    for StdFuzzer<CS, F, OF, ST, IC, IF>
where
    CS: Scheduler<I, S>,
    E: HasObservers + crate::executors::Executor<EM, I, S, Self>,
    E::Observers: ObserversTuple<I, S> + Serialize,
    EM: EventFirer<I, S>,
    F: Feedback<EM, I, E::Observers, S>,
    OF: Feedback<EM, I, E::Observers, S>,
    S: HasCorpus<I>
        + HasSolutions<I>
        + crate::state::MaybeHasClientPerfMonitor
        + HasCurrentTestcase<I>
        + HasExecutions
        + HasLastFoundTime,
    I: Input,
    IF: crate::fuzzer::InputFilter<EM, I, S>,
{
    fn evaluate_filtered(
        &mut self,
        state: &mut S,
        executor: &mut E,
        manager: &mut EM,
        input: &I,
    ) -> Result<(crate::fuzzer::ExecuteInputResult, Option<CorpusId>), Error> {
        use crate::fuzzer::EvaluatorObservers;
        if self.input_filter.should_execute(input, state, manager)? {
            self.evaluate_input_with_observers(state, executor, manager, input, true)
        } else {
            Ok((crate::fuzzer::ExecuteInputResult::None, None))
        }
    }

    fn evaluate_input(
        &mut self,
        state: &mut S,
        executor: &mut E,
        manager: &mut EM,
        input: &I,
    ) -> Result<(crate::fuzzer::ExecuteInputResult, Option<CorpusId>), Error> {
        use crate::fuzzer::EvaluatorObservers;
        self.evaluate_input_with_observers(state, executor, manager, input, true)
    }

    fn add_input(
        &mut self,
        state: &mut S,
        executor: &mut E,
        manager: &mut EM,
        input: I,
    ) -> Result<CorpusId, Error> {
        use crate::fuzzer::ExecutesInput;
        *state.last_found_time_mut() = current_time();

        let exit_kind = self.execute_input(state, executor, manager, &input)?;
        let observers = executor.observers();
        let mut testcase = Testcase::from(input.clone());
        testcase.set_executions(*state.executions());

        #[cfg(not(feature = "introspection"))]
        let is_solution =
            self.objective_mut()
                .is_interesting(state, manager, &input, &*observers, &exit_kind)?;
        #[cfg(feature = "introspection")]
        let is_solution = self.objective_mut().is_interesting_introspection(
            state,
            manager,
            &input,
            &*observers,
            &exit_kind,
        )?;

        if is_solution {
            self.objective_mut()
                .append_metadata(state, manager, &*observers, &mut testcase)?;
            let id = state.solutions_mut().add(testcase)?;

            manager.fire(
                state,
                EventWithStats::with_current_time(
                    Event::Objective {
                        input: self.share_objectives.then_some(input.clone()),
                        objective_size: state.solutions().count(),
                    },
                    *state.executions(),
                ),
            )?;
            return Ok(id);
        }

        self.feedback_mut()
            .append_metadata(state, manager, &*observers, &mut testcase)?;
        let id = state.corpus_mut().add(testcase)?;
        self.scheduler_mut().on_add(state, id)?;

        let observers_buf = if manager.configuration() == EventConfig::AlwaysUnique {
            None
        } else {
            Some(postcard::to_allocvec(&*observers)?)
        };
        manager.fire(
            state,
            EventWithStats::with_current_time(
                Event::NewTestcase {
                    input,
                    observers_buf,
                    exit_kind,
                    corpus_size: state.corpus().count(),
                    client_config: manager.configuration(),
                    forward_id: None,
                    #[cfg(all(unix, feature = "std", feature = "multi_machine"))]
                    node_id: None,
                },
                *state.executions(),
            ),
        )?;
        Ok(id)
    }

    fn add_disabled_input(&mut self, state: &mut S, input: I) -> Result<CorpusId, Error> {
        let mut testcase = Testcase::from(input);
        testcase.set_disabled(true);
        state.corpus_mut().add_disabled(testcase)
    }
}

impl<CS, E, EM, F, I, IC, OF, S, ST, IF> crate::fuzzer::EventProcessor<E, EM, I, S>
    for StdFuzzer<CS, F, OF, ST, IC, IF>
where
    CS: Scheduler<I, S>,
    E: HasObservers + crate::executors::Executor<EM, I, S, Self>,
    E::Observers: serde::de::DeserializeOwned + Serialize + ObserversTuple<I, S>,
    EM: crate::events::EventReceiver<I, S> + EventFirer<I, S>,
    F: Feedback<EM, I, E::Observers, S>,
    I: Input,
    OF: Feedback<EM, I, E::Observers, S>,
    S: HasCorpus<I>
        + HasSolutions<I>
        + HasExecutions
        + HasLastFoundTime
        + crate::state::MaybeHasClientPerfMonitor
        + HasCurrentCorpusId
        + crate::state::HasImported,
{
    fn process_events(
        &mut self,
        state: &mut S,
        executor: &mut E,
        manager: &mut EM,
    ) -> Result<(), Error> {
        use crate::fuzzer::{EvaluatorObservers, ExecutionProcessor};
        // Poll the event manager for received events and evaluate any new inputs/objectives.
        while let Some((event, with_observers)) = manager.try_receive(state)? {
            let res = if with_observers {
                match event.event() {
                    Event::NewTestcase {
                        input,
                        observers_buf,
                        exit_kind,
                        ..
                    } => {
                        let observers: E::Observers =
                            postcard::from_bytes(observers_buf.as_ref().unwrap())?;
                        let res = self.evaluate_execution(
                            state, manager, input, &observers, exit_kind, false,
                        )?;
                        res.1
                    }
                    _ => None,
                }
            } else {
                match event.event() {
                    Event::NewTestcase { input, .. } => {
                        let res = self.evaluate_input_with_observers(
                            state, executor, manager, input, false,
                        )?;
                        res.1
                    }
                    Event::Objective {
                        input: Some(unwrapped_input),
                        ..
                    } => {
                        let res = self.evaluate_input_with_observers(
                            state,
                            executor,
                            manager,
                            unwrapped_input,
                            false,
                        )?;
                        res.1
                    }
                    _ => None,
                }
            };
            if let Some(item) = res {
                *state.imported_mut() += 1;
                log::debug!("Added received input as item #{item}");
                manager.on_interesting(state, event)?;
            } else {
                log::debug!("Received input was discarded");
            }
        }
        Ok(())
    }
}

impl<CS, E, EM, F, I, IC, OF, S, ST, STF, IF> crate::fuzzer::Fuzzer<E, EM, I, S, ST>
    for StdFuzzer<CS, F, OF, STF, IC, IF>
where
    CS: Scheduler<I, S>,
    E: HasObservers + crate::executors::Executor<EM, I, S, Self>,
    E::Observers: serde::de::DeserializeOwned + Serialize + ObserversTuple<I, S>,
    EM: EventFirer<I, S>
        + crate::events::ProgressReporter<S>
        + SendExiting
        + crate::events::EventReceiver<I, S>,
    I: Input,
    F: Feedback<EM, I, E::Observers, S>,
    OF: Feedback<EM, I, E::Observers, S>,
    S: HasExecutions
        + crate::HasMetadata
        + HasCorpus<I>
        + HasSolutions<I>
        + crate::state::HasLastReportTime
        + HasLastFoundTime
        + crate::state::HasImported
        + HasTestcase<I>
        + HasCurrentCorpusId
        + HasCurrentStageId
        + Stoppable
        + crate::state::MaybeHasClientPerfMonitor,
    ST: crate::stages::pull::StagesTuple<E, EM, S, Self>,
{
    fn fuzz_one(
        &mut self,
        stages: &mut ST,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<CorpusId, Error> {
        use crate::fuzzer::EventProcessor;
        // Init timer for scheduler
        #[cfg(feature = "introspection")]
        state.introspection_stats_mut().start_timer();

        // Get the next index from the scheduler (or resume the current one).
        let id = if let Some(id) = state.current_corpus_id()? {
            id
        } else {
            let id = self.scheduler.next(state)?;
            state.set_corpus_id(id)?; // set up for resume
            id
        };

        #[cfg(feature = "introspection")]
        state.introspection_stats_mut().mark_scheduler_time();

        #[cfg(feature = "introspection")]
        state.introspection_stats_mut().reset_stage_index();

        // Execute all stages
        stages.perform_all(self, executor, state, manager)?;

        #[cfg(feature = "introspection")]
        state.introspection_stats_mut().start_timer();

        self.process_events(state, executor, manager)?;

        #[cfg(feature = "introspection")]
        state.introspection_stats_mut().mark_manager_time();

        {
            if let Ok(mut testcase) = state.testcase_mut(id) {
                let scheduled_count = testcase.scheduled_count();
                // increase scheduled count, this was fuzz_level in afl
                testcase.set_scheduled_count(scheduled_count + 1);
            }
        }

        state.clear_corpus_id()?;

        if state.stop_requested() {
            state.discard_stop_request();
            manager.on_shutdown()?;
            return Err(Error::shutting_down());
        }

        Ok(id)
    }

    fn fuzz_loop(
        &mut self,
        stages: &mut ST,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<(), Error> {
        let monitor_timeout = crate::fuzzer::STATS_TIMEOUT_DEFAULT;
        loop {
            manager.maybe_report_progress(state, monitor_timeout)?;
            crate::fuzzer::Fuzzer::fuzz_one(self, stages, executor, state, manager)?;
        }
    }

    fn fuzz_loop_for(
        &mut self,
        stages: &mut ST,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        iters: u64,
    ) -> Result<CorpusId, Error> {
        if iters == 0 {
            return Err(Error::illegal_argument(alloc::string::ToString::to_string(
                "Cannot fuzz for 0 iterations!",
            )));
        }

        let mut ret = None;
        let monitor_timeout = crate::fuzzer::STATS_TIMEOUT_DEFAULT;

        for _ in 0..iters {
            manager.maybe_report_progress(state, monitor_timeout)?;
            ret = Some(crate::fuzzer::Fuzzer::fuzz_one(
                self, stages, executor, state, manager,
            )?);
        }

        manager.report_progress(state)?;

        Ok(ret.unwrap())
    }
}

#[cfg(test)]
#[cfg(feature = "std")]
#[allow(
    clippy::type_complexity,
    clippy::match_wildcard_for_single_variants,
    clippy::duration_suboptimal_units
)]
mod tests {
    use libafl_bolts::{
        rands::StdRand,
        tuples::{RefIndexable, tuple_list},
    };

    use crate::{
        corpus::{Corpus, InMemoryCorpus, Testcase},
        events::NopEventManager,
        executors::{
            Executor, ExitKind, HasObservers,
            target::{StdTargetExecutor, TargetExecutor},
        },
        feedbacks::ConstFeedback,
        fuzzer::{
            EngineStep, ExecutionMode, ExecutionObservation, ExecutionRequest, FuzzingEngine,
            StdFuzzer,
        },
        inputs::BytesInput,
        mutators::{mutations::BitFlipMutator, scheduled::HavocScheduledMutator},
        observers::StdMapObserver,
        schedulers::QueueScheduler,
        stages::push::{CalibrationStage, MultiMutationalStage, StdMutationalStage},
        state::{HasCorpus, HasCurrentInputs, StdState},
    };

    static mut COVERAGE_MAP: [u8; 16] = [0; 16];
    use crate::INPROCESS_TEST_MUTEX;

    #[derive(Debug)]
    struct DummyExecutor<OT = (StdMapObserver<'static, u8, false>, ())> {
        observers: OT,
    }

    impl<OT> HasObservers for DummyExecutor<OT> {
        type Observers = OT;

        fn observers(&self) -> RefIndexable<&Self::Observers, Self::Observers> {
            RefIndexable::from(&self.observers)
        }

        fn observers_mut(&mut self) -> RefIndexable<&mut Self::Observers, Self::Observers> {
            RefIndexable::from(&mut self.observers)
        }
    }

    impl<EM, OT, S, Z> Executor<EM, BytesInput, S, Z> for DummyExecutor<OT> {
        fn run_target(
            &mut self,
            _fuzzer: &mut Z,
            _state: &mut S,
            _mgr: &mut EM,
            _input: &BytesInput,
        ) -> Result<ExitKind, libafl_bolts::Error> {
            Ok(ExitKind::Ok)
        }
    }

    impl TargetExecutor<BytesInput, (StdMapObserver<'static, u8, false>, ())> for DummyExecutor {
        fn execute_input(
            &mut self,
            _input: &BytesInput,
        ) -> Result<
            ExecutionObservation<(StdMapObserver<'static, u8, false>, ())>,
            libafl_bolts::Error,
        > {
            Ok(ExecutionObservation::new(
                ExitKind::Ok,
                self.observers.clone(),
            ))
        }

        fn execute_batch<'a>(
            &'a mut self,
            inputs: &[BytesInput],
        ) -> Result<
            &'a [ExecutionObservation<(StdMapObserver<'static, u8, false>, ())>],
            libafl_bolts::Error,
        > {
            let obs: alloc::vec::Vec<_> = inputs
                .iter()
                .map(|_| ExecutionObservation::new(ExitKind::Ok, self.observers.clone()))
                .collect();
            Ok(alloc::boxed::Box::leak(obs.into_boxed_slice()))
        }

        fn execute_borrowed_batch<'a>(
            &'a mut self,
            inputs: &[&BytesInput],
        ) -> Result<
            &'a [ExecutionObservation<(StdMapObserver<'static, u8, false>, ())>],
            libafl_bolts::Error,
        > {
            let obs: alloc::vec::Vec<_> = inputs
                .iter()
                .map(|_| ExecutionObservation::new(ExitKind::Ok, self.observers.clone()))
                .collect();
            Ok(alloc::boxed::Box::leak(obs.into_boxed_slice()))
        }

        fn execute_request<'a>(
            &'a mut self,
            request: &ExecutionRequest<BytesInput>,
        ) -> Result<
            &'a [ExecutionObservation<(StdMapObserver<'static, u8, false>, ())>],
            libafl_bolts::Error,
        > {
            let obs: alloc::vec::Vec<_> = request
                .inputs
                .iter()
                .enumerate()
                .map(|(i, _)| {
                    let mut item = ExecutionObservation::new(ExitKind::Ok, self.observers.clone());
                    if let Some(sid) = request.start_id {
                        item.id = Some(sid + i as u64);
                    }
                    if let Some(mut t) = request.tag {
                        t.input_id += i as u64;
                        item.tag = Some(t);
                    }
                    item
                })
                .collect();
            Ok(alloc::boxed::Box::leak(obs.into_boxed_slice()))
        }
    }

    #[test]
    fn execution_mode_raw_encoding_round_trips() {
        for mode in [
            ExecutionMode::Normal,
            ExecutionMode::CmpLog,
            ExecutionMode::Tracing,
            ExecutionMode::Asan,
            ExecutionMode::Concolic,
            ExecutionMode::VerifyTimeouts,
            ExecutionMode::custom(0),
            ExecutionMode::custom(1),
            ExecutionMode::custom(u16::MAX),
        ] {
            assert_eq!(
                ExecutionMode::from_raw(mode.to_raw()),
                Some(mode),
                "{mode} must survive the raw encoding"
            );
        }

        // Built-in encodings are dense, so the first unused one must not decode.
        assert_eq!(ExecutionMode::from_raw(6), None);
        assert_eq!(ExecutionMode::default(), ExecutionMode::Normal);
    }

    #[test]
    fn execution_mode_lives_on_the_tag_only() {
        let request = ExecutionRequest::single(BytesInput::new(vec![1]));
        assert_eq!(request.mode(), ExecutionMode::Normal);
        assert!(request.tag.is_none());

        let tagged = request.with_mode(ExecutionMode::CmpLog);
        assert_eq!(tagged.mode(), ExecutionMode::CmpLog);
        assert_eq!(
            tagged.tag.expect("with_mode must create a tag").mode,
            ExecutionMode::CmpLog,
            "the tag is the single source of truth for the mode"
        );
    }

    #[test]
    fn test_push_engine_step() {
        let rand = StdRand::with_seed(42);
        let mut corpus = InMemoryCorpus::<BytesInput>::new();
        let testcase = Testcase::new(BytesInput::new(vec![0x41, 0x42, 0x43]));
        let id = corpus.add(testcase).unwrap();

        let mut feedback = ConstFeedback::new(false);
        let mut objective = ConstFeedback::new(false);

        let mut state = StdState::new(
            rand,
            corpus,
            InMemoryCorpus::new(),
            &mut feedback,
            &mut objective,
        )
        .unwrap();

        let mut scheduler = QueueScheduler::new();
        crate::schedulers::Scheduler::on_add(&mut scheduler, &mut state, id).unwrap();

        let mutator = HavocScheduledMutator::new(tuple_list!(BitFlipMutator::new()));
        let mutational_stage = StdMutationalStage::new(mutator);
        let calibration_stage = CalibrationStage::with_runs(2);

        let stages = tuple_list!(calibration_stage, mutational_stage);
        let mut engine = StdFuzzer::new(scheduler, feedback, objective, stages);
        let mut mgr = NopEventManager::new();

        // 1. First step should initialize and execute calibration
        let step1 = FuzzingEngine::<
            NopEventManager,
            BytesInput,
            (StdMapObserver<'static, u8, false>, ()),
            _,
        >::step(&mut engine, &mut state, &mut mgr)
        .unwrap();
        match step1 {
            EngineStep::Execute(req) => {
                assert_eq!(req.inputs.len(), 2);
            }
            _ => panic!("Expected Execute step for calibration"),
        }

        // 2. Next step advances into mutational stage
        let step2 = FuzzingEngine::<
            NopEventManager,
            BytesInput,
            (StdMapObserver<'static, u8, false>, ()),
            _,
        >::step(&mut engine, &mut state, &mut mgr)
        .unwrap();
        match step2 {
            EngineStep::Execute(req) => {
                assert_eq!(req.inputs.len(), 1);
            }
            _ => panic!("Expected Execute step for mutational stage"),
        }
    }

    #[test]
    fn test_push_engine_with_executor_and_loop() {
        let rand = StdRand::with_seed(1337);
        let mut corpus = InMemoryCorpus::<BytesInput>::new();
        let testcase = Testcase::new(BytesInput::new(vec![0x01, 0x02, 0x03]));
        let id = corpus.add(testcase).unwrap();

        let mut feedback = ConstFeedback::new(true);
        let mut objective = ConstFeedback::new(false);

        let mut state = StdState::new(
            rand,
            corpus,
            InMemoryCorpus::new(),
            &mut feedback,
            &mut objective,
        )
        .unwrap();

        let mut scheduler = QueueScheduler::new();
        crate::schedulers::Scheduler::on_add(&mut scheduler, &mut state, id).unwrap();

        let map_ptr = &raw mut COVERAGE_MAP as *mut u8;
        let observer = unsafe { StdMapObserver::from_mut_ptr("coverage", map_ptr, 16) };

        let dummy = DummyExecutor {
            observers: (observer, ()),
        };
        let mut target_exec = StdTargetExecutor::new(dummy);

        let mutator = HavocScheduledMutator::new(tuple_list!(BitFlipMutator::new()));
        let mutational_stage = StdMutationalStage::new(mutator);
        let stages = tuple_list!(mutational_stage);
        let mut engine = StdFuzzer::new(scheduler, feedback, objective, stages);
        let mut mgr = NopEventManager::new();

        // Run a few steps using FuzzLoop driver
        for _ in 0..5 {
            match FuzzingEngine::<
                NopEventManager,
                BytesInput,
                (StdMapObserver<'static, u8, false>, ()),
                _,
            >::step(&mut engine, &mut state, &mut mgr)
            .unwrap()
            {
                EngineStep::Execute(req) => {
                    let res = target_exec.execute_batch(&req.inputs).unwrap();
                    engine
                        .report_observations(&mut state, &mut mgr, res)
                        .unwrap();
                }
                EngineStep::Progress => {}
                EngineStep::Completed => break,
            }
        }

        assert!(*crate::state::HasExecutions::executions(&state) > 0);
    }

    #[derive(Debug, Clone)]
    struct DummyMultiMutator;

    impl libafl_bolts::Named for DummyMultiMutator {
        fn name(&self) -> &alloc::borrow::Cow<'static, str> {
            static NAME: alloc::borrow::Cow<'static, str> =
                alloc::borrow::Cow::Borrowed("DummyMultiMutator");
            &NAME
        }
    }

    impl<S> crate::mutators::MultiMutator<BytesInput, S> for DummyMultiMutator {
        fn multi_mutate(
            &mut self,
            _state: &mut S,
            _input: &BytesInput,
            _max_count: Option<usize>,
        ) -> Result<alloc::vec::Vec<BytesInput>, libafl_bolts::Error> {
            Ok(alloc::vec![
                BytesInput::new(alloc::vec![1, 2, 3]),
                BytesInput::new(alloc::vec![4, 5, 6]),
                BytesInput::new(alloc::vec![7, 8, 9]),
            ])
        }
    }

    #[test]
    fn test_push_engine_batch_multi_eval() {
        let rand = StdRand::with_seed(999);
        let mut corpus = InMemoryCorpus::<BytesInput>::new();
        let testcase = Testcase::new(BytesInput::new(alloc::vec![0x10, 0x20]));
        let id = corpus.add(testcase).unwrap();

        let mut feedback = ConstFeedback::new(true);
        let mut objective = ConstFeedback::new(false);

        let mut state = StdState::new(
            rand,
            corpus,
            InMemoryCorpus::new(),
            &mut feedback,
            &mut objective,
        )
        .unwrap();

        let mut scheduler = QueueScheduler::new();
        crate::schedulers::Scheduler::on_add(&mut scheduler, &mut state, id).unwrap();

        let multi_stage = MultiMutationalStage::new(DummyMultiMutator);
        let stages = tuple_list!(multi_stage);
        let mut engine = StdFuzzer::new(scheduler, feedback, objective, stages);
        let mut mgr = NopEventManager::new();

        // Step 1: generates batch of inputs
        let step1 = FuzzingEngine::<
            NopEventManager,
            BytesInput,
            (StdMapObserver<'static, u8, false>, ()),
            _,
        >::step(&mut engine, &mut state, &mut mgr)
        .unwrap();
        let batch_len = match step1 {
            EngineStep::Execute(req) => {
                assert_eq!(req.inputs.len(), 3);
                req.inputs.len()
            }
            _ => panic!("Expected batch execution request"),
        };

        // Prepare batch of observations
        let map_ptr = &raw mut COVERAGE_MAP as *mut u8;
        let observer = unsafe { StdMapObserver::from_mut_ptr("coverage", map_ptr, 16) };
        let observations: alloc::vec::Vec<_> = (0..batch_len)
            .map(|_| ExecutionObservation::new(ExitKind::Ok, (observer.clone(), ())))
            .collect();

        // Step 2: Feed back all observations at once
        let initial_corpus_count = state.corpus().count();
        engine
            .report_observations(&mut state, &mut mgr, &observations)
            .unwrap();
        let step2 = FuzzingEngine::<
            NopEventManager,
            BytesInput,
            (StdMapObserver<'static, u8, false>, ()),
            _,
        >::step(&mut engine, &mut state, &mut mgr)
        .unwrap();
        assert!(matches!(
            step2,
            EngineStep::Progress | EngineStep::Execute(_)
        ));

        // All batch executions were accounted for
        assert_eq!(
            *crate::state::HasExecutions::executions(&state),
            batch_len as u64
        );
        // Feedback was true, so items were added to corpus
        assert!(state.corpus().count() >= initial_corpus_count);
    }

    #[test]
    fn test_dual_target_executor_cmplog_routing() {
        use crate::{
            executors::target::DualTargetExecutor, fuzzer::ExecutionRequest,
            state::HasExecutionMode,
        };

        #[derive(Debug)]
        struct PrimaryExecutor {
            observers: (StdMapObserver<'static, u8, false>, ()),
            hit: *mut bool,
        }

        impl HasObservers for PrimaryExecutor {
            type Observers = (StdMapObserver<'static, u8, false>, ());

            fn observers(&self) -> RefIndexable<&Self::Observers, Self::Observers> {
                RefIndexable::from(&self.observers)
            }

            fn observers_mut(&mut self) -> RefIndexable<&mut Self::Observers, Self::Observers> {
                RefIndexable::from(&mut self.observers)
            }
        }

        impl<EM, S, Z> Executor<EM, BytesInput, S, Z> for PrimaryExecutor {
            fn run_target(
                &mut self,
                _fuzzer: &mut Z,
                _state: &mut S,
                _mgr: &mut EM,
                _input: &BytesInput,
            ) -> Result<ExitKind, libafl_bolts::Error> {
                unsafe {
                    *self.hit = true;
                }
                Ok(ExitKind::Ok)
            }
        }

        #[derive(Debug)]
        struct TracerExecutor {
            observers: (StdMapObserver<'static, u8, false>, ()),
            hit: *mut bool,
        }

        impl HasObservers for TracerExecutor {
            type Observers = (StdMapObserver<'static, u8, false>, ());

            fn observers(&self) -> RefIndexable<&Self::Observers, Self::Observers> {
                RefIndexable::from(&self.observers)
            }

            fn observers_mut(&mut self) -> RefIndexable<&mut Self::Observers, Self::Observers> {
                RefIndexable::from(&mut self.observers)
            }
        }

        impl<EM, S, Z> Executor<EM, BytesInput, S, Z> for TracerExecutor {
            fn run_target(
                &mut self,
                _fuzzer: &mut Z,
                _state: &mut S,
                _mgr: &mut EM,
                _input: &BytesInput,
            ) -> Result<ExitKind, libafl_bolts::Error> {
                unsafe {
                    *self.hit = true;
                }
                Ok(ExitKind::Ok)
            }
        }

        let map_ptr = &raw mut COVERAGE_MAP as *mut u8;
        let observer1 = unsafe { StdMapObserver::from_mut_ptr("coverage", map_ptr, 16) };
        let observer2 = unsafe { StdMapObserver::from_mut_ptr("coverage", map_ptr, 16) };

        let mut primary_hit = false;
        let mut secondary_hit = false;

        let primary = PrimaryExecutor {
            observers: (observer1, ()),
            hit: &raw mut primary_hit,
        };
        let secondary = TracerExecutor {
            observers: (observer2, ()),
            hit: &raw mut secondary_hit,
        };

        let mut dual_exec = DualTargetExecutor::new(
            StdTargetExecutor::new(primary),
            StdTargetExecutor::new(secondary),
            ExecutionMode::CmpLog,
        );

        let rand = StdRand::with_seed(1234);
        let mut feedback = ConstFeedback::new(false);
        let mut objective = ConstFeedback::new(false);
        let mut state = StdState::new(
            rand,
            InMemoryCorpus::<BytesInput>::new(),
            InMemoryCorpus::new(),
            &mut feedback,
            &mut objective,
        )
        .unwrap();

        let input = BytesInput::new(alloc::vec![1, 2, 3]);

        // Standard mode -> routes to primary
        state.set_execution_mode(ExecutionMode::Normal);
        primary_hit = false;
        secondary_hit = false;
        let res_std = dual_exec
            .execute_batch(core::slice::from_ref(&input))
            .unwrap();
        assert_eq!(res_std.len(), 1);
        assert!(primary_hit);
        assert!(!secondary_hit);

        // Custom "cmplog" mode in request -> routes to secondary (tracer)
        let req_cmplog = ExecutionRequest::single(input).with_mode(ExecutionMode::CmpLog);
        primary_hit = false;
        secondary_hit = false;
        let res_cmp = dual_exec.execute_request(&req_cmplog).unwrap();
        assert_eq!(res_cmp.len(), 1);
        assert!(!primary_hit);
        assert!(secondary_hit);
    }

    #[test]
    fn test_state_serialization_and_deterministic_restart() {
        use crate::state::HasExecutionMode;

        let rand = StdRand::with_seed(0xdeadbeef);
        let mut corpus = InMemoryCorpus::<BytesInput>::new();
        let testcase = Testcase::new(BytesInput::new(alloc::vec![0x41, 0x42, 0x43, 0x44]));
        let id = corpus.add(testcase).unwrap();

        let mut feedback = ConstFeedback::new(false);
        let mut objective = ConstFeedback::new(false);

        let mut state = StdState::new(
            rand,
            corpus,
            InMemoryCorpus::new(),
            &mut feedback,
            &mut objective,
        )
        .unwrap();

        let mut scheduler = QueueScheduler::new();
        crate::schedulers::Scheduler::on_add(&mut scheduler, &mut state, id).unwrap();

        let map_ptr = &raw mut COVERAGE_MAP as *mut u8;
        let observer = unsafe { StdMapObserver::from_mut_ptr("coverage", map_ptr, 16) };
        let dummy = DummyExecutor {
            observers: (observer, ()),
        };
        let mut target_exec1 = StdTargetExecutor::new(dummy);

        let map_ptr2 = &raw mut COVERAGE_MAP as *mut u8;
        let observer2 = unsafe { StdMapObserver::from_mut_ptr("coverage", map_ptr2, 16) };
        let dummy2 = DummyExecutor {
            observers: (observer2, ()),
        };
        let mut target_exec2 = StdTargetExecutor::new(dummy2);

        let mutator1 = HavocScheduledMutator::new(tuple_list!(BitFlipMutator::new()));
        let mutational_stage1 = StdMutationalStage::new(mutator1);
        let calibration_stage1 = CalibrationStage::with_runs(3);
        let stages1 = tuple_list!(calibration_stage1, mutational_stage1);

        let mut engine_original = StdFuzzer::new(scheduler, feedback, objective, stages1);
        let mut mgr = NopEventManager::new();

        // 1. Run 3 steps on original engine
        for _ in 0..3 {
            match FuzzingEngine::<
                NopEventManager,
                BytesInput,
                (StdMapObserver<'static, u8, false>, ()),
                _,
            >::step(&mut engine_original, &mut state, &mut mgr)
            .unwrap()
            {
                EngineStep::Execute(req) => {
                    let res = target_exec1.execute_batch(&req.inputs).unwrap();
                    engine_original
                        .report_observations(&mut state, &mut mgr, res)
                        .unwrap();
                }
                EngineStep::Progress => {}
                EngineStep::Completed => break,
            }
        }

        // 2. Serialize State to bytes
        let serialized_state = postcard::to_allocvec(&state).expect("Failed to serialize state");

        // 3. Deserialize into a fresh State instance
        let mut restarted_state: StdState<
            InMemoryCorpus<BytesInput>,
            BytesInput,
            StdRand,
            InMemoryCorpus<BytesInput>,
        > = postcard::from_bytes(&serialized_state).expect("Failed to deserialize state");

        // 4. Create identical fresh engine for the restarted state
        let scheduler_clone = QueueScheduler::new();
        let feedback_clone = ConstFeedback::new(false);
        let objective_clone = ConstFeedback::new(false);
        let mutator2 = HavocScheduledMutator::new(tuple_list!(BitFlipMutator::new()));
        let mutational_stage2 = StdMutationalStage::new(mutator2);
        let calibration_stage2 = CalibrationStage::with_runs(3);
        let stages2 = tuple_list!(calibration_stage2, mutational_stage2);
        let mut engine_restarted =
            StdFuzzer::new(scheduler_clone, feedback_clone, objective_clone, stages2);

        // 5. Run next 10 steps on both engines in parallel and assert identical results!
        for step_idx in 0..10 {
            let step_orig = FuzzingEngine::<
                NopEventManager,
                BytesInput,
                (StdMapObserver<'static, u8, false>, ()),
                _,
            >::step(&mut engine_original, &mut state, &mut mgr)
            .unwrap();
            let step_rest =
                FuzzingEngine::<
                    NopEventManager,
                    BytesInput,
                    (StdMapObserver<'static, u8, false>, ()),
                    _,
                >::step(&mut engine_restarted, &mut restarted_state, &mut mgr)
                .unwrap();

            match (step_orig, step_rest) {
                (EngineStep::Execute(req_orig), EngineStep::Execute(req_rest)) => {
                    assert_eq!(
                        req_orig.inputs, req_rest.inputs,
                        "Mismatch at step {step_idx}: original and restarted engines yielded different inputs!"
                    );
                    assert_eq!(
                        state.execution_mode(),
                        restarted_state.execution_mode(),
                        "Mismatch at step {step_idx}: execution mode differs!"
                    );

                    let res_orig = target_exec1.execute_batch(&req_orig.inputs).unwrap();
                    let res_rest = target_exec2.execute_batch(&req_rest.inputs).unwrap();

                    engine_original
                        .report_observations(&mut state, &mut mgr, res_orig)
                        .unwrap();
                    engine_restarted
                        .report_observations(&mut restarted_state, &mut mgr, res_rest)
                        .unwrap();
                }
                (EngineStep::Progress, EngineStep::Progress) => {}
                (EngineStep::Completed, EngineStep::Completed) => break,
                (other_orig, other_rest) => {
                    panic!(
                        "Mismatch at step {step_idx}: orig is {other_orig:?}, restarted is {other_rest:?}"
                    );
                }
            }

            // Also check state executions match exactly
            assert_eq!(
                *crate::state::HasExecutions::executions(&state),
                *crate::state::HasExecutions::executions(&restarted_state),
                "Executions count diverged at step {step_idx}!"
            );
        }
    }

    #[test]
    fn test_state_serialization_with_dual_target_executor_and_cmplog_resumption() {
        use crate::{
            common::HasMetadata,
            corpus::SchedulerTestcaseMetadata,
            executors::target::DualTargetExecutor,
            schedulers::powersched::{PowerQueueScheduler, PowerSchedule},
            stages::push::{AflppCmplogTracingStage, StdPowerMutationalStage},
            state::HasExecutionMode,
        };

        let rand = StdRand::with_seed(0xc0ffee);
        let mut corpus = InMemoryCorpus::<BytesInput>::new();
        let mut testcase = Testcase::new(BytesInput::new(alloc::vec![1, 2, 3, 4]));
        testcase.set_exec_time(core::time::Duration::from_millis(1));
        testcase.add_metadata(SchedulerTestcaseMetadata::new(1));
        let id = corpus.add(testcase).unwrap();

        let mut feedback = ConstFeedback::new(false);
        let mut objective = ConstFeedback::new(false);

        let mut state = StdState::new(
            rand,
            corpus,
            InMemoryCorpus::new(),
            &mut feedback,
            &mut objective,
        )
        .unwrap();

        let map_ptr = &raw mut COVERAGE_MAP as *mut u8;
        let observer1 = unsafe { StdMapObserver::from_mut_ptr("coverage1", map_ptr, 16) };
        let observer2 = unsafe { StdMapObserver::from_mut_ptr("coverage2", map_ptr, 16) };

        let mut scheduler = PowerQueueScheduler::new(&mut state, &observer1, PowerSchedule::fast());
        crate::schedulers::Scheduler::on_add(&mut scheduler, &mut state, id).unwrap();

        let primary1 = DummyExecutor {
            observers: (observer1.clone(), ()),
        };
        let secondary1 = DummyExecutor {
            observers: (observer2.clone(), ()),
        };
        let mut dual_exec1 = DualTargetExecutor::new(primary1, secondary1, ExecutionMode::CmpLog);

        let primary2 = DummyExecutor {
            observers: (observer1.clone(), ()),
        };
        let secondary2 = DummyExecutor {
            observers: (observer2, ()),
        };
        let mut dual_exec2 = DualTargetExecutor::new(primary2, secondary2, ExecutionMode::CmpLog);

        let cmplog_stage1 = AflppCmplogTracingStage::new();
        let mutator1 = HavocScheduledMutator::new(tuple_list!(BitFlipMutator::new()));
        let power_stage1 = StdPowerMutationalStage::new(mutator1);
        let stages1 = tuple_list!(cmplog_stage1, power_stage1);

        let mut engine_orig = StdFuzzer::new(scheduler, feedback, objective, stages1);
        let mut mgr = NopEventManager::new();

        // 1. Run 2 steps on original engine (entering cmplog mode)
        for _ in 0..2 {
            match FuzzingEngine::<
                NopEventManager,
                BytesInput,
                (StdMapObserver<'static, u8, false>, ()),
                _,
            >::step(&mut engine_orig, &mut state, &mut mgr)
            .unwrap()
            {
                EngineStep::Execute(req) => {
                    let res = dual_exec1.execute_batch(&req.inputs).unwrap();
                    engine_orig
                        .report_observations(&mut state, &mut mgr, res)
                        .unwrap();
                }
                EngineStep::Progress => {}
                EngineStep::Completed => break,
            }
        }

        // 2. Serialize State mid-campaign
        let serialized_state = postcard::to_allocvec(&state).expect("Failed to serialize state");

        // 3. Deserialize State
        let mut restarted_state: StdState<
            InMemoryCorpus<BytesInput>,
            BytesInput,
            StdRand,
            InMemoryCorpus<BytesInput>,
        > = postcard::from_bytes(&serialized_state).expect("Failed to deserialize state");

        // 4. Create fresh engine on restarted state
        let scheduler_clone =
            PowerQueueScheduler::new(&mut restarted_state, &observer1, PowerSchedule::fast());
        let feedback_clone = ConstFeedback::new(false);
        let objective_clone = ConstFeedback::new(false);
        let cmplog_stage2 = AflppCmplogTracingStage::new();
        let mutator2 = HavocScheduledMutator::new(tuple_list!(BitFlipMutator::new()));
        let power_stage2 = StdPowerMutationalStage::new(mutator2);
        let stages2 = tuple_list!(cmplog_stage2, power_stage2);
        let mut engine_rest =
            StdFuzzer::new(scheduler_clone, feedback_clone, objective_clone, stages2);

        // 5. Verify byte-for-byte identical execution across 10 steps
        for step_idx in 0..10 {
            let step_orig = FuzzingEngine::<
                NopEventManager,
                BytesInput,
                (StdMapObserver<'static, u8, false>, ()),
                _,
            >::step(&mut engine_orig, &mut state, &mut mgr)
            .unwrap();
            let step_rest = FuzzingEngine::<
                NopEventManager,
                BytesInput,
                (StdMapObserver<'static, u8, false>, ()),
                _,
            >::step(&mut engine_rest, &mut restarted_state, &mut mgr)
            .unwrap();

            match (step_orig, step_rest) {
                (EngineStep::Execute(req_orig), EngineStep::Execute(req_rest)) => {
                    assert_eq!(
                        req_orig.inputs, req_rest.inputs,
                        "Mismatch in inputs at step {step_idx}"
                    );
                    assert_eq!(
                        state.execution_mode(),
                        restarted_state.execution_mode(),
                        "Mismatch in execution_mode at step {step_idx}"
                    );

                    let res_orig = dual_exec1.execute_batch(&req_orig.inputs).unwrap();
                    let res_rest = dual_exec2.execute_batch(&req_rest.inputs).unwrap();

                    engine_orig
                        .report_observations(&mut state, &mut mgr, res_orig)
                        .unwrap();
                    engine_rest
                        .report_observations(&mut restarted_state, &mut mgr, res_rest)
                        .unwrap();
                }
                (EngineStep::Progress, EngineStep::Progress) => {}
                (EngineStep::Completed, EngineStep::Completed) => break,
                (other_orig, other_rest) => {
                    panic!(
                        "Mismatch at step {step_idx}: orig is {other_orig:?}, restarted is {other_rest:?}"
                    );
                }
            }

            assert_eq!(
                *crate::state::HasExecutions::executions(&state),
                *crate::state::HasExecutions::executions(&restarted_state),
                "Executions diverged at step {step_idx}"
            );
        }
    }

    #[test]
    fn test_exhaustive_state_serialization_deserialization_step_by_step_in_memory() {
        use crate::{
            common::HasMetadata,
            corpus::{HasCurrentCorpusId, SchedulerTestcaseMetadata},
            executors::target::DualTargetExecutor,
            schedulers::powersched::{PowerQueueScheduler, PowerSchedule},
            stages::push::{
                AflppCmplogTracingStage, CalibrationStage, StdMutationalStage,
                StdPowerMutationalStage,
            },
            state::{HasCurrentStageId, HasExecutionMode},
        };

        let rand = StdRand::with_seed(0x1337_dead_beef);
        // Non-disk-backed in-memory corpus
        let mut corpus = InMemoryCorpus::<BytesInput>::new();
        for i in 0..4 {
            let mut testcase =
                Testcase::new(BytesInput::new(alloc::vec![b'A' + i, b'B', b'C', b'D']));
            testcase.set_exec_time(core::time::Duration::from_millis(1));
            testcase.add_metadata(SchedulerTestcaseMetadata::new(1));
            corpus.add(testcase).unwrap();
        }

        let mut feedback = ConstFeedback::new(false);
        let mut objective = ConstFeedback::new(false);

        // Entire state is in-memory only (no disk corpus)
        let mut state = StdState::new(
            rand,
            corpus,
            InMemoryCorpus::new(),
            &mut feedback,
            &mut objective,
        )
        .unwrap();

        let map_ptr = &raw mut COVERAGE_MAP as *mut u8;
        let observer = unsafe { StdMapObserver::from_mut_ptr("coverage_ex", map_ptr, 16) };
        let mut scheduler = PowerQueueScheduler::new(&mut state, &observer, PowerSchedule::fast());
        for id in state.corpus().ids().collect::<alloc::vec::Vec<_>>() {
            crate::schedulers::Scheduler::on_add(&mut scheduler, &mut state, id).unwrap();
        }

        let make_stages = || {
            let cal = CalibrationStage::with_runs(2);
            let cmp = AflppCmplogTracingStage::new();
            let mut1 = HavocScheduledMutator::new(tuple_list!(BitFlipMutator::new()));
            let mut_stage = StdMutationalStage::new(mut1);
            let mut2 = HavocScheduledMutator::new(tuple_list!(BitFlipMutator::new()));
            let pwr_stage = StdPowerMutationalStage::new(mut2);
            tuple_list!(cal, cmp, mut_stage, pwr_stage)
        };

        let mut engine_main = StdFuzzer::new(
            scheduler,
            ConstFeedback::new(false),
            ConstFeedback::new(false),
            make_stages(),
        );

        let mut mgr = NopEventManager::new();

        let primary = DummyExecutor {
            observers: (observer.clone(), ()),
        };
        let secondary = DummyExecutor {
            observers: (observer.clone(), ()),
        };
        let mut dual_exec = DualTargetExecutor::new(primary, secondary, ExecutionMode::CmpLog);

        // Perform 10 steps, and at EVERY step, serialize, deserialize, and verify 5 steps of identical future progression!
        for checkpoint_idx in 0..10 {
            // Step 1: Step the main engine
            let step_res = FuzzingEngine::<
                NopEventManager,
                BytesInput,
                (StdMapObserver<'static, u8, false>, ()),
                _,
            >::step(&mut engine_main, &mut state, &mut mgr)
            .unwrap();

            match step_res {
                EngineStep::Execute(ref req) => {
                    let res = dual_exec.execute_batch(&req.inputs).unwrap();
                    engine_main
                        .report_observations(&mut state, &mut mgr, res)
                        .unwrap();
                }
                EngineStep::Progress => {}
                EngineStep::Completed => break,
            }

            // Step 2: Serialize State in memory
            let serialized_bytes = postcard::to_allocvec(&state).expect("Serialization failed");

            // Step 3: Deserialize into a fresh isolated State
            let deserialized_state: StdState<
                InMemoryCorpus<BytesInput>,
                BytesInput,
                StdRand,
                InMemoryCorpus<BytesInput>,
            > = postcard::from_bytes(&serialized_bytes).expect("Deserialization failed");

            // Verify basic state fields match immediately upon deserialization
            assert_eq!(
                state.current_corpus_id().unwrap(),
                deserialized_state.current_corpus_id().unwrap(),
                "Checkpoint {checkpoint_idx}: current_corpus_id mismatch"
            );
            assert_eq!(
                state.current_stage_id().unwrap(),
                deserialized_state.current_stage_id().unwrap(),
                "Checkpoint {checkpoint_idx}: current_stage_id mismatch"
            );
            assert_eq!(
                state.execution_mode(),
                deserialized_state.execution_mode(),
                "Checkpoint {checkpoint_idx}: execution_mode mismatch"
            );
            assert_eq!(
                *crate::state::HasExecutions::executions(&state),
                *crate::state::HasExecutions::executions(&deserialized_state),
                "Checkpoint {checkpoint_idx}: executions mismatch"
            );

            // Step 4: Clone the main state & engine to compare against the deserialized state
            let clone_bytes = postcard::to_allocvec(&state).unwrap();
            let mut state_branch_a: StdState<
                InMemoryCorpus<BytesInput>,
                BytesInput,
                StdRand,
                InMemoryCorpus<BytesInput>,
            > = postcard::from_bytes(&clone_bytes).unwrap();
            let mut state_branch_b = deserialized_state;

            let scheduler_a =
                PowerQueueScheduler::new(&mut state_branch_a, &observer, PowerSchedule::fast());
            let scheduler_b =
                PowerQueueScheduler::new(&mut state_branch_b, &observer, PowerSchedule::fast());

            let mut engine_branch_a = StdFuzzer::new(
                scheduler_a,
                ConstFeedback::new(false),
                ConstFeedback::new(false),
                make_stages(),
            );
            let mut engine_branch_b = StdFuzzer::new(
                scheduler_b,
                ConstFeedback::new(false),
                ConstFeedback::new(false),
                make_stages(),
            );

            let primary_a = DummyExecutor {
                observers: (observer.clone(), ()),
            };
            let secondary_a = DummyExecutor {
                observers: (observer.clone(), ()),
            };
            let mut exec_a = DualTargetExecutor::new(primary_a, secondary_a, ExecutionMode::CmpLog);

            let primary_b = DummyExecutor {
                observers: (observer.clone(), ()),
            };
            let secondary_b = DummyExecutor {
                observers: (observer.clone(), ()),
            };
            let mut exec_b = DualTargetExecutor::new(primary_b, secondary_b, ExecutionMode::CmpLog);

            // Advance both branches 5 steps into the future and assert 100% identical outputs
            for future_step in 0..5 {
                let step_a =
                    FuzzingEngine::<
                        NopEventManager,
                        BytesInput,
                        (StdMapObserver<'static, u8, false>, ()),
                        _,
                    >::step(&mut engine_branch_a, &mut state_branch_a, &mut mgr)
                    .unwrap();
                let step_b =
                    FuzzingEngine::<
                        NopEventManager,
                        BytesInput,
                        (StdMapObserver<'static, u8, false>, ()),
                        _,
                    >::step(&mut engine_branch_b, &mut state_branch_b, &mut mgr)
                    .unwrap();

                match (step_a, step_b) {
                    (EngineStep::Execute(req_a), EngineStep::Execute(req_b)) => {
                        assert_eq!(
                            req_a.inputs, req_b.inputs,
                            "Checkpoint {checkpoint_idx} future step {future_step}: inputs diverged! a: {req_a:?}, b: {req_b:?}"
                        );
                        assert_eq!(
                            state_branch_a.execution_mode(),
                            state_branch_b.execution_mode(),
                            "Checkpoint {checkpoint_idx} future step {future_step}: execution mode diverged!"
                        );

                        let res_a = exec_a.execute_batch(&req_a.inputs).unwrap();
                        let res_b = exec_b.execute_batch(&req_b.inputs).unwrap();

                        engine_branch_a
                            .report_observations(&mut state_branch_a, &mut mgr, res_a)
                            .unwrap();
                        engine_branch_b
                            .report_observations(&mut state_branch_b, &mut mgr, res_b)
                            .unwrap();
                    }
                    (EngineStep::Progress, EngineStep::Progress) => {}
                    (EngineStep::Completed, EngineStep::Completed) => break,
                    (other_a, other_b) => {
                        panic!(
                            "Checkpoint {checkpoint_idx} future step {future_step}: step type mismatch! a: {other_a:?}, b: {other_b:?}"
                        );
                    }
                }

                assert_eq!(
                    *crate::state::HasExecutions::executions(&state_branch_a),
                    *crate::state::HasExecutions::executions(&state_branch_b),
                    "Checkpoint {checkpoint_idx} future step {future_step}: executions count diverged!"
                );
            }
        }
    }

    #[test]
    fn test_in_memory_corpus_growth_and_resumption_determinism() {
        use crate::{
            executors::target::StdTargetExecutor, schedulers::QueueScheduler,
            stages::push::StdMutationalStage, state::HasExecutionMode,
        };

        let rand = StdRand::with_seed(0x5ca1ab1e);
        let mut corpus = InMemoryCorpus::<BytesInput>::new();
        corpus
            .add(Testcase::new(BytesInput::new(alloc::vec![1, 2, 3])))
            .unwrap();

        // Feedback that triggers on executions to dynamically grow in-memory corpus
        let mut feedback = ConstFeedback::new(true);
        let mut objective = ConstFeedback::new(false);

        let mut state = StdState::new(
            rand,
            corpus,
            InMemoryCorpus::new(),
            &mut feedback,
            &mut objective,
        )
        .unwrap();

        let map_ptr = &raw mut COVERAGE_MAP as *mut u8;
        let observer = unsafe { StdMapObserver::from_mut_ptr("cov_growth", map_ptr, 16) };
        let mut scheduler = QueueScheduler::new();
        for id in state.corpus().ids().collect::<alloc::vec::Vec<_>>() {
            crate::schedulers::Scheduler::on_add(&mut scheduler, &mut state, id).unwrap();
        }

        let mutator = HavocScheduledMutator::new(tuple_list!(BitFlipMutator::new()));
        let stages = tuple_list!(StdMutationalStage::new(mutator));
        let mut engine_orig = StdFuzzer::new(scheduler, feedback, objective, stages);
        let mut mgr = NopEventManager::new();

        let mut dummy_exec1 = StdTargetExecutor::new(DummyExecutor {
            observers: (observer.clone(), ()),
        });
        let mut dummy_exec2 = StdTargetExecutor::new(DummyExecutor {
            observers: (observer, ()),
        });

        // 1. Run 10 steps on original engine (growing the in-memory corpus)
        for _ in 0..10 {
            match FuzzingEngine::<
                NopEventManager,
                BytesInput,
                (StdMapObserver<'static, u8, false>, ()),
                _,
            >::step(&mut engine_orig, &mut state, &mut mgr)
            .unwrap()
            {
                EngineStep::Execute(req) => {
                    let res = dummy_exec1.execute_batch(&req.inputs).unwrap();
                    engine_orig
                        .report_observations(&mut state, &mut mgr, res)
                        .unwrap();
                }
                EngineStep::Progress => {}
                EngineStep::Completed => break,
            }
        }

        assert!(
            state.corpus().count() > 1,
            "Corpus should have grown in memory"
        );

        // 2. Serialize State to bytes
        let serialized = postcard::to_allocvec(&state).expect("Serialization failed");

        // 3. Deserialize State from bytes
        let mut restarted_state: StdState<
            InMemoryCorpus<BytesInput>,
            BytesInput,
            StdRand,
            InMemoryCorpus<BytesInput>,
        > = postcard::from_bytes(&serialized).expect("Deserialization failed");

        // 4. Create fresh engine on restarted state
        let mutator_rest = HavocScheduledMutator::new(tuple_list!(BitFlipMutator::new()));
        let stages_rest = tuple_list!(StdMutationalStage::new(mutator_rest));
        let mut engine_rest = StdFuzzer::new(
            QueueScheduler::new(),
            ConstFeedback::new(true),
            ConstFeedback::new(false),
            stages_rest,
        );

        // 5. Compare next 25 steps side-by-side
        for step_idx in 0..25 {
            let step_orig = FuzzingEngine::<
                NopEventManager,
                BytesInput,
                (StdMapObserver<'static, u8, false>, ()),
                _,
            >::step(&mut engine_orig, &mut state, &mut mgr)
            .unwrap();
            let step_rest = FuzzingEngine::<
                NopEventManager,
                BytesInput,
                (StdMapObserver<'static, u8, false>, ()),
                _,
            >::step(&mut engine_rest, &mut restarted_state, &mut mgr)
            .unwrap();

            match (step_orig, step_rest) {
                (EngineStep::Execute(req_orig), EngineStep::Execute(req_rest)) => {
                    assert_eq!(
                        req_orig.inputs, req_rest.inputs,
                        "Mismatch at step {step_idx}: inputs diverged"
                    );
                    assert_eq!(
                        state.execution_mode(),
                        restarted_state.execution_mode(),
                        "Mismatch at step {step_idx}: execution_mode diverged"
                    );

                    let res_orig = dummy_exec1.execute_batch(&req_orig.inputs).unwrap();
                    let res_rest = dummy_exec2.execute_batch(&req_rest.inputs).unwrap();

                    engine_orig
                        .report_observations(&mut state, &mut mgr, res_orig)
                        .unwrap();
                    engine_rest
                        .report_observations(&mut restarted_state, &mut mgr, res_rest)
                        .unwrap();
                }
                (EngineStep::Progress, EngineStep::Progress) => {}
                (EngineStep::Completed, EngineStep::Completed) => break,
                (other_orig, other_rest) => {
                    panic!(
                        "Mismatch at step {step_idx}: orig is {other_orig:?}, restarted is {other_rest:?}"
                    );
                }
            }

            assert_eq!(
                *crate::state::HasExecutions::executions(&state),
                *crate::state::HasExecutions::executions(&restarted_state),
                "Executions count diverged at step {step_idx}"
            );
            assert_eq!(
                state.corpus().count(),
                restarted_state.corpus().count(),
                "Corpus count diverged at step {step_idx}"
            );
        }
    }

    #[test]
    fn test_property_randomized_state_serialization_roundtrips_and_invariants() {
        use crate::{
            common::{HasMetadata, HasNamedMetadata},
            corpus::{HasCurrentCorpusId, SchedulerTestcaseMetadata},
            executors::target::StdTargetExecutor,
            schedulers::powersched::{PowerQueueScheduler, PowerSchedule},
            stages::push::{
                CalibrationStage, StageProgressMetadata, StdMutationalStage,
                StdPowerMutationalStage,
            },
            state::{HasCurrentStageId, HasExecutionMode},
        };

        // Run across 4 diverse randomized pseudo-fuzz property trials with different seeds, corpora sizes, and step counts
        let trial_seeds = [
            0x1234_5678_90ab_cdef,
            0xdead_beef_cafe_babe,
            0xfeed_face_0123_4567,
            0x3141_5926_5358_9793,
        ];

        for (trial_idx, &seed) in trial_seeds.iter().enumerate() {
            let rand = StdRand::with_seed(seed);
            let mut corpus = InMemoryCorpus::<BytesInput>::new();
            let num_initial_seeds = 1 + (seed as usize % 5);
            for i in 0..num_initial_seeds {
                let mut tc =
                    Testcase::new(BytesInput::new(alloc::vec![(seed >> (i * 8)) as u8; 4]));
                tc.set_exec_time(core::time::Duration::from_millis(1));
                tc.add_metadata(SchedulerTestcaseMetadata::new(1));
                corpus.add(tc).unwrap();
            }

            let mut feedback = ConstFeedback::new(false);
            let mut objective = ConstFeedback::new(false);

            let mut state = StdState::new(
                rand,
                corpus,
                InMemoryCorpus::new(),
                &mut feedback,
                &mut objective,
            )
            .unwrap();

            let map_ptr = &raw mut COVERAGE_MAP as *mut u8;
            let observer = unsafe { StdMapObserver::from_mut_ptr("cov_prop", map_ptr, 16) };
            let mut scheduler =
                PowerQueueScheduler::new(&mut state, &observer, PowerSchedule::fast());
            for id in state.corpus().ids().collect::<alloc::vec::Vec<_>>() {
                crate::schedulers::Scheduler::on_add(&mut scheduler, &mut state, id).unwrap();
            }

            let make_stages = || {
                let cal = CalibrationStage::with_runs(2);
                let mut1 = HavocScheduledMutator::new(tuple_list!(BitFlipMutator::new()));
                let mut_stage = StdMutationalStage::new(mut1);
                let mut2 = HavocScheduledMutator::new(tuple_list!(BitFlipMutator::new()));
                let pwr_stage = StdPowerMutationalStage::new(mut2);
                tuple_list!(cal, mut_stage, pwr_stage)
            };

            let mut engine = StdFuzzer::new(
                scheduler,
                ConstFeedback::new(false),
                ConstFeedback::new(false),
                make_stages(),
            );

            let mut dummy_exec = StdTargetExecutor::new(DummyExecutor {
                observers: (observer.clone(), ()),
            });
            let mut mgr = NopEventManager::new();

            let num_steps = 6;
            let mut prev_executions = *crate::state::HasExecutions::executions(&state);

            for step_idx in 0..num_steps {
                let step_res = FuzzingEngine::<
                    NopEventManager,
                    BytesInput,
                    (StdMapObserver<'static, u8, false>, ()),
                    _,
                >::step(&mut engine, &mut state, &mut mgr)
                .unwrap();

                // INVARIANT 1: State executions must be monotonically non-decreasing
                let curr_executions = *crate::state::HasExecutions::executions(&state);
                assert!(
                    curr_executions >= prev_executions,
                    "Trial {trial_idx} step {step_idx}: Executions decreased from {prev_executions} to {curr_executions}"
                );
                prev_executions = curr_executions;

                // INVARIANT 2: If stage progress metadata exists, done must never exceed to_do
                if let Ok(progress) =
                    state.named_metadata::<StageProgressMetadata>("stage_progress")
                {
                    assert!(
                        progress.testcases_done <= progress.testcases_to_do,
                        "Trial {trial_idx} step {step_idx}: progress.testcases_done ({}) > progress.testcases_to_do ({})",
                        progress.testcases_done,
                        progress.testcases_to_do
                    );
                }

                // INVARIANT 3: Serialization round-trip must preserve exact state structure and future steps
                let serialized = postcard::to_allocvec(&state).expect("Serialization failed");
                let deserialized_state: StdState<
                    InMemoryCorpus<BytesInput>,
                    BytesInput,
                    StdRand,
                    InMemoryCorpus<BytesInput>,
                > = postcard::from_bytes(&serialized).expect("Deserialization failed");

                assert_eq!(
                    state.current_corpus_id().unwrap(),
                    deserialized_state.current_corpus_id().unwrap(),
                    "Trial {trial_idx} step {step_idx}: current_corpus_id mismatch on roundtrip"
                );
                assert_eq!(
                    state.current_stage_id().unwrap(),
                    deserialized_state.current_stage_id().unwrap(),
                    "Trial {trial_idx} step {step_idx}: current_stage_id mismatch on roundtrip"
                );
                assert_eq!(
                    state.execution_mode(),
                    deserialized_state.execution_mode(),
                    "Trial {trial_idx} step {step_idx}: execution_mode mismatch on roundtrip"
                );
                assert_eq!(
                    *crate::state::HasExecutions::executions(&state),
                    *crate::state::HasExecutions::executions(&deserialized_state),
                    "Trial {trial_idx} step {step_idx}: executions mismatch on roundtrip"
                );

                match step_res {
                    EngineStep::Execute(ref req) => {
                        let res = dummy_exec.execute_batch(&req.inputs).unwrap();
                        engine
                            .report_observations(&mut state, &mut mgr, res)
                            .unwrap();
                    }
                    EngineStep::Progress => {}
                    EngineStep::Completed => break,
                }
            }
        }
    }

    #[test]
    fn test_multi_node_sharing_and_state_migration_determinism() {
        use crate::{
            common::HasMetadata,
            corpus::SchedulerTestcaseMetadata,
            events::NopEventManager,
            executors::target::StdTargetExecutor,
            schedulers::powersched::{PowerQueueScheduler, PowerSchedule},
            stages::push::{CalibrationStage, StdMutationalStage},
            state::HasExecutionMode,
        };

        // Simulate Node A fuzzing, discovering inputs, importing inputs from Node B,
        // migrating state to Node C, and continuing.
        let rand_a = StdRand::with_seed(0xaaa);
        let mut corpus_a = InMemoryCorpus::<BytesInput>::new();
        let mut tc0 = Testcase::new(BytesInput::new(alloc::vec![1, 1, 1]));
        tc0.set_exec_time(core::time::Duration::from_millis(1));
        tc0.add_metadata(SchedulerTestcaseMetadata::new(1));
        corpus_a.add(tc0).unwrap();

        let mut feedback_a = ConstFeedback::new(false);
        let mut objective_a = ConstFeedback::new(false);

        let mut state_a = StdState::new(
            rand_a,
            corpus_a,
            InMemoryCorpus::new(),
            &mut feedback_a,
            &mut objective_a,
        )
        .unwrap();

        let map_ptr = &raw mut COVERAGE_MAP as *mut u8;
        let observer = unsafe { StdMapObserver::from_mut_ptr("cov_share", map_ptr, 16) };
        let mut scheduler_a =
            PowerQueueScheduler::new(&mut state_a, &observer, PowerSchedule::fast());
        for id in state_a.corpus().ids().collect::<alloc::vec::Vec<_>>() {
            crate::schedulers::Scheduler::on_add(&mut scheduler_a, &mut state_a, id).unwrap();
        }

        let make_stages = || {
            let cal = CalibrationStage::with_runs(2);
            let mut1 = HavocScheduledMutator::new(tuple_list!(BitFlipMutator::new()));
            let mut_stage = StdMutationalStage::new(mut1);
            tuple_list!(cal, mut_stage)
        };

        let mut engine_a = StdFuzzer::new(
            scheduler_a,
            ConstFeedback::new(false),
            ConstFeedback::new(false),
            make_stages(),
        );

        let mut dummy_exec_a = StdTargetExecutor::new(DummyExecutor {
            observers: (observer.clone(), ()),
        });
        let mut mgr = NopEventManager::new();

        // Node A runs 5 steps
        for _ in 0..5 {
            match FuzzingEngine::<
                NopEventManager,
                BytesInput,
                (StdMapObserver<'static, u8, false>, ()),
                _,
            >::step(&mut engine_a, &mut state_a, &mut mgr)
            .unwrap()
            {
                EngineStep::Execute(req) => {
                    let res = dummy_exec_a.execute_batch(&req.inputs).unwrap();
                    engine_a
                        .report_observations(&mut state_a, &mut mgr, res)
                        .unwrap();
                }
                EngineStep::Progress => {}
                EngineStep::Completed => break,
            }
        }

        // Simulate incoming shared testcase from Node B
        let mut shared_tc = Testcase::new(BytesInput::new(alloc::vec![2, 2, 2]));
        shared_tc.set_exec_time(core::time::Duration::from_millis(1));
        shared_tc.add_metadata(SchedulerTestcaseMetadata::new(1));
        let new_id = state_a.corpus_mut().add(shared_tc).unwrap();
        // Notify scheduler of newly added testcase
        crate::schedulers::Scheduler::on_add(&mut engine_a.scheduler, &mut state_a, new_id)
            .unwrap();

        // Node A runs another 3 steps with the shared corpus
        for _ in 0..3 {
            match FuzzingEngine::<
                NopEventManager,
                BytesInput,
                (StdMapObserver<'static, u8, false>, ()),
                _,
            >::step(&mut engine_a, &mut state_a, &mut mgr)
            .unwrap()
            {
                EngineStep::Execute(req) => {
                    let res = dummy_exec_a.execute_batch(&req.inputs).unwrap();
                    engine_a
                        .report_observations(&mut state_a, &mut mgr, res)
                        .unwrap();
                }
                EngineStep::Progress => {}
                EngineStep::Completed => break,
            }
        }

        // Now migrate state_a to Node C across serialization boundary
        let node_c_serialized =
            postcard::to_allocvec(&state_a).expect("Migration serialization failed");
        let mut state_c: StdState<
            InMemoryCorpus<BytesInput>,
            BytesInput,
            StdRand,
            InMemoryCorpus<BytesInput>,
        > = postcard::from_bytes(&node_c_serialized).expect("Migration deserialization failed");

        let mut engine_c = StdFuzzer::new(
            PowerQueueScheduler::new(&mut state_c, &observer, PowerSchedule::fast()),
            ConstFeedback::new(false),
            ConstFeedback::new(false),
            make_stages(),
        );

        let mut dummy_exec_c = StdTargetExecutor::new(DummyExecutor {
            observers: (observer, ()),
        });

        // Verify Node A continuation vs Node C execution are 100% identical
        for step_idx in 0..15 {
            let step_a = FuzzingEngine::<
                NopEventManager,
                BytesInput,
                (StdMapObserver<'static, u8, false>, ()),
                _,
            >::step(&mut engine_a, &mut state_a, &mut mgr)
            .unwrap();
            let step_c = FuzzingEngine::<
                NopEventManager,
                BytesInput,
                (StdMapObserver<'static, u8, false>, ()),
                _,
            >::step(&mut engine_c, &mut state_c, &mut mgr)
            .unwrap();

            match (step_a, step_c) {
                (EngineStep::Execute(req_a), EngineStep::Execute(req_c)) => {
                    assert_eq!(
                        req_a.inputs, req_c.inputs,
                        "Mismatch at step {step_idx}: Node A and Node C generated different inputs!"
                    );
                    assert_eq!(
                        state_a.execution_mode(),
                        state_c.execution_mode(),
                        "Mismatch at step {step_idx}: Node A and Node C execution modes diverged!"
                    );

                    let res_a = dummy_exec_a.execute_batch(&req_a.inputs).unwrap();
                    let res_c = dummy_exec_c.execute_batch(&req_c.inputs).unwrap();

                    engine_a
                        .report_observations(&mut state_a, &mut mgr, res_a)
                        .unwrap();
                    engine_c
                        .report_observations(&mut state_c, &mut mgr, res_c)
                        .unwrap();
                }
                (EngineStep::Progress, EngineStep::Progress) => {}
                (EngineStep::Completed, EngineStep::Completed) => break,
                (other_a, other_c) => {
                    panic!("Mismatch at step {step_idx}: a is {other_a:?}, c is {other_c:?}");
                }
            }

            assert_eq!(
                *crate::state::HasExecutions::executions(&state_a),
                *crate::state::HasExecutions::executions(&state_c),
                "Executions diverged at step {step_idx}"
            );
        }
    }

    #[test]
    fn test_async_out_of_order_execution_observations() {
        use libafl_bolts::{rands::StdRand, tuples::tuple_list};

        use crate::{
            corpus::InMemoryCorpus,
            events::NopEventManager,
            feedbacks::ConstFeedback,
            fuzzer::{EngineStep, ExecutionObservation, StdFuzzer},
            inputs::BytesInput,
            observers::StdMapObserver,
            schedulers::QueueScheduler,
            stages::push::CalibrationStage,
            state::StdState,
        };

        let rand = StdRand::with_seed(42);
        let mut corpus = InMemoryCorpus::<BytesInput>::new();
        let tc = Testcase::new(BytesInput::new(alloc::vec![0xAA]));
        corpus.add(tc).unwrap();

        let mut feedback = ConstFeedback::new(false);
        let mut objective = ConstFeedback::new(false);
        let mut state = StdState::new(
            rand,
            corpus,
            InMemoryCorpus::new(),
            &mut feedback,
            &mut objective,
        )
        .unwrap();

        let mut engine = StdFuzzer::new(
            QueueScheduler::new(),
            ConstFeedback::new(false),
            ConstFeedback::new(false),
            tuple_list!(CalibrationStage::with_runs(4)),
        );

        let map_ptr = &raw mut COVERAGE_MAP as *mut u8;
        let observer = unsafe { StdMapObserver::from_mut_ptr("cov_async", map_ptr, 16) };
        let mut mgr = NopEventManager::new();

        // 1. Initial step yields the first execution request with start_id = Some(1)
        let step1 = FuzzingEngine::<
            NopEventManager,
            BytesInput,
            (StdMapObserver<'static, u8, false>, ()),
            _,
        >::step(&mut engine, &mut state, &mut mgr)
        .unwrap();
        let (inputs, start_id) = match step1 {
            EngineStep::Execute(req) => (req.inputs, req.start_id.unwrap()),
            other => panic!("Expected Execute step, got {other:?}"),
        };
        assert_eq!(start_id, 1);
        assert!(!inputs.is_empty());

        // 2. Simulate an async worker returning the execution observation tagged with ID 1
        let obs1 = ExecutionObservation::with_id(1, ExitKind::Ok, (observer.clone(), ()));
        engine
            .report_observations(&mut state, &mut mgr, &[obs1])
            .unwrap();
        let step2 = FuzzingEngine::<
            NopEventManager,
            BytesInput,
            (StdMapObserver<'static, u8, false>, ()),
            _,
        >::step(&mut engine, &mut state, &mut mgr)
        .unwrap();
        assert!(matches!(
            step2,
            EngineStep::Execute(_) | EngineStep::Progress
        ));

        // Verify executions incremented
        assert_eq!(*crate::state::HasExecutions::executions(&state), 1);
    }

    #[test]
    fn test_current_inputs_in_state_and_report_observation() {
        use libafl_bolts::{rands::StdRand, tuples::tuple_list};

        use crate::{
            corpus::InMemoryCorpus,
            events::NopEventManager,
            feedbacks::ConstFeedback,
            fuzzer::{EngineStep, ExecutionObservation, StdFuzzer},
            inputs::BytesInput,
            observers::StdMapObserver,
            schedulers::QueueScheduler,
            stages::push::CalibrationStage,
            state::StdState,
        };

        let rand = StdRand::with_seed(42);
        let mut corpus = InMemoryCorpus::<BytesInput>::new();
        let tc = Testcase::new(BytesInput::new(alloc::vec![0x42, 0x43]));
        corpus.add(tc).unwrap();

        let mut feedback = ConstFeedback::new(false);
        let mut objective = ConstFeedback::new(false);
        let mut state = StdState::new(
            rand,
            corpus,
            InMemoryCorpus::new(),
            &mut feedback,
            &mut objective,
        )
        .unwrap();

        let mut engine = StdFuzzer::new(
            QueueScheduler::new(),
            ConstFeedback::new(false),
            ConstFeedback::new(false),
            tuple_list!(CalibrationStage::with_runs(2)),
        );

        let map_ptr = &raw mut COVERAGE_MAP as *mut u8;
        let observer = unsafe { StdMapObserver::from_mut_ptr("cov_report", map_ptr, 16) };
        let mut mgr = NopEventManager::new();

        // 1. Initial step stages inputs directly into state.current_inputs()
        let step1 = FuzzingEngine::<
            NopEventManager,
            BytesInput,
            (StdMapObserver<'static, u8, false>, ()),
            _,
        >::step(&mut engine, &mut state, &mut mgr)
        .unwrap();
        assert!(matches!(step1, EngineStep::Execute(_)));

        // Assert state holds current inputs (2 calibration runs)
        assert_eq!(state.current_inputs().len(), 2);
        assert_eq!(state.current_inputs()[0].as_ref().as_slice(), &[0x42, 0x43]);

        // 2. Report observation directly via report_observation
        let obs = ExecutionObservation::with_id(1, ExitKind::Ok, (observer, ()));
        engine.report(&mut state, &mut mgr, &obs).unwrap();

        assert_eq!(*crate::state::HasExecutions::executions(&state), 1);
    }

    #[test]
    fn test_time_observer_with_batch_and_parallel_observations() {
        use core::time::Duration;

        use libafl_bolts::{rands::StdRand, tuples::tuple_list};

        use crate::{
            corpus::InMemoryCorpus,
            events::NopEventManager,
            feedbacks::ConstFeedback,
            fuzzer::{EngineStep, ExecutionObservation, StdFuzzer},
            inputs::BytesInput,
            observers::TimeObserver,
            schedulers::QueueScheduler,
            stages::push::CalibrationStage,
            state::StdState,
        };

        let rand = StdRand::with_seed(42);
        let mut corpus = InMemoryCorpus::<BytesInput>::new();
        let tc = Testcase::new(BytesInput::new(alloc::vec![0x77]));
        corpus.add(tc).unwrap();

        let mut feedback = ConstFeedback::new(false);
        let mut objective = ConstFeedback::new(false);
        let mut state = StdState::new(
            rand,
            corpus,
            InMemoryCorpus::new(),
            &mut feedback,
            &mut objective,
        )
        .unwrap();

        let mut engine = StdFuzzer::new(
            QueueScheduler::new(),
            ConstFeedback::new(false),
            ConstFeedback::new(false),
            tuple_list!(CalibrationStage::with_runs(3)),
        );

        let mut mgr = NopEventManager::new();

        // 1. Initial step
        let step1 = FuzzingEngine::<NopEventManager, BytesInput, (TimeObserver, ()), _>::step(
            &mut engine,
            &mut state,
            &mut mgr,
        )
        .unwrap();
        assert!(matches!(step1, EngineStep::Execute(_)));
        assert_eq!(state.current_inputs().len(), 3);

        // 2. Simulate 3 parallel workers returning tagged time observations with distinct runtimes
        let obs1 = ExecutionObservation::with_id(
            1,
            ExitKind::Ok,
            (
                TimeObserver::with_runtime("time", Duration::from_micros(150)),
                (),
            ),
        );
        let obs2 = ExecutionObservation::with_id(
            2,
            ExitKind::Ok,
            (
                TimeObserver::with_runtime("time", Duration::from_micros(250)),
                (),
            ),
        );
        let obs3 = ExecutionObservation::with_id(
            3,
            ExitKind::Ok,
            (
                TimeObserver::with_runtime("time", Duration::from_micros(350)),
                (),
            ),
        );

        // Report in arbitrary out-of-order sequence (Worker 3, Worker 1, Worker 2)
        engine.report(&mut state, &mut mgr, &obs3).unwrap();
        engine.report(&mut state, &mut mgr, &obs1).unwrap();
        engine.report(&mut state, &mut mgr, &obs2).unwrap();

        assert_eq!(*crate::state::HasExecutions::executions(&state), 3);
    }

    #[test]
    fn test_execution_tag_and_post_exec_routing() {
        use alloc::borrow::Cow;

        use libafl_bolts::{Named, rands::StdRand, tuples::tuple_list};

        use crate::{
            corpus::InMemoryCorpus,
            events::NopEventManager,
            feedbacks::ConstFeedback,
            fuzzer::{EngineStep, ExecutionObservation, ExecutionRequest, ExecutionTag, StdFuzzer},
            inputs::{BytesInput, Input},
            observers::TimeObserver,
            schedulers::QueueScheduler,
            stages::push::{Stage, StageStep},
            state::{HasCorpus, HasCurrentTestcase, StdState},
        };

        #[derive(Debug, Default)]
        struct MockPostExecStage {
            name: Cow<'static, str>,
            post_exec_count: usize,
        }

        impl Named for MockPostExecStage {
            fn name(&self) -> &Cow<'static, str> {
                &self.name
            }
        }

        impl<EM, I, OT, S> Stage<EM, I, OT, S> for MockPostExecStage
        where
            I: Input + Clone,
            S: HasCurrentTestcase<I> + HasCorpus<I>,
        {
            fn init(&mut self, _state: &mut S, _manager: &mut EM) -> Result<(), crate::Error> {
                Ok(())
            }

            fn step(
                &mut self,
                state: &mut S,
                _manager: &mut EM,
            ) -> Result<StageStep<I>, crate::Error> {
                if self.post_exec_count > 0 {
                    return Ok(StageStep::Done);
                }
                let input = state.current_input_cloned()?;
                let tag = ExecutionTag::new(0, 100);
                Ok(StageStep::Execute(ExecutionRequest::with_tag(
                    tag,
                    alloc::vec![input],
                )))
            }

            fn post_exec(
                &mut self,
                _state: &mut S,
                _manager: &mut EM,
                _obs: super::BorrowedObservation<'_, I, OT>,
            ) -> Result<(), crate::Error> {
                self.post_exec_count += 1;
                Ok(())
            }

            fn deinit(&mut self, _state: &mut S, _manager: &mut EM) -> Result<(), crate::Error> {
                Ok(())
            }
        }

        let rand = StdRand::with_seed(42);
        let mut corpus = InMemoryCorpus::<BytesInput>::new();
        corpus
            .add(Testcase::new(BytesInput::new(alloc::vec![0x99])))
            .unwrap();

        let mut feedback = ConstFeedback::new(false);
        let mut objective = ConstFeedback::new(false);
        let mut state = StdState::new(
            rand,
            corpus,
            InMemoryCorpus::new(),
            &mut feedback,
            &mut objective,
        )
        .unwrap();

        let stage = MockPostExecStage {
            name: Cow::Borrowed("mock_post_exec"),
            post_exec_count: 0,
        };

        let mut engine = StdFuzzer::new(
            QueueScheduler::new(),
            ConstFeedback::new(false),
            ConstFeedback::new(false),
            tuple_list!(stage),
        );

        let mut mgr = NopEventManager::new();
        let step1 = FuzzingEngine::<NopEventManager, BytesInput, (TimeObserver, ()), _>::step(
            &mut engine,
            &mut state,
            &mut mgr,
        )
        .unwrap();
        assert!(matches!(step1, EngineStep::Execute(_)));

        // Report observation tagged with stage index 0 and input ID 100
        let tag = ExecutionTag::new(0, 100);
        let obs =
            ExecutionObservation::with_tag(tag, ExitKind::Ok, (TimeObserver::new("time"), ()));

        engine.report(&mut state, &mut mgr, &obs).unwrap();
        assert_eq!(*crate::state::HasExecutions::executions(&state), 1);
    }

    #[test]
    fn test_vectorized_mutational_stage_batching_and_fuzz_loop() {
        use libafl_bolts::{rands::StdRand, tuples::tuple_list};

        use crate::{
            corpus::InMemoryCorpus,
            events::NopEventManager,
            executors::target::{FuzzLoop, StdTargetExecutor},
            feedbacks::ConstFeedback,
            fuzzer::{EngineStep, StdFuzzer},
            inputs::BytesInput,
            mutators::{mutations::BitFlipMutator, scheduled::HavocScheduledMutator},
            observers::StdMapObserver,
            schedulers::QueueScheduler,
            stages::push::StdMutationalStage,
            state::{HasExecutions, StdState},
        };

        let rand = StdRand::with_seed(42);
        let mut corpus = InMemoryCorpus::<BytesInput>::new();
        corpus
            .add(Testcase::new(BytesInput::new(alloc::vec![0x10, 0x20])))
            .unwrap();

        let mut feedback = ConstFeedback::new(false);
        let mut objective = ConstFeedback::new(false);
        let mut state = StdState::new(
            rand,
            corpus,
            InMemoryCorpus::new(),
            &mut feedback,
            &mut objective,
        )
        .unwrap();

        // Configure mutational stage with batch size 16
        let mutator = HavocScheduledMutator::new(tuple_list!(BitFlipMutator::new()));
        let stage = StdMutationalStage::with_batch_size(mutator, 16);
        assert_eq!(stage.batch_size(), 16);

        let mut engine = StdFuzzer::new(
            QueueScheduler::new(),
            ConstFeedback::new(false),
            ConstFeedback::new(false),
            tuple_list!(stage),
        );

        let map_ptr = &raw mut COVERAGE_MAP as *mut u8;
        let observer = unsafe { StdMapObserver::from_mut_ptr("cov_batch", map_ptr, 16) };
        let dummy = DummyExecutor {
            observers: (observer, ()),
        };
        let mut target_executor = StdTargetExecutor::new(dummy);

        let mut mgr = NopEventManager::new();

        // 1. Single step yields a batch of 16 inputs
        let step = FuzzingEngine::<
            NopEventManager,
            BytesInput,
            (StdMapObserver<'static, u8, false>, ()),
            _,
        >::step(&mut engine, &mut state, &mut mgr)
        .unwrap();
        let obs = if let EngineStep::Execute(req) = step {
            assert_eq!(req.inputs.len(), 16);
            assert_eq!(req.start_id, Some(1));

            let obs = target_executor.execute_request(&req).unwrap();
            assert_eq!(obs.len(), 16);
            assert_eq!(obs[0].id, Some(1));
            assert_eq!(obs[15].id, Some(16));
            obs
        } else {
            panic!("Expected EngineStep::Execute with batch of 16");
        };

        // Feed step 1 results back into engine so its execution counter increments by 16
        engine
            .report_observations(&mut state, &mut mgr, obs)
            .unwrap();
        assert_eq!(*state.executions(), 16);

        // 2. Drive remaining iterations via FuzzLoop
        let executed =
            FuzzLoop::run_for(&mut engine, &mut target_executor, &mut state, &mut mgr, 32).unwrap();
        assert_eq!(executed, 32);
        assert!(*state.executions() >= 32);
    }

    #[test]
    fn test_dual_target_executor_with_automated_tag_and_id_propagation() {
        use libafl_bolts::rands::StdRand;

        use crate::{
            corpus::InMemoryCorpus,
            executors::target::{DualTargetExecutor, TargetExecutor},
            feedbacks::ConstFeedback,
            fuzzer::{ExecutionRequest, ExecutionTag},
            inputs::BytesInput,
            observers::StdMapObserver,
            state::{HasExecutionMode, StdState},
        };

        let map_ptr = &raw mut COVERAGE_MAP as *mut u8;
        let obs1 = unsafe { StdMapObserver::from_mut_ptr("cov_primary", map_ptr, 16) };
        let obs2 = unsafe { StdMapObserver::from_mut_ptr("cov_secondary", map_ptr, 16) };

        let dummy1 = DummyExecutor {
            observers: (obs1, ()),
        };
        let dummy2 = DummyExecutor {
            observers: (obs2, ()),
        };

        let mut dual = DualTargetExecutor::new(dummy1, dummy2, ExecutionMode::CmpLog);

        let mut feedback = ConstFeedback::new(false);
        let mut objective = ConstFeedback::new(false);
        let mut state = StdState::new(
            StdRand::with_seed(1),
            InMemoryCorpus::<BytesInput>::new(),
            InMemoryCorpus::new(),
            &mut feedback,
            &mut objective,
        )
        .unwrap();

        let tag = ExecutionTag::new(2, 50);
        let req = ExecutionRequest::with_tag(
            tag,
            alloc::vec![
                BytesInput::new(alloc::vec![1]),
                BytesInput::new(alloc::vec![2]),
                BytesInput::new(alloc::vec![3]),
            ],
        );

        // 1. Primary mode execution request
        state.set_execution_mode(ExecutionMode::Normal);
        let obs = dual.execute_request(&req).unwrap();
        assert_eq!(obs.len(), 3);
        assert_eq!(obs[0].id, Some(50));
        assert_eq!(obs[1].id, Some(51));
        assert_eq!(obs[2].id, Some(52));
        assert_eq!(obs[0].tag.unwrap().input_id, 50);
        assert_eq!(obs[1].tag.unwrap().input_id, 51);
        assert_eq!(obs[2].tag.unwrap().input_id, 52);

        // 2. Secondary mode execution request
        state.set_execution_mode(ExecutionMode::CmpLog);
        let obs_sec = dual.execute_request(&req).unwrap();
        assert_eq!(obs_sec.len(), 3);
        assert_eq!(obs_sec[0].id, Some(50));
        assert_eq!(obs_sec[2].tag.unwrap().input_id, 52);
    }

    #[test]
    fn test_report_observations_batch_and_direct_slice_lookup() {
        use libafl_bolts::{rands::StdRand, tuples::tuple_list};

        use crate::{
            corpus::InMemoryCorpus,
            events::NopEventManager,
            feedbacks::ConstFeedback,
            fuzzer::{EngineStep, ExecutionObservation, StdFuzzer},
            inputs::BytesInput,
            observers::StdMapObserver,
            schedulers::QueueScheduler,
            stages::push::CalibrationStage,
            state::StdState,
        };

        let rand = StdRand::with_seed(42);
        let mut corpus = InMemoryCorpus::<BytesInput>::new();
        let tc = Testcase::new(BytesInput::new(alloc::vec![0x11, 0x22]));
        corpus.add(tc).unwrap();

        let mut feedback = ConstFeedback::new(false);
        let mut objective = ConstFeedback::new(false);
        let mut state = StdState::new(
            rand,
            corpus,
            InMemoryCorpus::new(),
            &mut feedback,
            &mut objective,
        )
        .unwrap();

        let mut engine = StdFuzzer::new(
            QueueScheduler::new(),
            ConstFeedback::new(false),
            ConstFeedback::new(false),
            tuple_list!(CalibrationStage::with_runs(3)),
        );

        let map_ptr = &raw mut COVERAGE_MAP as *mut u8;
        let observer = unsafe { StdMapObserver::from_mut_ptr("cov_batch_rep", map_ptr, 16) };
        let mut mgr = NopEventManager::new();

        // 1. First step yields 3 calibration requests starting at ID 1
        let step1 = FuzzingEngine::<
            NopEventManager,
            BytesInput,
            (StdMapObserver<'static, u8, false>, ()),
            _,
        >::step(&mut engine, &mut state, &mut mgr)
        .unwrap();
        assert!(matches!(step1, EngineStep::Execute(_)));
        assert_eq!(state.current_inputs().len(), 3);

        // 2. Report observations in a single batch call via report_observations
        let obs_batch = [
            ExecutionObservation::with_id(1, ExitKind::Ok, (observer.clone(), ())),
            ExecutionObservation::with_id(2, ExitKind::Ok, (observer.clone(), ())),
            ExecutionObservation::with_id(3, ExitKind::Ok, (observer, ())),
        ];

        engine
            .report_observations(&mut state, &mut mgr, &obs_batch)
            .unwrap();

        // Verify executions incremented by 3
        assert_eq!(*crate::state::HasExecutions::executions(&state), 3);
    }

    #[test]
    fn test_parallel_target_executors_with_borrowed_inputs() {
        use alloc::vec::Vec;

        use libafl_bolts::{
            rands::StdRand,
            tuples::{RefIndexable, tuple_list},
        };

        use crate::{
            corpus::InMemoryCorpus,
            events::NopEventManager,
            executors::{
                Executor, ExitKind, HasObservers,
                target::{StdTargetExecutor, TargetExecutor},
            },
            feedbacks::ConstFeedback,
            fuzzer::{EngineStep, ExecutionObservation, StdFuzzer},
            inputs::BytesInput,
            mutators::{mutations::BitFlipMutator, scheduled::HavocScheduledMutator},
            observers::TimeObserver,
            schedulers::QueueScheduler,
            stages::push::StdMutationalStage,
            state::{HasExecutions, StdState},
        };

        #[derive(Debug)]
        struct DummyTimeExecutor {
            observers: (TimeObserver, ()),
        }

        impl HasObservers for DummyTimeExecutor {
            type Observers = (TimeObserver, ());

            fn observers(&self) -> RefIndexable<&Self::Observers, Self::Observers> {
                RefIndexable::from(&self.observers)
            }

            fn observers_mut(&mut self) -> RefIndexable<&mut Self::Observers, Self::Observers> {
                RefIndexable::from(&mut self.observers)
            }
        }

        impl<EM, S, Z> Executor<EM, BytesInput, S, Z> for DummyTimeExecutor {
            fn run_target(
                &mut self,
                _fuzzer: &mut Z,
                _state: &mut S,
                _mgr: &mut EM,
                _input: &BytesInput,
            ) -> Result<ExitKind, libafl_bolts::Error> {
                Ok(ExitKind::Ok)
            }
        }

        let rand = StdRand::with_seed(42);
        let mut corpus = InMemoryCorpus::<BytesInput>::new();
        let tc = Testcase::new(BytesInput::new(alloc::vec![0xAA, 0xBB, 0xCC]));
        corpus.add(tc).unwrap();

        let mut feedback = ConstFeedback::new(false);
        let mut objective = ConstFeedback::new(false);
        let mut state = StdState::new(
            rand,
            corpus,
            InMemoryCorpus::new(),
            &mut feedback,
            &mut objective,
        )
        .unwrap();

        let mutator = HavocScheduledMutator::new(tuple_list!(BitFlipMutator::new()));
        let mut engine = StdFuzzer::new(
            QueueScheduler::new(),
            ConstFeedback::new(false),
            ConstFeedback::new(false),
            tuple_list!(StdMutationalStage::with_batch_size(mutator, 8)),
        );

        let mut mgr = NopEventManager::new();

        // 1. Generate 8 mutational inputs from engine
        let step = FuzzingEngine::<NopEventManager, BytesInput, (TimeObserver, ()), _>::step(
            &mut engine,
            &mut state,
            &mut mgr,
        )
        .unwrap();
        let EngineStep::Execute(req) = step else {
            panic!("Expected Execute request");
        };
        assert_eq!(req.inputs.len(), 8);

        // 2. Spawn 4 parallel worker threads in std::thread::scope
        // Each worker executes 2 borrowed inputs concurrently using its own executor
        let borrowed_inputs: &[BytesInput] = &req.inputs;

        let results: Vec<Vec<ExecutionObservation<(TimeObserver, ())>>> = std::thread::scope(|s| {
            let h1 = s.spawn(|| {
                let _local_state = StdState::new(
                    StdRand::with_seed(101),
                    InMemoryCorpus::<BytesInput>::new(),
                    InMemoryCorpus::new(),
                    &mut ConstFeedback::new(false),
                    &mut ConstFeedback::new(false),
                )
                .unwrap();
                let dummy = DummyTimeExecutor {
                    observers: (TimeObserver::new("time_1"), ()),
                };
                let mut exec = StdTargetExecutor::new(dummy);
                let mut obs_vec = Vec::new();
                for (i, input) in borrowed_inputs[0..2].iter().enumerate() {
                    let mut obs = exec.execute_input(input).unwrap();
                    obs.id = Some(1 + i as u64);
                    obs_vec.push(obs);
                }
                obs_vec
            });

            let h2 = s.spawn(|| {
                let _local_state = StdState::new(
                    StdRand::with_seed(102),
                    InMemoryCorpus::<BytesInput>::new(),
                    InMemoryCorpus::new(),
                    &mut ConstFeedback::new(false),
                    &mut ConstFeedback::new(false),
                )
                .unwrap();
                let dummy = DummyTimeExecutor {
                    observers: (TimeObserver::new("time_2"), ()),
                };
                let mut exec = StdTargetExecutor::new(dummy);
                let mut obs_vec = Vec::new();
                for (i, input) in borrowed_inputs[2..4].iter().enumerate() {
                    let mut obs = exec.execute_input(input).unwrap();
                    obs.id = Some(3 + i as u64);
                    obs_vec.push(obs);
                }
                obs_vec
            });

            let h3 = s.spawn(|| {
                let _local_state = StdState::new(
                    StdRand::with_seed(103),
                    InMemoryCorpus::<BytesInput>::new(),
                    InMemoryCorpus::new(),
                    &mut ConstFeedback::new(false),
                    &mut ConstFeedback::new(false),
                )
                .unwrap();
                let dummy = DummyTimeExecutor {
                    observers: (TimeObserver::new("time_3"), ()),
                };
                let mut exec = StdTargetExecutor::new(dummy);
                let mut obs_vec = Vec::new();
                for (i, input) in borrowed_inputs[4..6].iter().enumerate() {
                    let mut obs = exec.execute_input(input).unwrap();
                    obs.id = Some(5 + i as u64);
                    obs_vec.push(obs);
                }
                obs_vec
            });

            let h4 = s.spawn(|| {
                let _local_state = StdState::new(
                    StdRand::with_seed(104),
                    InMemoryCorpus::<BytesInput>::new(),
                    InMemoryCorpus::new(),
                    &mut ConstFeedback::new(false),
                    &mut ConstFeedback::new(false),
                )
                .unwrap();
                let dummy = DummyTimeExecutor {
                    observers: (TimeObserver::new("time_4"), ()),
                };
                let mut exec = StdTargetExecutor::new(dummy);
                let mut obs_vec = Vec::new();
                for (i, input) in borrowed_inputs[6..8].iter().enumerate() {
                    let mut obs = exec.execute_input(input).unwrap();
                    obs.id = Some(7 + i as u64);
                    obs_vec.push(obs);
                }
                obs_vec
            });

            alloc::vec![
                h1.join().unwrap(),
                h2.join().unwrap(),
                h3.join().unwrap(),
                h4.join().unwrap(),
            ]
        });

        // 3. Flatten observations and report all 8 to the engine in a batch
        let all_obs: Vec<ExecutionObservation<(TimeObserver, ())>> =
            results.into_iter().flatten().collect();
        assert_eq!(all_obs.len(), 8);

        engine
            .report_observations(&mut state, &mut mgr, &all_obs)
            .unwrap();

        // 4. Verify that state recorded 8 executions
        assert_eq!(*state.executions(), 8);
    }

    #[test]
    fn test_fuzz_loop_run_executor_with_live_state_and_manager() {
        use libafl_bolts::{
            rands::StdRand,
            tuples::{RefIndexable, tuple_list},
        };

        use crate::{
            corpus::InMemoryCorpus,
            events::NopEventManager,
            executors::{Executor, ExitKind, HasObservers, target::FuzzLoop},
            feedbacks::ConstFeedback,
            fuzzer::{NopFuzzer, StdFuzzer},
            inputs::BytesInput,
            mutators::{mutations::BitFlipMutator, scheduled::HavocScheduledMutator},
            observers::StdMapObserver,
            schedulers::QueueScheduler,
            stages::push::StdMutationalStage,
            state::{HasExecutions, StdState},
        };

        #[derive(Debug)]
        struct LiveStateExecutor {
            observers: (StdMapObserver<'static, u8, false>, ()),
            executed_count: usize,
        }

        impl HasObservers for LiveStateExecutor {
            type Observers = (StdMapObserver<'static, u8, false>, ());

            fn observers(&self) -> RefIndexable<&Self::Observers, Self::Observers> {
                RefIndexable::from(&self.observers)
            }

            fn observers_mut(&mut self) -> RefIndexable<&mut Self::Observers, Self::Observers> {
                RefIndexable::from(&mut self.observers)
            }
        }

        impl<EM, Z>
            Executor<
                EM,
                BytesInput,
                StdState<
                    InMemoryCorpus<BytesInput>,
                    BytesInput,
                    StdRand,
                    InMemoryCorpus<BytesInput>,
                >,
                Z,
            > for LiveStateExecutor
        {
            fn run_target(
                &mut self,
                _fuzzer: &mut Z,
                state: &mut StdState<
                    InMemoryCorpus<BytesInput>,
                    BytesInput,
                    StdRand,
                    InMemoryCorpus<BytesInput>,
                >,
                _mgr: &mut EM,
                _input: &BytesInput,
            ) -> Result<ExitKind, libafl_bolts::Error> {
                self.executed_count += 1;
                // Live state is accessible and mutable
                assert!(state.corpus().count() >= 1);
                Ok(ExitKind::Ok)
            }
        }

        let rand = StdRand::with_seed(42);
        let mut corpus = InMemoryCorpus::<BytesInput>::new();
        corpus
            .add(Testcase::new(BytesInput::new(alloc::vec![1, 2, 3])))
            .unwrap();

        let mut feedback = ConstFeedback::new(false);
        let mut objective = ConstFeedback::new(false);
        let mut state = StdState::new(
            rand,
            corpus,
            InMemoryCorpus::new(),
            &mut feedback,
            &mut objective,
        )
        .unwrap();

        let mutator = HavocScheduledMutator::new(tuple_list!(BitFlipMutator::new()));
        let mut engine = StdFuzzer::new(
            QueueScheduler::new(),
            ConstFeedback::new(false),
            ConstFeedback::new(false),
            tuple_list!(StdMutationalStage::with_batch_size(mutator, 4)),
        );

        let map_ptr = &raw mut COVERAGE_MAP as *mut u8;
        let observer = unsafe { StdMapObserver::from_mut_ptr("cov_live", map_ptr, 16) };
        let mut live_exec = LiveStateExecutor {
            observers: (observer, ()),
            executed_count: 0,
        };

        let mut mgr = NopEventManager::new();
        let mut fuzzer = NopFuzzer::new();

        let count1 = FuzzLoop::run_executor_for_with_fuzzer(
            &mut engine,
            &mut live_exec,
            &mut state,
            &mut mgr,
            &mut fuzzer,
            8,
        )
        .unwrap();
        let count2 =
            FuzzLoop::run_executor_for(&mut engine, &mut live_exec, &mut state, &mut mgr, 8)
                .unwrap();
        let count = count1 + count2;

        assert_eq!(count, 16);
        assert_eq!(live_exec.executed_count, 16);
        assert_eq!(*state.executions(), 16);
    }

    #[test]
    fn test_parallel_target_executor_automated_batch_partitioning() {
        use libafl_bolts::{rands::StdRand, tuples::tuple_list};

        use crate::{
            corpus::InMemoryCorpus,
            events::NopEventManager,
            executors::{
                ExitKind,
                target::{HarnessTargetExecutor, ParallelTargetExecutor, TargetExecutor},
            },
            feedbacks::ConstFeedback,
            fuzzer::{EngineStep, StdFuzzer},
            inputs::BytesInput,
            mutators::{mutations::BitFlipMutator, scheduled::HavocScheduledMutator},
            observers::TimeObserver,
            schedulers::QueueScheduler,
            stages::push::StdMutationalStage,
            state::{HasExecutions, StdState},
        };

        let rand = StdRand::with_seed(42);
        let mut corpus = InMemoryCorpus::<BytesInput>::new();
        corpus
            .add(Testcase::new(BytesInput::new(alloc::vec![0x10, 0x20])))
            .unwrap();

        let mut feedback = ConstFeedback::new(false);
        let mut objective = ConstFeedback::new(false);
        let mut state = StdState::new(
            rand,
            corpus,
            InMemoryCorpus::new(),
            &mut feedback,
            &mut objective,
        )
        .unwrap();

        let mutator = HavocScheduledMutator::new(tuple_list!(BitFlipMutator::new()));
        let mut engine = StdFuzzer::new(
            QueueScheduler::new(),
            ConstFeedback::new(false),
            ConstFeedback::new(false),
            tuple_list!(StdMutationalStage::with_batch_size(mutator, 32)),
        );

        let mut parallel_executor = ParallelTargetExecutor::new(4, || {
            HarnessTargetExecutor::new(
                |_input: &BytesInput| ExitKind::Ok,
                (TimeObserver::new("parallel_time"), ()),
            )
        });

        assert_eq!(parallel_executor.num_threads(), 4);

        let mut mgr = NopEventManager::new();

        // 1. Generate 32 inputs in a single batch
        let step = FuzzingEngine::<NopEventManager, BytesInput, (TimeObserver, ()), _>::step(
            &mut engine,
            &mut state,
            &mut mgr,
        )
        .unwrap();
        let EngineStep::Execute(req) = step else {
            panic!("Expected EngineStep::Execute with batch of 32");
        };
        assert_eq!(req.inputs.len(), 32);

        // 2. Execute 32 inputs across 4 worker threads automatically
        let obs = parallel_executor.execute_request(&req).unwrap();
        assert_eq!(obs.len(), 32);
        assert_eq!(obs[0].id, Some(1));
        assert_eq!(obs[31].id, Some(32));

        // 3. Report batch observations to engine
        engine
            .report_observations(&mut state, &mut mgr, obs)
            .unwrap();
        assert_eq!(*state.executions(), 32);
    }

    #[test]
    fn test_inprocess_batch_crash_resumption_zero_loss() {
        use crate::{
            corpus::{Corpus, InMemoryCorpus, Testcase},
            events::NopEventManager,
            executors::ExitKind,
            feedbacks::ConstFeedback,
            fuzzer::{EngineStep, FuzzingEngine, StdFuzzer},
            inputs::BytesInput,
            mutators::{mutations::BitFlipMutator, scheduled::HavocScheduledMutator},
            schedulers::QueueScheduler,
            stages::push::StdMutationalStage,
            state::{HasCurrentInputs, HasExecutions, StdState},
        };

        let _inproc_guard = INPROCESS_TEST_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let rand = StdRand::with_seed(999);
        let mut corpus = InMemoryCorpus::<BytesInput>::new();
        corpus
            .add(Testcase::new(BytesInput::new(alloc::vec![1, 2, 3, 4])))
            .unwrap();

        let mut feedback = ConstFeedback::new(false);
        let mut objective = ConstFeedback::new(false);
        let mut state = StdState::new(
            rand,
            corpus,
            InMemoryCorpus::new(),
            &mut feedback,
            &mut objective,
        )
        .unwrap();

        let mut mgr = NopEventManager::new();
        let mutator = HavocScheduledMutator::new(tuple_list!(BitFlipMutator::new()));
        let mut engine = StdFuzzer::new(
            QueueScheduler::new(),
            ConstFeedback::new(false),
            ConstFeedback::new(false),
            tuple_list!(StdMutationalStage::with_batch_size(mutator, 4)),
        );

        let step1 = FuzzingEngine::<NopEventManager, BytesInput, (), _>::step(
            &mut engine,
            &mut state,
            &mut mgr,
        )
        .unwrap();
        let EngineStep::Execute(req) = step1 else {
            panic!("Expected batch Execute step");
        };
        assert_eq!(req.inputs.len(), 4);
        let expected_remaining = vec![req.inputs[2].clone(), req.inputs[3].clone()];

        // Simulate in-process execution of idx = 0 succeeding and idx = 1 crashing
        state.set_current_input_idx(1);
        engine
            .process_execution(
                &mut state,
                &mut mgr,
                super::BorrowedObservation {
                    input: &req.inputs[0],
                    observers: &(),
                    exit_kind: ExitKind::Ok,
                    id: Some(1),
                    tag: req.tag,
                    exec_time: None,
                },
            )
            .unwrap();
        assert_eq!(*state.executions(), 1);

        // Before idx = 1 executes and crashes, current_input_idx is set to 2
        state.set_current_input_idx(2);

        // Simulate process restart with the snapshotted state:
        let mut restarted_engine = StdFuzzer::new(
            QueueScheduler::new(),
            ConstFeedback::new(false),
            ConstFeedback::new(false),
            tuple_list!(StdMutationalStage::with_batch_size(
                HavocScheduledMutator::new(tuple_list!(BitFlipMutator::new())),
                4
            )),
        );

        // First step after restart immediately yields the remaining 2 inputs [I_2, I_3] from the interrupted batch!
        let step2 = FuzzingEngine::<NopEventManager, BytesInput, (), _>::step(
            &mut restarted_engine,
            &mut state,
            &mut mgr,
        )
        .unwrap();
        let EngineStep::Execute(resumed_req) = step2 else {
            panic!("Expected resumed batch Execute step");
        };
        assert_eq!(resumed_req.inputs, expected_remaining);
    }

    #[test]
    fn test_parallel_target_executor_crash_isolation() {
        use crate::{
            executors::{
                ExitKind,
                target::{HarnessTargetExecutor, ParallelTargetExecutor, TargetExecutor},
            },
            fuzzer::ExecutionRequest,
            inputs::BytesInput,
            observers::TimeObserver,
        };

        let mut parallel_executor = ParallelTargetExecutor::new(4, || {
            HarnessTargetExecutor::new(
                |input: &BytesInput| {
                    assert!(
                        input.as_ref().as_slice() != [0xDE, 0xAD],
                        "Simulated crash in worker thread"
                    );
                    ExitKind::Ok
                },
                (TimeObserver::new("parallel_time"), ()),
            )
        });

        let inputs = vec![
            BytesInput::new(vec![1]),
            BytesInput::new(vec![2]),
            BytesInput::new(vec![0xDE, 0xAD]), // Crashes on worker thread
            BytesInput::new(vec![4]),
        ];
        let req = ExecutionRequest::batch(inputs);
        let obs = parallel_executor.execute_request(&req).unwrap();
        assert_eq!(obs.len(), 4);
        assert_eq!(obs[0].exit_kind, ExitKind::Ok);
        assert_eq!(obs[1].exit_kind, ExitKind::Ok);
        assert_eq!(obs[2].exit_kind, ExitKind::Crash);
        assert_eq!(obs[3].exit_kind, ExitKind::Ok);
    }

    #[test]
    fn test_async_sliding_window_replenish_out_of_order() {
        use crate::{
            corpus::{Corpus, InMemoryCorpus, Testcase},
            events::NopEventManager,
            executors::ExitKind,
            feedbacks::ConstFeedback,
            fuzzer::{ExecutionObservation, StdFuzzer},
            inputs::BytesInput,
            mutators::{mutations::BitFlipMutator, scheduled::HavocScheduledMutator},
            schedulers::QueueScheduler,
            stages::push::StdMutationalStage,
            state::{HasExecutions, HasInFlightExecutions, StdState},
        };

        let rand = StdRand::with_seed(12345);
        let mut corpus = InMemoryCorpus::<BytesInput>::new();
        corpus
            .add(Testcase::new(BytesInput::new(alloc::vec![0xAA, 0xBB])))
            .unwrap();

        let mut feedback = ConstFeedback::new(false);
        let mut objective = ConstFeedback::new(false);
        let mut state = StdState::new(
            rand,
            corpus,
            InMemoryCorpus::new(),
            &mut feedback,
            &mut objective,
        )
        .unwrap();

        let mut mgr = NopEventManager::new();
        let mutator = HavocScheduledMutator::new(tuple_list!(BitFlipMutator::new()));
        let mut engine = StdFuzzer::new(
            QueueScheduler::new(),
            ConstFeedback::new(false),
            ConstFeedback::new(false),
            tuple_list!(StdMutationalStage::new(mutator)),
        );

        // 1. Fill initial sliding window of 4 concurrent worker slots using next_n
        let initial_window =
            FuzzingEngine::<_, _, (), _>::next_n(&mut engine, &mut state, &mut mgr, 4).unwrap();
        assert_eq!(initial_window.len(), 4);
        assert_eq!(initial_window[0].id, 1);
        assert_eq!(initial_window[1].id, 2);
        assert_eq!(initial_window[2].id, 3);
        assert_eq!(initial_window[3].id, 4);
        assert_eq!(state.active_inputs_count(), 4);

        // 2. Worker 3 (id=3) and Worker 1 (id=1) finish out of order while Workers 2 and 4 are still running!
        let obs3 = ExecutionObservation::with_id(3, ExitKind::Ok, ());
        let obs1 = ExecutionObservation::with_id(1, ExitKind::Ok, ());

        // Calling report_batch on 2 completed observations returns exactly the next 2 inputs (id=5, id=6)
        // to immediately replenish the 2 free workers:
        let replenished = engine
            .report_batch(&mut state, &mut mgr, &[obs3, obs1])
            .unwrap();

        assert_eq!(*state.executions(), 2);
        assert_eq!(replenished.len(), 2);
        assert_eq!(replenished[0].id, 5);
        assert_eq!(replenished[1].id, 6);
        assert_eq!(state.active_inputs_count(), 4);

        // 3. Remaining 4 in-flight handles (2, 4, 5, 6) complete in arbitrary order
        let obs5 = ExecutionObservation::with_id(5, ExitKind::Ok, ());
        let obs2 = ExecutionObservation::with_id(2, ExitKind::Ok, ());
        let obs6 = ExecutionObservation::with_id(6, ExitKind::Ok, ());
        let obs4 = ExecutionObservation::with_id(4, ExitKind::Ok, ());

        let final_batch = engine
            .report_and_next(&mut state, &mut mgr, &[obs5, obs2, obs6, obs4], 0)
            .unwrap();
        assert!(final_batch.is_empty());
        assert_eq!(*state.executions(), 6);
        assert_eq!(state.active_inputs_count(), 0);
    }

    #[test]
    fn test_active_inputs_persisted_in_state_across_restart() {
        use crate::{
            corpus::{Corpus, InMemoryCorpus, Testcase},
            events::NopEventManager,
            executors::ExitKind,
            feedbacks::ConstFeedback,
            fuzzer::{ExecutionObservation, StdFuzzer},
            inputs::BytesInput,
            mutators::{mutations::BitFlipMutator, scheduled::HavocScheduledMutator},
            schedulers::QueueScheduler,
            stages::push::StdMutationalStage,
            state::{HasExecutions, HasInFlightExecutions, StdState},
        };

        let rand = StdRand::with_seed(999);
        let mut corpus = InMemoryCorpus::<BytesInput>::new();
        corpus
            .add(Testcase::new(BytesInput::new(alloc::vec![0x11, 0x22])))
            .unwrap();

        let mut feedback = ConstFeedback::new(false);
        let mut objective = ConstFeedback::new(false);
        let mut state = StdState::new(
            rand,
            corpus,
            InMemoryCorpus::new(),
            &mut feedback,
            &mut objective,
        )
        .unwrap();

        let mut mgr = NopEventManager::new();
        let mutator = HavocScheduledMutator::new(tuple_list!(BitFlipMutator::new()));
        let mut fuzzer = StdFuzzer::new(
            QueueScheduler::new(),
            ConstFeedback::new(false),
            ConstFeedback::new(false),
            tuple_list!(StdMutationalStage::new(mutator)),
        );

        // 1. Hand out 4 inputs; verify they are stored in state.active_inputs
        let window =
            FuzzingEngine::<_, _, (), _>::next_n(&mut fuzzer, &mut state, &mut mgr, 4).unwrap();
        assert_eq!(window.len(), 4);
        assert_eq!(state.active_inputs_count(), 4);

        // 2. Simulate process crash/restart by serializing and deserializing `state`
        let serialized_state = postcard::to_allocvec(&state).unwrap();
        let mut restarted_state: StdState<
            InMemoryCorpus<BytesInput>,
            BytesInput,
            StdRand,
            InMemoryCorpus<BytesInput>,
        > = postcard::from_bytes(&serialized_state).unwrap();

        // Active inputs survive restart inside `state`!
        assert_eq!(restarted_state.active_inputs_count(), 4);

        // 3. New fuzzer instance in restarted process evaluates out-of-order observations from `restarted_state`
        let mut restarted_fuzzer = StdFuzzer::new(
            QueueScheduler::new(),
            ConstFeedback::new(false),
            ConstFeedback::new(false),
            tuple_list!(StdMutationalStage::new(HavocScheduledMutator::new(
                tuple_list!(BitFlipMutator::new())
            ))),
        );

        let obs3 = ExecutionObservation::with_id(window[2].id, ExitKind::Ok, ());
        let obs1 = ExecutionObservation::with_id(window[0].id, ExitKind::Ok, ());

        restarted_fuzzer
            .report(&mut restarted_state, &mut mgr, &obs3)
            .unwrap();
        restarted_fuzzer
            .report(&mut restarted_state, &mut mgr, &obs1)
            .unwrap();

        assert_eq!(*restarted_state.executions(), 2);
        assert_eq!(restarted_state.active_inputs_count(), 2);
    }

    #[test]
    fn test_inprocess_executor_crash_and_timeout_restart_resumption_with_all_stages() {
        use crate::{
            corpus::{Corpus, InMemoryCorpus, Testcase},
            events::NopEventManager,
            executors::{ExitKind, InProcessExecutor, inprocess::run_observers_and_save_state},
            feedback_or_fast,
            feedbacks::{ConstFeedback, CrashFeedback, TimeoutFeedback},
            fuzzer::StdFuzzer,
            inputs::BytesInput,
            mutators::{
                I2SRandReplace, mutations::BitFlipMutator, scheduled::HavocScheduledMutator,
            },
            observers::TimeObserver,
            schedulers::QueueScheduler,
            stages::push::{CalibrationStage, StdMutationalStage, TracingStage},
            state::{HasExecutions, HasInFlightExecutions, HasSolutions, StdState},
        };

        let _inproc_guard = INPROCESS_TEST_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let rand = StdRand::with_seed(42);
        let mut corpus = InMemoryCorpus::<BytesInput>::new();
        corpus
            .add(Testcase::new(BytesInput::new(alloc::vec![
                0xDE, 0xAD, 0xBE, 0xEF
            ])))
            .unwrap();

        let mut feedback = ConstFeedback::new(false);
        let mut objective = feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new());
        let mut state = StdState::new(
            rand,
            corpus,
            InMemoryCorpus::new(),
            &mut feedback,
            &mut objective,
        )
        .unwrap();

        let mut mgr = NopEventManager::new();

        // Pipeline of CalibrationStage, TracingStage, and StdMutationalStage with I2S mutator
        let stages = tuple_list!(
            CalibrationStage::with_runs(2),
            TracingStage::with_mode(ExecutionMode::CmpLog),
            StdMutationalStage::new(HavocScheduledMutator::new(tuple_list!(
                I2SRandReplace::new(),
                BitFlipMutator::new()
            )))
        );

        let mut fuzzer = StdFuzzer::new(QueueScheduler::new(), feedback, objective, stages);

        let mut harness = |_input: &BytesInput| ExitKind::Ok;
        let mut executor = InProcessExecutor::builder()
            .harness(&mut harness)
            .observers(tuple_list!(TimeObserver::new("time")))
            .fuzzer(&mut fuzzer)
            .state(&mut state)
            .event_mgr(&mut mgr)
            .build()
            .unwrap();

        // 1. Pull next input during CalibrationStage
        let scheduled1 = fuzzer
            .next_with_executor(&executor, &mut state, &mut mgr)
            .unwrap()
            .unwrap();

        // Simulate in-process crash during scheduled1 execution:
        run_observers_and_save_state(
            &mut executor,
            &mut state,
            &scheduled1.input,
            &mut fuzzer,
            &mut mgr,
            ExitKind::Crash,
        );
        assert_eq!(state.solutions().count(), 1);
        assert!(state.pending_exec_time().is_some());

        // Snapshot state across simulated process restart
        let serialized_after_crash = postcard::to_allocvec(&state).unwrap();
        let mut state_after_crash: StdState<
            InMemoryCorpus<BytesInput>,
            BytesInput,
            StdRand,
            InMemoryCorpus<BytesInput>,
        > = postcard::from_bytes(&serialized_after_crash).unwrap();
        assert_eq!(state_after_crash.solutions().count(), 1);
        assert!(state_after_crash.pending_exec_time().is_some());

        // 2. Restarted fuzzer resumes cleanly without re-executing crashed input, advancing through TracingStage & I2S
        let mut restarted_fuzzer = StdFuzzer::new(
            QueueScheduler::new(),
            ConstFeedback::new(false),
            feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new()),
            tuple_list!(
                CalibrationStage::with_runs(2),
                TracingStage::with_mode(ExecutionMode::CmpLog),
                StdMutationalStage::new(HavocScheduledMutator::new(tuple_list!(
                    I2SRandReplace::new(),
                    BitFlipMutator::new()
                )))
            ),
        );

        let mut restarted_executor = InProcessExecutor::builder()
            .harness(&mut harness)
            .observers(tuple_list!(TimeObserver::new("time")))
            .fuzzer(&mut restarted_fuzzer)
            .state(&mut state_after_crash)
            .event_mgr(&mut mgr)
            .build()
            .unwrap();

        // Execute 5 fuzzing iterations across the remaining calibration run, tracing stage, and I2S mutational stage
        restarted_fuzzer
            .fuzz_loop_for(&mut restarted_executor, &mut state_after_crash, &mut mgr, 5)
            .unwrap();
        assert!(*state_after_crash.executions() >= 5);
        assert!(state_after_crash.pending_exec_time().is_none());
        assert_eq!(state_after_crash.active_inputs_count(), 0);

        // 3. Simulate an in-process timeout on the next scheduled input
        let scheduled_tmout = restarted_fuzzer
            .next_with_executor(&restarted_executor, &mut state_after_crash, &mut mgr)
            .unwrap()
            .unwrap();
        run_observers_and_save_state(
            &mut restarted_executor,
            &mut state_after_crash,
            &scheduled_tmout.input,
            &mut restarted_fuzzer,
            &mut mgr,
            ExitKind::Timeout,
        );
        assert_eq!(
            state_after_crash.pending_exit_kind(),
            Some(ExitKind::Timeout)
        );
        assert!(state_after_crash.pending_exec_time().is_some());

        // Verify state snapshots and resumes cleanly after timeout:
        // on restart, next_with_executor evaluates pending_exit_kind via process_execution
        // and records the timeout solution in state_after_tmout.solutions()!
        let serialized_after_tmout = postcard::to_allocvec(&state_after_crash).unwrap();
        let mut state_after_tmout: StdState<
            InMemoryCorpus<BytesInput>,
            BytesInput,
            StdRand,
            InMemoryCorpus<BytesInput>,
        > = postcard::from_bytes(&serialized_after_tmout).unwrap();
        assert!(state_after_tmout.pending_exec_time().is_some());

        let next_after_tmout = restarted_fuzzer
            .next_with_executor(&restarted_executor, &mut state_after_tmout, &mut mgr)
            .unwrap();
        assert!(next_after_tmout.is_some());
        assert_eq!(state_after_tmout.solutions().count(), 2);
        assert!(state_after_tmout.pending_exec_time().is_none());
        assert!(state_after_tmout.active_inputs_count() <= 1);
    }

    #[test]
    #[cfg(all(unix, feature = "std"))]
    fn test_llmp_shared_memory_restart_and_state_restorer_in_depth() {
        use libafl_bolts::{
            ClientId,
            llmp::{LlmpClient, LlmpSharedMap},
            shmem::{ShMemProvider, StdShMem, StdShMemProvider},
            staterestore::StateRestorer,
        };

        use crate::{
            corpus::{Corpus, InMemoryCorpus, Testcase},
            events::{EventRestarter, llmp::LlmpEventManagerBuilder},
            executors::{ExitKind, InProcessExecutor, inprocess::run_observers_and_save_state},
            feedback_or_fast,
            feedbacks::{ConstFeedback, CrashFeedback, TimeoutFeedback},
            fuzzer::StdFuzzer,
            inputs::BytesInput,
            mutators::{mutations::BitFlipMutator, scheduled::HavocScheduledMutator},
            observers::TimeObserver,
            schedulers::QueueScheduler,
            stages::push::{CalibrationStage, StdMutationalStage},
            state::{HasExecutions, HasInFlightExecutions, HasSolutions, StdState},
        };

        // 1. Setup POSIX shared memory provider and LLMP client ringbuffer
        let mut shmem_provider = StdShMemProvider::new().unwrap();
        let mut llmp_client = LlmpClient::new(
            shmem_provider.clone(),
            LlmpSharedMap::new(ClientId(0), shmem_provider.new_shmem(65536).unwrap()),
            ClientId(0),
        )
        .unwrap();
        unsafe {
            llmp_client.mark_safe_to_unmap();
        }

        let mut llmp_mgr = LlmpEventManagerBuilder::new()
            .build_from_client(llmp_client, "llmp_push_fuzzer".into())
            .unwrap();

        let _inproc_guard = INPROCESS_TEST_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let rand = StdRand::with_seed(777);
        let mut corpus = InMemoryCorpus::<BytesInput>::new();
        corpus
            .add(Testcase::new(BytesInput::new(alloc::vec![
                0xCA, 0xFE, 0xBA, 0xBE
            ])))
            .unwrap();

        let mut feedback = ConstFeedback::new(false);
        let mut objective = feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new());
        let mut state = StdState::new(
            rand,
            corpus,
            InMemoryCorpus::new(),
            &mut feedback,
            &mut objective,
        )
        .unwrap();

        let stages = tuple_list!(
            CalibrationStage::with_runs(2),
            StdMutationalStage::new(HavocScheduledMutator::new(tuple_list!(
                BitFlipMutator::new()
            )))
        );
        let mut fuzzer = StdFuzzer::new(QueueScheduler::new(), feedback, objective, stages);

        let mut harness = |_input: &BytesInput| ExitKind::Ok;
        let mut executor = InProcessExecutor::builder()
            .harness(&mut harness)
            .observers(tuple_list!(TimeObserver::new("time")))
            .fuzzer(&mut fuzzer)
            .state(&mut state)
            .event_mgr(&mut llmp_mgr)
            .build()
            .unwrap();

        // 2. Run 2 iterations through LLMP event manager
        fuzzer
            .fuzz_loop_for(&mut executor, &mut state, &mut llmp_mgr, 2)
            .unwrap();
        assert_eq!(*state.executions(), 4);

        // 3. Hand out 3 active inputs and trigger in-process crash on the first one
        let active_window = FuzzingEngine::<_, _, (TimeObserver, ()), _>::next_n(
            &mut fuzzer,
            &mut state,
            &mut llmp_mgr,
            3,
        )
        .unwrap();
        assert_eq!(state.active_inputs_count(), 3);

        run_observers_and_save_state(
            &mut executor,
            &mut state,
            &active_window[0].input,
            &mut fuzzer,
            &mut llmp_mgr,
            ExitKind::Crash,
        );
        assert_eq!(state.solutions().count(), 1);

        // 4. Persist state + LLMP client description into a shared-memory StateRestorer
        let mut staterestorer = StateRestorer::<StdShMem, StdShMemProvider>::new(
            shmem_provider.new_shmem(16 * 1024 * 1024).unwrap(),
        );
        staterestorer.reset();
        staterestorer
            .save(&(&mut state, &llmp_mgr.describe().unwrap()))
            .unwrap();
        assert!(staterestorer.has_content());

        // 5. Respawned child process restores state & LLMP client from shared-memory StateRestorer
        let (mut restored_state, llmp_desc): (
            StdState<InMemoryCorpus<BytesInput>, BytesInput, StdRand, InMemoryCorpus<BytesInput>>,
            _,
        ) = staterestorer.restore().unwrap().unwrap();

        assert_eq!(restored_state.solutions().count(), 1);
        assert_eq!(restored_state.active_inputs_count(), 3);

        let restored_client =
            LlmpClient::existing_client_from_description(shmem_provider, &llmp_desc).unwrap();
        let mut restored_mgr = LlmpEventManagerBuilder::new()
            .build_from_client(restored_client, "llmp_push_fuzzer".into())
            .unwrap();

        // Invoke post-resume restarter hook on restored event manager
        restored_mgr.on_resume(&mut restored_state).unwrap();

        let mut restarted_fuzzer = StdFuzzer::new(
            QueueScheduler::new(),
            ConstFeedback::new(false),
            feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new()),
            tuple_list!(
                CalibrationStage::with_runs(2),
                StdMutationalStage::new(HavocScheduledMutator::new(tuple_list!(
                    BitFlipMutator::new()
                )))
            ),
        );

        let mut restarted_executor = InProcessExecutor::builder()
            .harness(&mut harness)
            .observers(tuple_list!(TimeObserver::new("time")))
            .fuzzer(&mut restarted_fuzzer)
            .state(&mut restored_state)
            .event_mgr(&mut restored_mgr)
            .build()
            .unwrap();

        // 6. Execute 4 more iterations over the restored LLMP channel
        restarted_fuzzer
            .fuzz_loop_for(
                &mut restarted_executor,
                &mut restored_state,
                &mut restored_mgr,
                4,
            )
            .unwrap();
        assert!(*restored_state.executions() >= 6);
    }

    #[test]
    fn test_exact_reproducibility_continuous_vs_restarted_sequence() {
        use crate::{
            corpus::{Corpus, InMemoryCorpus, Testcase},
            events::NopEventManager,
            executors::{ExitKind, InProcessExecutor},
            feedbacks::ConstFeedback,
            fuzzer::{ExecutionObservation, StdFuzzer},
            inputs::BytesInput,
            mutators::{mutations::BitFlipMutator, scheduled::HavocScheduledMutator},
            observers::TimeObserver,
            schedulers::QueueScheduler,
            stages::push::{CalibrationStage, StdMutationalStage},
            state::StdState,
        };

        let build_state = || {
            let _inproc_guard = INPROCESS_TEST_MUTEX
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let rand = StdRand::with_seed(123456);
            let mut corpus = InMemoryCorpus::<BytesInput>::new();
            corpus
                .add(Testcase::new(BytesInput::new(alloc::vec![
                    0x41, 0x42, 0x43, 0x44
                ])))
                .unwrap();
            let mut feedback = ConstFeedback::new(false);
            let mut objective = ConstFeedback::new(false);
            StdState::new(
                rand,
                corpus,
                InMemoryCorpus::new(),
                &mut feedback,
                &mut objective,
            )
            .unwrap()
        };

        let mut mgr = NopEventManager::new();
        let mut harness = |_input: &BytesInput| ExitKind::Ok;

        // --- A. Continuous Run (20 scheduled inputs) ---
        let mut state_continuous = build_state();
        let mut fuzzer_continuous = StdFuzzer::new(
            QueueScheduler::new(),
            ConstFeedback::new(false),
            ConstFeedback::new(false),
            tuple_list!(
                CalibrationStage::with_runs(2),
                StdMutationalStage::new(HavocScheduledMutator::new(tuple_list!(
                    BitFlipMutator::new()
                )))
            ),
        );
        let executor_continuous = InProcessExecutor::builder()
            .harness(&mut harness)
            .observers(tuple_list!(TimeObserver::new("time")))
            .fuzzer(&mut fuzzer_continuous)
            .state(&mut state_continuous)
            .event_mgr(&mut mgr)
            .build()
            .unwrap();

        let mut continuous_seq = alloc::vec::Vec::new();
        for _ in 0..20 {
            let item = fuzzer_continuous
                .next_with_executor(&executor_continuous, &mut state_continuous, &mut mgr)
                .unwrap()
                .unwrap();
            fuzzer_continuous
                .report(
                    &mut state_continuous,
                    &mut mgr,
                    &ExecutionObservation::with_id(
                        item.id,
                        ExitKind::Ok,
                        (TimeObserver::new("time"), ()),
                    ),
                )
                .unwrap();
            continuous_seq.push((item.id, item.input));
        }

        // --- B. Restarted Run (7 inputs -> crash/snapshot/restart -> 13 inputs) ---
        let mut state_restarting = build_state();
        let mut fuzzer_before_crash = StdFuzzer::new(
            QueueScheduler::new(),
            ConstFeedback::new(false),
            ConstFeedback::new(false),
            tuple_list!(
                CalibrationStage::with_runs(2),
                StdMutationalStage::new(HavocScheduledMutator::new(tuple_list!(
                    BitFlipMutator::new()
                )))
            ),
        );
        let executor_before_crash = InProcessExecutor::builder()
            .harness(&mut harness)
            .observers(tuple_list!(TimeObserver::new("time")))
            .fuzzer(&mut fuzzer_before_crash)
            .state(&mut state_restarting)
            .event_mgr(&mut mgr)
            .build()
            .unwrap();

        let mut restarted_seq = alloc::vec::Vec::new();
        for _ in 0..7 {
            let item = fuzzer_before_crash
                .next_with_executor(&executor_before_crash, &mut state_restarting, &mut mgr)
                .unwrap()
                .unwrap();
            fuzzer_before_crash
                .report(
                    &mut state_restarting,
                    &mut mgr,
                    &ExecutionObservation::with_id(
                        item.id,
                        ExitKind::Ok,
                        (TimeObserver::new("time"), ()),
                    ),
                )
                .unwrap();
            restarted_seq.push((item.id, item.input));
        }

        // Snapshot state across simulated process crash and respawn
        let snapshot = postcard::to_allocvec(&state_restarting).unwrap();
        let mut state_after_restart: StdState<
            InMemoryCorpus<BytesInput>,
            BytesInput,
            StdRand,
            InMemoryCorpus<BytesInput>,
        > = postcard::from_bytes(&snapshot).unwrap();

        let mut fuzzer_after_restart = StdFuzzer::new(
            QueueScheduler::new(),
            ConstFeedback::new(false),
            ConstFeedback::new(false),
            tuple_list!(
                CalibrationStage::with_runs(2),
                StdMutationalStage::new(HavocScheduledMutator::new(tuple_list!(
                    BitFlipMutator::new()
                )))
            ),
        );
        let executor_after_restart = InProcessExecutor::builder()
            .harness(&mut harness)
            .observers(tuple_list!(TimeObserver::new("time")))
            .fuzzer(&mut fuzzer_after_restart)
            .state(&mut state_after_restart)
            .event_mgr(&mut mgr)
            .build()
            .unwrap();

        for _ in 7..20 {
            let item = fuzzer_after_restart
                .next_with_executor(&executor_after_restart, &mut state_after_restart, &mut mgr)
                .unwrap()
                .unwrap();
            fuzzer_after_restart
                .report(
                    &mut state_after_restart,
                    &mut mgr,
                    &ExecutionObservation::with_id(
                        item.id,
                        ExitKind::Ok,
                        (TimeObserver::new("time"), ()),
                    ),
                )
                .unwrap();
            restarted_seq.push((item.id, item.input));
        }

        // Verify byte-for-byte reproducibility and identical execution handle IDs across restarts!
        assert_eq!(continuous_seq.len(), 20);
        assert_eq!(restarted_seq.len(), 20);
        assert_eq!(continuous_seq, restarted_seq);
    }

    #[test]
    fn test_std_fuzzer_with_custom_non_bytes_input_and_custom_converter() {
        use alloc::borrow::Cow;
        use core::hash::Hash;

        use serde::{Deserialize, Serialize};

        use crate::{
            Error, StdFuzzer,
            executors::InProcessExecutor,
            inputs::Input,
            mutators::{MutationResult, Mutator},
            observers::TimeObserver,
            state::HasExecutions,
        };

        #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
        struct CustomAstInput {
            node_id: u32,
            symbols: alloc::vec::Vec<alloc::string::String>,
        }

        impl Input for CustomAstInput {}

        struct CustomAstMutator;
        impl libafl_bolts::Named for CustomAstMutator {
            fn name(&self) -> &Cow<'static, str> {
                static NAME: Cow<'static, str> = Cow::Borrowed("CustomAstMutator");
                &NAME
            }
        }

        impl<S> Mutator<CustomAstInput, S> for CustomAstMutator {
            fn mutate(
                &mut self,
                _state: &mut S,
                input: &mut CustomAstInput,
            ) -> Result<MutationResult, Error> {
                input.node_id = input.node_id.wrapping_add(1);
                input.symbols.push(alloc::format!("sym_{}", input.node_id));
                Ok(MutationResult::Mutated)
            }

            fn post_exec(
                &mut self,
                _state: &mut S,
                _new_corpus_id: Option<crate::corpus::CorpusId>,
            ) -> Result<(), Error> {
                Ok(())
            }
        }

        struct CustomAstConverter;
        impl<S> crate::inputs::ToTargetBytesConverter<CustomAstInput, S> for CustomAstConverter {
            fn convert_to_target_bytes<'a>(
                &mut self,
                _state: &mut S,
                input: &'a CustomAstInput,
            ) -> libafl_bolts::ownedref::OwnedSlice<'a, u8> {
                let bytes = alloc::format!("{}:{:?}", input.node_id, input.symbols).into_bytes();
                libafl_bolts::ownedref::OwnedSlice::from(bytes)
            }
        }

        let _inproc_guard = INPROCESS_TEST_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let rand = StdRand::with_seed(0x1337);
        let corpus = InMemoryCorpus::<CustomAstInput>::new();
        let solutions = InMemoryCorpus::<CustomAstInput>::new();
        let mut feedback = ConstFeedback::new(false);
        let mut objective = ConstFeedback::new(false);

        let mut state =
            StdState::new(rand, corpus, solutions, &mut feedback, &mut objective).unwrap();
        state
            .corpus_mut()
            .add(Testcase::new(CustomAstInput {
                node_id: 1,
                symbols: alloc::vec!["root".into()],
            }))
            .unwrap();

        let mut mgr = NopEventManager::new();
        let scheduler = QueueScheduler::new();
        let stages = tuple_list!(StdMutationalStage::new(CustomAstMutator));

        // Create StdFuzzer with custom structured input and custom converter
        let mut fuzzer =
            StdFuzzer::with_converter(scheduler, feedback, objective, stages, CustomAstConverter);

        let mut harness = |input: &CustomAstInput| {
            assert!(!input.symbols.is_empty());
            ExitKind::Ok
        };

        let mut executor = InProcessExecutor::builder()
            .harness(&mut harness)
            .observers(tuple_list!(TimeObserver::new("time")))
            .fuzzer(&mut fuzzer)
            .state(&mut state)
            .event_mgr(&mut mgr)
            .build()
            .unwrap();

        // Run 10 fuzz iterations with the custom structured input
        let iters = fuzzer
            .fuzz_loop_for(&mut executor, &mut state, &mut mgr, 10)
            .unwrap();
        assert_eq!(iters, 10);
        assert_eq!(*state.executions(), 20);

        // Verify state serialization roundtrip with the custom structured input
        let serialized = postcard::to_allocvec(&state).unwrap();
        let mut restored_state: StdState<
            InMemoryCorpus<CustomAstInput>,
            CustomAstInput,
            StdRand,
            InMemoryCorpus<CustomAstInput>,
        > = postcard::from_bytes(&serialized).unwrap();

        assert_eq!(*restored_state.executions(), 20);

        // Continue fuzzing from restored state with custom input
        let iters_after = fuzzer
            .fuzz_loop_for(&mut executor, &mut restored_state, &mut mgr, 5)
            .unwrap();
        assert_eq!(iters_after, 5);
        assert_eq!(*restored_state.executions(), 30);
    }

    #[test]
    fn test_exhaustive_step_by_step_state_restart_determinism() {
        use libafl_bolts::rands::Rand;

        use super::StdFuzzer;
        use crate::{
            common::HasNamedMetadata,
            mutators::mutations::BitFlipMutator,
            stages::push::{
                CalibrationPushStage, ShadowPushStage, StdMutationalPushStage, TracingPushStage,
                TuneableMutationalPushStage,
            },
            state::HasRand,
        };

        let make_fuzzer = || {
            let scheduler = QueueScheduler::new();
            let feedback = ConstFeedback::new(false);
            let objective = ConstFeedback::new(false);
            let stages = tuple_list!(
                CalibrationPushStage::with_runs(2),
                StdMutationalPushStage::new(BitFlipMutator::new()),
                TracingPushStage::with_mode(ExecutionMode::CmpLog),
                ShadowPushStage::new(),
                TuneableMutationalPushStage::new(BitFlipMutator::new())
            );
            StdFuzzer::new(scheduler, feedback, objective, stages)
        };

        let rand = StdRand::with_seed(0xDEC0_DED1);
        let mut corpus = InMemoryCorpus::<BytesInput>::new();
        let id1 = corpus
            .add(Testcase::new(BytesInput::new(alloc::vec![
                0x11, 0x22, 0x33, 0x44
            ])))
            .unwrap();
        let id2 = corpus
            .add(Testcase::new(BytesInput::new(alloc::vec![
                0xAA, 0xBB, 0xCC, 0xDD
            ])))
            .unwrap();

        let mut feedback = ConstFeedback::new(false);
        let mut objective = ConstFeedback::new(false);
        let mut state = StdState::new(
            rand,
            corpus,
            InMemoryCorpus::new(),
            &mut feedback,
            &mut objective,
        )
        .unwrap();

        let mut fuzzer = make_fuzzer();
        crate::schedulers::Scheduler::on_add(fuzzer.scheduler_mut(), &mut state, id1).unwrap();
        crate::schedulers::Scheduler::on_add(fuzzer.scheduler_mut(), &mut state, id2).unwrap();

        // Tune the TuneableMutationalPushStage to 3 iterations so we transition quickly through all stages
        state.add_named_metadata(
            "TuneableMutationalStage",
            crate::stages::tuneable::TuneableMutationalStageMetadata::default(),
        );
        crate::stages::tuneable::set_iters_by_name(&mut state, 3, "TuneableMutationalStage")
            .unwrap();

        let mut mgr = NopEventManager::new();
        let mut last_results: Option<alloc::vec::Vec<ExecutionObservation<()>>> = None;

        // Step 60 times across multiple stages and corpus items, verifying 100% restart determinism at EVERY step
        for step_idx in 0..60 {
            if let Some(obs) = last_results.take() {
                fuzzer
                    .report_observations(&mut state, &mut mgr, &obs)
                    .unwrap();
            }
            // 1. Serialize state before the step
            let serialized = postcard::to_allocvec(&state).unwrap();
            let mut restored_state: StdState<
                InMemoryCorpus<BytesInput>,
                BytesInput,
                StdRand,
                InMemoryCorpus<BytesInput>,
            > = postcard::from_bytes(&serialized).unwrap();

            // 2. Create a brand new fuzzer with freshly instantiated stages
            let mut restarted_fuzzer = make_fuzzer();
            let mut restarted_mgr = NopEventManager::new();

            // 3. Call .step() on continuous fuzzer
            let continuous_step = FuzzingEngine::<NopEventManager, BytesInput, (), _>::step(
                &mut fuzzer,
                &mut state,
                &mut mgr,
            )
            .unwrap();

            // 4. Call .step() on freshly restarted fuzzer with restored state
            let restarted_step = FuzzingEngine::<NopEventManager, BytesInput, (), _>::step(
                &mut restarted_fuzzer,
                &mut restored_state,
                &mut restarted_mgr,
            )
            .unwrap();

            // 5. Assert exact equality of EngineStep, inputs, tags, modes, and RNG state
            match (&continuous_step, &restarted_step) {
                (EngineStep::Execute(req_c), EngineStep::Execute(req_r)) => {
                    assert_eq!(
                        req_c.inputs, req_r.inputs,
                        "Mismatch in RequestInputs at step {step_idx}"
                    );
                    assert_eq!(
                        req_c.start_id, req_r.start_id,
                        "Mismatch in start_id at step {step_idx}"
                    );
                    assert_eq!(req_c.tag, req_r.tag, "Mismatch in tag at step {step_idx}");
                    assert_eq!(
                        req_c.mode(),
                        req_r.mode(),
                        "Mismatch in mode at step {step_idx}"
                    );
                }
                (EngineStep::Progress, EngineStep::Progress) => {}
                (EngineStep::Completed, EngineStep::Completed) => break,
                (c, r) => panic!(
                    "EngineStep variant mismatch at step {step_idx}: continuous={c:?}, restarted={r:?}"
                ),
            }

            // Verify RNG sequence parity after the step
            let mut rand_check_c = *state.rand();
            let mut rand_check_r = *restored_state.rand();
            assert_eq!(
                rand_check_c.next(),
                rand_check_r.next(),
                "RNG state diverged after step {step_idx}"
            );

            // 6. Prepare observations for next step
            last_results = match continuous_step {
                EngineStep::Execute(req) => {
                    let start = req.start_id.unwrap_or(1);
                    Some(
                        (0..req.inputs.len())
                            .map(|i| {
                                ExecutionObservation::with_id(start + i as u64, ExitKind::Ok, ())
                            })
                            .collect(),
                    )
                }
                EngineStep::Progress | EngineStep::Completed => None,
            };
        }
    }

    #[test]
    fn test_decoupled_observer_pre_post_exec_and_timing() {
        use core::time::Duration;

        use libafl_bolts::{ToSlice, ToSliceMut, tuples::tuple_list};

        use crate::{
            corpus::{Corpus, InMemoryCorpus, Testcase},
            events::NopEventManager,
            executors::{Executor, ExitKind, HasObservers},
            feedback_or,
            feedbacks::{MaxMapFeedback, TimeFeedback},
            fuzzer::{FuzzLoop, StdFuzzer, StdTargetExecutor, TargetExecutor},
            inputs::BytesInput,
            mutators::{BitFlipMutator, HavocScheduledMutator},
            observers::{StdMapObserver, TimeObserver},
            schedulers::QueueScheduler,
            stages::push::{CalibrationStage, StdMutationalStage},
            state::{HasCorpus, StdState},
        };

        type TestObservers = (StdMapObserver<'static, u8, false>, (TimeObserver, ()));

        struct MapAndTimeExecutor {
            observers: TestObservers,
            pre_exec_verified_runs: usize,
        }

        impl HasObservers for MapAndTimeExecutor {
            type Observers = TestObservers;

            fn observers(&self) -> RefIndexable<&Self::Observers, Self::Observers> {
                RefIndexable::from(&self.observers)
            }

            fn observers_mut(&mut self) -> RefIndexable<&mut Self::Observers, Self::Observers> {
                RefIndexable::from(&mut self.observers)
            }
        }

        impl<EM, S, Z> Executor<EM, BytesInput, S, Z> for MapAndTimeExecutor {
            fn run_target(
                &mut self,
                _fuzzer: &mut Z,
                _state: &mut S,
                _mgr: &mut EM,
                input: &BytesInput,
            ) -> Result<ExitKind, libafl_bolts::Error> {
                // 1. Verify pre_exec_all was invoked before run_target:
                // The map observer must be reset to all zeroes at the start of run_target,
                // and TimeObserver::last_runtime() must be reset to None.
                assert!(
                    self.observers.0.to_slice().iter().all(|&b| b == 0),
                    "StdMapObserver was not reset by pre_exec_all before run_target"
                );
                assert!(
                    self.observers.1.0.last_runtime().is_none(),
                    "TimeObserver::last_runtime() was not reset to None by pre_exec_all"
                );
                self.pre_exec_verified_runs += 1;

                // Sleep briefly to ensure strictly non-zero execution duration
                std::thread::sleep(Duration::from_micros(50));

                // Populate map observer so next run verifies pre_exec reset it
                let idx = input.as_ref().first().copied().unwrap_or(0) as usize % 16;
                self.observers.0.to_slice_mut()[idx] = 1;
                Ok(ExitKind::Ok)
            }
        }

        let map_obs = StdMapObserver::owned("edges", vec![0u8; 16]);
        let time_obs = TimeObserver::new("time");
        let mut feedback =
            feedback_or!(MaxMapFeedback::new(&map_obs), TimeFeedback::new(&time_obs));
        let mut objective = ();

        // Part 1: Verify StdTargetExecutor calls pre_exec_all and post_exec_all and attaches exec_time
        let mut std_target_exec = StdTargetExecutor::new(MapAndTimeExecutor {
            observers: tuple_list!(map_obs.clone(), time_obs.clone()),
            pre_exec_verified_runs: 0,
        });

        let input1 = BytesInput::new(vec![1]);
        let input2 = BytesInput::new(vec![2]);
        let obs_single = std_target_exec.execute_input(&input1).unwrap();
        assert!(obs_single.exec_time.is_some() && obs_single.exec_time.unwrap() > Duration::ZERO);
        assert!(
            obs_single.observers.1.0.last_runtime().is_some()
                && obs_single.observers.1.0.last_runtime().unwrap() > Duration::ZERO
        );

        let batch_inputs = vec![input1.clone(), input2.clone()];
        let obs_batch = std_target_exec.execute_batch(&batch_inputs).unwrap();
        assert_eq!(obs_batch.len(), 2);
        for obs in obs_batch {
            assert!(obs.exec_time.is_some() && obs.exec_time.unwrap() > Duration::ZERO);
            assert!(
                obs.observers.1.0.last_runtime().is_some()
                    && obs.observers.1.0.last_runtime().unwrap() > Duration::ZERO
            );
        }

        let borrowed_inputs = vec![&input1, &input2];
        let obs_borrowed = std_target_exec
            .execute_borrowed_batch(&borrowed_inputs)
            .unwrap();
        assert_eq!(obs_borrowed.len(), 2);
        for obs in obs_borrowed {
            assert!(obs.exec_time.is_some() && obs.exec_time.unwrap() > Duration::ZERO);
            assert!(
                obs.observers.1.0.last_runtime().is_some()
                    && obs.observers.1.0.last_runtime().unwrap() > Duration::ZERO
            );
        }
        assert_eq!(std_target_exec.inner().pre_exec_verified_runs, 5);

        // Part 2: Verify FuzzLoop::run_executor_for with CalibrationStage and TimeFeedback
        let mut state = StdState::new(
            StdRand::with_seed(42),
            InMemoryCorpus::new(),
            InMemoryCorpus::new(),
            &mut feedback,
            &mut objective,
        )
        .unwrap();
        state
            .corpus_mut()
            .add(Testcase::new(BytesInput::new(vec![0])))
            .unwrap();

        let mut mgr = NopEventManager::new();
        let mut executor = MapAndTimeExecutor {
            observers: tuple_list!(map_obs, time_obs),
            pre_exec_verified_runs: 0,
        };
        let stages = tuple_list!(
            CalibrationStage::new(),
            StdMutationalStage::new(HavocScheduledMutator::new(tuple_list!(
                BitFlipMutator::new()
            )))
        );
        let mut fuzzer = StdFuzzer::new(QueueScheduler::new(), feedback, objective, stages);

        let executed =
            FuzzLoop::run_executor_for(&mut fuzzer, &mut executor, &mut state, &mut mgr, 4)
                .unwrap();
        assert!(executed >= 4);
        assert!(executor.pre_exec_verified_runs >= 4);
        assert!(
            executor.observers.1.0.last_runtime().is_some()
                && executor.observers.1.0.last_runtime().unwrap() > Duration::ZERO
        );

        // Verify that CalibrationStage and TimeFeedback populated exec_time on corpus testcases
        let mut found_calibrated_time = false;
        for id in state.corpus().ids() {
            let tc = state.corpus().get(id).unwrap().borrow();
            if let Some(exec_time) = tc.exec_time() {
                assert!(*exec_time > Duration::ZERO);
                found_calibrated_time = true;
            }
        }
        assert!(
            found_calibrated_time,
            "CalibrationStage / TimeFeedback did not record execution time on corpus testcases"
        );
    }

    #[test]
    fn test_in_place_state_requests_and_inprocess_crash_and_timeout_recovery() {
        use crate::{
            BorrowedObservation, StdFuzzer, feedback_or,
            feedbacks::{CrashFeedback, TimeoutFeedback},
            observers::TimeObserver,
            stages::push::StdMutationalStage,
            state::{HasInFlightExecutions, HasSolutions},
        };

        let rand = StdRand::with_seed(1337);
        let mut corpus = InMemoryCorpus::<BytesInput>::new();
        let id = corpus
            .add(Testcase::new(BytesInput::new(alloc::vec![
                0x11, 0x22, 0x33, 0x44
            ])))
            .unwrap();

        let mut feedback = ConstFeedback::new(false);
        let mut objective = feedback_or!(CrashFeedback::new(), TimeoutFeedback::new());
        let mut state = StdState::new(
            rand,
            corpus,
            InMemoryCorpus::new(),
            &mut feedback,
            &mut objective,
        )
        .unwrap();

        let mut scheduler = QueueScheduler::new();
        crate::schedulers::Scheduler::on_add(&mut scheduler, &mut state, id).unwrap();

        let mutator = HavocScheduledMutator::new(tuple_list!(BitFlipMutator::new()));
        let stage = StdMutationalStage::with_batch_size(mutator, 4);
        let mut fuzzer = StdFuzzer::new(
            scheduler,
            ConstFeedback::new(false),
            feedback_or!(CrashFeedback::new(), TimeoutFeedback::new()),
            tuple_list!(stage),
        );
        let mut mgr = NopEventManager::new();

        // 1. Step engine: populates state.current_inputs() with 4 inputs
        let step1 = FuzzingEngine::<NopEventManager, BytesInput, (), _>::step(
            &mut fuzzer,
            &mut state,
            &mut mgr,
        )
        .unwrap();
        let EngineStep::Execute(req) = step1 else {
            panic!("Expected Execute step");
        };
        assert_eq!(req.inputs.len(), 4);
        assert_eq!(state.current_inputs().len(), 4);
        let batch_snapshot = state.current_inputs().to_vec();

        // 2. Execute input idx = 0 normally
        state.set_current_input_idx(0);
        fuzzer
            .process_execution(
                &mut state,
                &mut mgr,
                BorrowedObservation {
                    input: &batch_snapshot[0],
                    observers: &(),
                    exit_kind: ExitKind::Ok,
                    id: Some(1),
                    tag: req.tag,
                    exec_time: None,
                },
            )
            .unwrap();
        state.set_current_input_idx(1);

        // 3. During execution of input idx = 1, an in-process Crash occurs!
        assert_eq!(state.current_input_idx(), 1);
        let crashing_input = state.current_inputs()[state.current_input_idx()].clone();
        assert_eq!(crashing_input, batch_snapshot[1]);

        let map_ptr = &raw mut COVERAGE_MAP as *mut u8;
        let observer = unsafe { StdMapObserver::from_mut_ptr("cov", map_ptr, 16) };
        let mut dummy_exec = DummyExecutor {
            observers: (TimeObserver::new("time"), (observer, ())),
        };

        // The in-process crash handler runs `run_observers_and_save_state` with ExitKind::Crash
        crate::executors::inprocess::run_observers_and_save_state(
            &mut dummy_exec,
            &mut state,
            &crashing_input,
            &mut fuzzer,
            &mut mgr,
            ExitKind::Crash,
        );
        assert!(state.pending_exec_time().is_some());

        // Simulate restart: deserialize state from saved snapshot
        let serialized_state = postcard::to_allocvec(&state).unwrap();
        let mut restored_state: StdState<
            InMemoryCorpus<BytesInput>,
            BytesInput,
            StdRand,
            InMemoryCorpus<BytesInput>,
        > = postcard::from_bytes(&serialized_state).unwrap();
        assert_eq!(restored_state.solutions().count(), 1);
        assert_eq!(restored_state.current_input_idx(), 2);
        assert!(restored_state.pending_exec_time().is_some());

        // 4. step() resumes directly from index 2 in state.current_inputs(). We probe this on a
        // clone because step() drains the batch; the real recovery flow below drives reconcile
        // *before* step (matching `run_executor_for`), keeping `restored_state` coordinates intact.
        let mut resume_probe = restored_state.clone();
        let step_resume = FuzzingEngine::<NopEventManager, BytesInput, (), _>::step(
            &mut fuzzer,
            &mut resume_probe,
            &mut mgr,
        )
        .unwrap();
        let EngineStep::Execute(req_resume) = step_resume else {
            panic!("Expected Execute step with remaining inputs");
        };
        assert_eq!(req_resume.inputs.len(), 2);
        assert_eq!(req_resume.inputs[0], batch_snapshot[2]);
        assert_eq!(req_resume.inputs[1], batch_snapshot[3]);

        // Reconcile pending_exit_kind and pending_exec_time via next_with_executor
        let next_scheduled = fuzzer
            .next_with_executor(&dummy_exec, &mut restored_state, &mut mgr)
            .unwrap()
            .unwrap();
        assert_eq!(next_scheduled.input, batch_snapshot[2]);
        assert!(restored_state.pending_exec_time().is_none());
        assert_eq!(restored_state.active_inputs_count(), 1);

        // 5. Now simulate an in-process Timeout on input idx = 0 of the resumed batch (batch_snapshot[2])!
        let timeout_input = next_scheduled.input;
        assert_eq!(timeout_input, batch_snapshot[2]);

        crate::executors::inprocess::run_observers_and_save_state(
            &mut dummy_exec,
            &mut restored_state,
            &timeout_input,
            &mut fuzzer,
            &mut mgr,
            ExitKind::Timeout,
        );
        assert!(restored_state.pending_exec_time().is_some());
        assert_eq!(restored_state.active_inputs_count(), 1);

        // Simulate second restart after timeout
        let serialized_state2 = postcard::to_allocvec(&restored_state).unwrap();
        let mut restored_state2: StdState<
            InMemoryCorpus<BytesInput>,
            BytesInput,
            StdRand,
            InMemoryCorpus<BytesInput>,
        > = postcard::from_bytes(&serialized_state2).unwrap();
        assert!(restored_state2.pending_exec_time().is_some());

        // Both the Crash and Timeout solutions are now recorded in solutions!
        assert_eq!(restored_state2.solutions().count(), 2);

        // 6. step() resumes directly at the last remaining input (batch_snapshot[3]); probed on a
        // clone for the same reason as above (step() drains; reconcile must run first).
        let mut resume_probe2 = restored_state2.clone();
        let step_final = FuzzingEngine::<NopEventManager, BytesInput, (), _>::step(
            &mut fuzzer,
            &mut resume_probe2,
            &mut mgr,
        )
        .unwrap();
        let EngineStep::Execute(req_final) = step_final else {
            panic!("Expected Execute step with final input");
        };
        assert_eq!(req_final.inputs.len(), 1);
        assert_eq!(req_final.inputs[0], batch_snapshot[3]);

        // Reconcile pending_exit_kind and pending_exec_time after timeout
        let final_scheduled = fuzzer
            .next_with_executor(&dummy_exec, &mut restored_state2, &mut mgr)
            .unwrap()
            .unwrap();
        assert_eq!(final_scheduled.input, batch_snapshot[3]);
        assert!(restored_state2.pending_exec_time().is_none());
        assert_eq!(restored_state2.active_inputs_count(), 1);
    }
}
