//! Decoupled target executor traits and drivers.
//!
//! Target executors focus exclusively on executing inputs against the target and collecting
//! observations. They are decoupled from the fuzzer loop, corpus, and schedulers.

use alloc::vec::Vec;
use core::fmt::Debug;

use libafl_bolts::Error;

#[cfg(feature = "introspection")]
use crate::monitors::stats::PerfFeature;
use crate::{
    events::NopEventManager,
    executors::{Executor, ExitKind, HasObservers},
    fuzzer::{
        EngineStep, ExecutionMode, ExecutionObservation, ExecutionRequest, FuzzingEngine,
        NopFuzzer, ScheduledInput,
    },
    mark_feature_time,
    observers::ObserversTuple,
    start_timer,
    state::{FuzzerState, MaybeHasClientPerfMonitor},
};

/// Decoupled target executor trait.
///
/// A `TargetExecutor` executes inputs against a target environment (in-process, forkserver,
/// VM, GPU, network, etc.) and produces execution observations without requiring mutable access
/// to the fuzzer state. This allows multiple executors to run concurrently in parallel threads
/// or worker pools borrowing from the same input batch.
pub trait TargetExecutor<I, OT> {
    /// Execute a single borrowed input and return its observation.
    fn execute_input(&mut self, input: &I) -> Result<ExecutionObservation<OT>, Error>;

    /// Execute a scheduled input (preserving its `id` and `tag`) and return the resulting observation.
    fn execute_scheduled(
        &mut self,
        item: &ScheduledInput<I>,
    ) -> Result<ExecutionObservation<OT>, Error> {
        self.execute_input(&item.input)
            .map(|obs| obs.with_id_and_tag(item.id, item.tag))
    }

    /// Execute a slice of borrowed inputs and return observations for each execution.
    fn execute_batch<'a>(
        &'a mut self,
        inputs: &[I],
    ) -> Result<&'a [ExecutionObservation<OT>], Error>;

    /// Execute a slice of borrowed input references and return observations for each execution.
    fn execute_borrowed_batch<'a>(
        &'a mut self,
        inputs: &[&I],
    ) -> Result<&'a [ExecutionObservation<OT>], Error>;

    /// Execute a request (with optional `start_id` / tag / [`ExecutionMode`]) and return observations
    /// with propagated tags/IDs.
    fn execute_request<'a>(
        &'a mut self,
        request: &ExecutionRequest<I>,
    ) -> Result<&'a [ExecutionObservation<OT>], Error> {
        self.execute_batch(&request.inputs)
    }

    /// Return a clone of the executor's current observers tuple, if available.
    fn observers_snapshot(&self) -> Option<OT> {
        None
    }
}

/// A pure, lightweight target executor that executes a borrowed closure harness and records observers.
pub struct HarnessTargetExecutor<H, OT> {
    harness: H,
    observers: OT,
    observations_buf: Vec<ExecutionObservation<OT>>,
}

impl<H: Debug, OT: Debug> Debug for HarnessTargetExecutor<H, OT> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HarnessTargetExecutor")
            .field("observers", &self.observers)
            .finish_non_exhaustive()
    }
}

impl<H, OT> HarnessTargetExecutor<H, OT> {
    /// Create a new harness target executor.
    pub fn new(harness: H, observers: OT) -> Self {
        Self {
            harness,
            observers,
            observations_buf: Vec::new(),
        }
    }

    /// Access the observers.
    pub fn observers(&self) -> &OT {
        &self.observers
    }

    /// Access the observers (mutable).
    pub fn observers_mut(&mut self) -> &mut OT {
        &mut self.observers
    }
}

impl<H, I, OT> TargetExecutor<I, OT> for HarnessTargetExecutor<H, OT>
where
    H: FnMut(&I) -> ExitKind,
    OT: ObserversTuple<I, ()> + Clone,
{
    fn execute_input(&mut self, input: &I) -> Result<ExecutionObservation<OT>, Error> {
        self.observers.pre_exec_all(&mut (), input)?;
        let exec_start = libafl_bolts::current_time();
        let exit_kind = (self.harness)(input);
        let exec_time = libafl_bolts::current_time().checked_sub(exec_start);
        self.observers.post_exec_all(&mut (), input, &exit_kind)?;
        let mut obs = ExecutionObservation::new(exit_kind, self.observers.clone());
        obs.exec_time = exec_time;
        Ok(obs)
    }

    fn execute_batch<'a>(
        &'a mut self,
        inputs: &[I],
    ) -> Result<&'a [ExecutionObservation<OT>], Error> {
        self.observations_buf.clear();
        self.observations_buf.reserve(inputs.len());
        for input in inputs {
            self.observers.pre_exec_all(&mut (), input)?;
            let exec_start = libafl_bolts::current_time();
            let exit_kind = (self.harness)(input);
            let exec_time = libafl_bolts::current_time().checked_sub(exec_start);
            self.observers.post_exec_all(&mut (), input, &exit_kind)?;
            let mut obs = ExecutionObservation::new(exit_kind, self.observers.clone());
            obs.exec_time = exec_time;
            self.observations_buf.push(obs);
        }
        Ok(&self.observations_buf)
    }

    fn execute_borrowed_batch<'a>(
        &'a mut self,
        inputs: &[&I],
    ) -> Result<&'a [ExecutionObservation<OT>], Error> {
        self.observations_buf.clear();
        self.observations_buf.reserve(inputs.len());
        for input in inputs {
            self.observers.pre_exec_all(&mut (), *input)?;
            let exec_start = libafl_bolts::current_time();
            let exit_kind = (self.harness)(*input);
            let exec_time = libafl_bolts::current_time().checked_sub(exec_start);
            self.observers.post_exec_all(&mut (), *input, &exit_kind)?;
            let mut obs = ExecutionObservation::new(exit_kind, self.observers.clone());
            obs.exec_time = exec_time;
            self.observations_buf.push(obs);
        }
        Ok(&self.observations_buf)
    }

    fn execute_request<'a>(
        &'a mut self,
        request: &ExecutionRequest<I>,
    ) -> Result<&'a [ExecutionObservation<OT>], Error> {
        self.observations_buf.clear();
        self.observations_buf.reserve(request.inputs.len());
        for (idx, input) in request.inputs.iter().enumerate() {
            self.observers.pre_exec_all(&mut (), input)?;
            let exec_start = libafl_bolts::current_time();
            let exit_kind = (self.harness)(input);
            let exec_time = libafl_bolts::current_time().checked_sub(exec_start);
            self.observers.post_exec_all(&mut (), input, &exit_kind)?;
            let mut obs = ExecutionObservation::new(exit_kind, self.observers.clone());
            obs.exec_time = exec_time;
            if let Some(start_id) = request.start_id {
                obs.id = Some(start_id + idx as u64);
            }
            if let Some(mut tag) = request.tag {
                tag.input_id += idx as u64;
                obs.tag = Some(tag);
            }
            self.observations_buf.push(obs);
        }
        Ok(&self.observations_buf)
    }

    fn observers_snapshot(&self) -> Option<OT> {
        Some(self.observers.clone())
    }
}

/// A parallel target executor that distributes batches of inputs across worker threads
/// using a factory function to instantiate thread-local target executors.
#[cfg(feature = "std")]
pub struct ParallelTargetExecutor<F, OT, E = ()> {
    factory: F,
    num_threads: usize,
    single_executor: Option<E>,
    observations_buf: Vec<ExecutionObservation<OT>>,
}

#[cfg(feature = "std")]
impl<F: Debug, OT: Debug, E> Debug for ParallelTargetExecutor<F, OT, E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ParallelTargetExecutor")
            .field("num_threads", &self.num_threads)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "std")]
impl<F, OT, E> ParallelTargetExecutor<F, OT, E> {
    /// Create a new parallel target executor with a given number of worker threads and executor factory.
    pub fn new(num_threads: usize, factory: F) -> Self {
        let num_threads = if num_threads == 0 {
            std::thread::available_parallelism().map_or(1, core::num::NonZero::get)
        } else {
            num_threads
        };
        Self {
            factory,
            num_threads,
            single_executor: None,
            observations_buf: Vec::new(),
        }
    }

    /// Access the configured number of threads.
    pub fn num_threads(&self) -> usize {
        self.num_threads
    }
}

#[cfg(feature = "std")]
impl<F, E, I, OT> TargetExecutor<I, OT> for ParallelTargetExecutor<F, OT, E>
where
    F: Fn() -> E + Sync + Send,
    E: TargetExecutor<I, OT>,
    I: Sync,
    OT: Send + Clone,
{
    fn execute_input(&mut self, input: &I) -> Result<ExecutionObservation<OT>, Error> {
        let executor = self.single_executor.get_or_insert_with(&self.factory);
        executor.execute_input(input)
    }

    fn execute_batch<'a>(
        &'a mut self,
        inputs: &[I],
    ) -> Result<&'a [ExecutionObservation<OT>], Error> {
        if inputs.is_empty() {
            self.observations_buf.clear();
            return Ok(&self.observations_buf);
        }
        if inputs.len() == 1 || self.num_threads <= 1 {
            let executor = self.single_executor.get_or_insert_with(&self.factory);
            let obs = executor.execute_batch(inputs)?;
            self.observations_buf.clear();
            self.observations_buf.extend_from_slice(obs);
            return Ok(&self.observations_buf);
        }

        let factory = &self.factory;
        let chunk_size = inputs.len().div_ceil(self.num_threads);
        let results: Vec<Vec<ExecutionObservation<OT>>> = std::thread::scope(|s| {
            let mut handles = Vec::new();
            for chunk in inputs.chunks(chunk_size) {
                let handle = s.spawn(move || {
                    let mut executor = factory();
                    executor.execute_batch(chunk).map(<[_]>::to_vec)
                });
                handles.push(handle);
            }
            handles
                .into_iter()
                .map(|h| h.join().unwrap())
                .collect::<Result<Vec<_>, Error>>()
        })?;

        self.observations_buf.clear();
        self.observations_buf.reserve(inputs.len());
        for res in results {
            self.observations_buf.extend(res);
        }
        Ok(&self.observations_buf)
    }

    fn execute_borrowed_batch<'a>(
        &'a mut self,
        inputs: &[&I],
    ) -> Result<&'a [ExecutionObservation<OT>], Error> {
        if inputs.is_empty() {
            self.observations_buf.clear();
            return Ok(&self.observations_buf);
        }
        if inputs.len() == 1 || self.num_threads <= 1 {
            let executor = self.single_executor.get_or_insert_with(&self.factory);
            let obs = executor.execute_borrowed_batch(inputs)?;
            self.observations_buf.clear();
            self.observations_buf.extend_from_slice(obs);
            return Ok(&self.observations_buf);
        }

        let factory = &self.factory;
        let chunk_size = inputs.len().div_ceil(self.num_threads);
        let results: Vec<Vec<ExecutionObservation<OT>>> = std::thread::scope(|s| {
            let mut handles = Vec::new();
            for chunk in inputs.chunks(chunk_size) {
                let handle = s.spawn(move || {
                    let mut executor = factory();
                    executor.execute_borrowed_batch(chunk).map(<[_]>::to_vec)
                });
                handles.push(handle);
            }
            handles
                .into_iter()
                .map(|h| h.join().unwrap())
                .collect::<Result<Vec<_>, Error>>()
        })?;

        self.observations_buf.clear();
        self.observations_buf.reserve(inputs.len());
        for res in results {
            self.observations_buf.extend(res);
        }
        Ok(&self.observations_buf)
    }

    fn execute_request<'a>(
        &'a mut self,
        request: &ExecutionRequest<I>,
    ) -> Result<&'a [ExecutionObservation<OT>], Error> {
        if request.inputs.is_empty() {
            self.observations_buf.clear();
            return Ok(&self.observations_buf);
        }
        if request.inputs.len() == 1 || self.num_threads <= 1 {
            let executor = self.single_executor.get_or_insert_with(&self.factory);
            let obs = executor.execute_request(request)?;
            self.observations_buf.clear();
            self.observations_buf.extend_from_slice(obs);
            return Ok(&self.observations_buf);
        }

        let factory = &self.factory;
        let chunk_size = request.inputs.len().div_ceil(self.num_threads);
        let results: Vec<Vec<ExecutionObservation<OT>>> = std::thread::scope(|s| {
            let mut handles = Vec::new();
            let mut offset = 0;
            for chunk in request.inputs.chunks(chunk_size) {
                let chunk_refs: Vec<&I> = chunk.iter().collect();
                let start_id = request.start_id.map(|sid| sid + offset as u64);
                let tag = request.tag.map(|mut t| {
                    t.input_id += offset as u64;
                    t
                });

                let handle = s.spawn(move || {
                    let mut executor = factory();
                    let raw_obs = if let Ok(res) =
                        std::panic::catch_unwind(core::panic::AssertUnwindSafe(|| {
                            executor
                                .execute_borrowed_batch(&chunk_refs)
                                .map(<[_]>::to_vec)
                        })) {
                        res?
                    } else {
                        let mut recovered = Vec::with_capacity(chunk_refs.len());
                        let mut sample_obs: Option<OT> = executor.observers_snapshot();
                        for input in &chunk_refs {
                            executor = factory();
                            if sample_obs.is_none() {
                                sample_obs = executor.observers_snapshot();
                            }
                            match std::panic::catch_unwind(core::panic::AssertUnwindSafe(|| {
                                executor.execute_input(*input)
                            })) {
                                Ok(Ok(obs)) => {
                                    if sample_obs.is_none() {
                                        sample_obs = Some(obs.observers.clone());
                                    }
                                    recovered.push(obs);
                                }
                                Ok(Err(e)) => return Err(e),
                                Err(_) => {
                                    if let Some(ref sample) = sample_obs {
                                        recovered.push(ExecutionObservation::new(
                                            ExitKind::Crash,
                                            sample.clone(),
                                        ));
                                    }
                                }
                            }
                        }
                        recovered
                    };
                    let mut tagged_obs = raw_obs;
                    for (i, item) in tagged_obs.iter_mut().enumerate() {
                        if let Some(sid) = start_id {
                            item.id = Some(sid + i as u64);
                        }
                        if let Some(mut t) = tag {
                            t.input_id += i as u64;
                            item.tag = Some(t);
                        }
                    }
                    Ok(tagged_obs)
                });
                handles.push(handle);
                offset += chunk.len();
            }
            handles
                .into_iter()
                .map(|h| h.join().unwrap())
                .collect::<Result<Vec<_>, Error>>()
        })?;

        self.observations_buf.clear();
        self.observations_buf.reserve(request.inputs.len());
        for res in results {
            self.observations_buf.extend(res);
        }
        Ok(&self.observations_buf)
    }
}

/// Standard wrapper adapting an out-of-process or stateless [`Executor`] into a [`TargetExecutor`].
///
/// # Safety and In-Process Executors
/// This adapter runs with an ephemeral dummy state (`S::default()`) and is intended for
/// out-of-process, command, or forkserver executors (such as `ForkserverExecutor`).
/// For [`InProcessExecutor`](crate::executors::InProcessExecutor), do not use `StdTargetExecutor`;
/// instead, drive the executor directly with [`FuzzLoop::run_executor`] or [`FuzzLoop::run_executor_for`]
/// to provide live `&mut state` references to process-wide crash and timeout signal handlers.
#[derive(Debug)]
pub struct StdTargetExecutor<E: HasObservers, S = ()> {
    inner: E,
    state: S,
    observations_buf: Vec<ExecutionObservation<E::Observers>>,
}

impl<E: HasObservers> StdTargetExecutor<E, ()> {
    /// Wrap an executor.
    pub const fn new(inner: E) -> Self {
        Self {
            inner,
            state: (),
            observations_buf: Vec::new(),
        }
    }
}

impl<E: HasObservers, S: Default> StdTargetExecutor<E, S> {
    /// Wrap an executor with a default-initialized state type.
    pub fn with_state(inner: E) -> Self {
        Self {
            inner,
            state: S::default(),
            observations_buf: Vec::new(),
        }
    }
}

impl<E: HasObservers, S> StdTargetExecutor<E, S> {
    /// Wrap an executor with an explicitly provided state value.
    pub const fn with_custom_state(inner: E, state: S) -> Self {
        Self {
            inner,
            state,
            observations_buf: Vec::new(),
        }
    }

    /// Access the underlying executor.
    pub fn inner(&self) -> &E {
        &self.inner
    }

    /// Access the underlying executor (mutable).
    pub fn inner_mut(&mut self) -> &mut E {
        &mut self.inner
    }

    /// Access the persistent local state.
    pub fn state(&self) -> &S {
        &self.state
    }

    /// Access the persistent local state (mutable).
    pub fn state_mut(&mut self) -> &mut S {
        &mut self.state
    }
}

impl<E, I, S> TargetExecutor<I, E::Observers> for StdTargetExecutor<E, S>
where
    E: HasObservers + Executor<NopEventManager, I, S, NopFuzzer>,
    E::Observers: ObserversTuple<I, S> + Clone,
    I: Debug,
{
    fn execute_input(&mut self, input: &I) -> Result<ExecutionObservation<E::Observers>, Error> {
        let mut nop_fuzzer = NopFuzzer::new();
        let mut nop_mgr = NopEventManager::new();
        self.inner
            .observers_mut()
            .pre_exec_all(&mut self.state, input)?;
        let exec_start = libafl_bolts::current_time();
        let exit_kind =
            self.inner
                .run_target(&mut nop_fuzzer, &mut self.state, &mut nop_mgr, input)?;
        let exec_time = libafl_bolts::current_time().checked_sub(exec_start);
        self.inner
            .observers_mut()
            .post_exec_all(&mut self.state, input, &exit_kind)?;
        let observers = (*self.inner.observers()).clone();
        let mut obs = ExecutionObservation::new(exit_kind, observers);
        obs.exec_time = exec_time;
        Ok(obs)
    }

    fn execute_batch<'a>(
        &'a mut self,
        inputs: &[I],
    ) -> Result<&'a [ExecutionObservation<E::Observers>], Error> {
        self.observations_buf.clear();
        self.observations_buf.reserve(inputs.len());
        let mut nop_fuzzer = NopFuzzer::new();
        let mut nop_mgr = NopEventManager::new();

        for input in inputs {
            self.inner
                .observers_mut()
                .pre_exec_all(&mut self.state, input)?;
            let exec_start = libafl_bolts::current_time();
            let exit_kind =
                self.inner
                    .run_target(&mut nop_fuzzer, &mut self.state, &mut nop_mgr, input)?;
            let exec_time = libafl_bolts::current_time().checked_sub(exec_start);
            self.inner
                .observers_mut()
                .post_exec_all(&mut self.state, input, &exit_kind)?;
            let observers = (*self.inner.observers()).clone();
            let mut obs = ExecutionObservation::new(exit_kind, observers);
            obs.exec_time = exec_time;
            self.observations_buf.push(obs);
        }

        Ok(&self.observations_buf)
    }

    fn execute_borrowed_batch<'a>(
        &'a mut self,
        inputs: &[&I],
    ) -> Result<&'a [ExecutionObservation<E::Observers>], Error> {
        self.observations_buf.clear();
        self.observations_buf.reserve(inputs.len());
        let mut nop_fuzzer = NopFuzzer::new();
        let mut nop_mgr = NopEventManager::new();

        for input in inputs {
            self.inner
                .observers_mut()
                .pre_exec_all(&mut self.state, *input)?;
            let exec_start = libafl_bolts::current_time();
            let exit_kind =
                self.inner
                    .run_target(&mut nop_fuzzer, &mut self.state, &mut nop_mgr, *input)?;
            let exec_time = libafl_bolts::current_time().checked_sub(exec_start);
            self.inner
                .observers_mut()
                .post_exec_all(&mut self.state, *input, &exit_kind)?;
            let observers = (*self.inner.observers()).clone();
            let mut obs = ExecutionObservation::new(exit_kind, observers);
            obs.exec_time = exec_time;
            self.observations_buf.push(obs);
        }

        Ok(&self.observations_buf)
    }

    fn execute_request<'a>(
        &'a mut self,
        request: &ExecutionRequest<I>,
    ) -> Result<&'a [ExecutionObservation<E::Observers>], Error> {
        self.observations_buf.clear();
        self.observations_buf.reserve(request.inputs.len());
        let mut nop_fuzzer = NopFuzzer::new();
        let mut nop_mgr = NopEventManager::new();

        for (idx, input) in request.inputs.iter().enumerate() {
            self.inner
                .observers_mut()
                .pre_exec_all(&mut self.state, input)?;
            let exec_start = libafl_bolts::current_time();
            let exit_kind =
                self.inner
                    .run_target(&mut nop_fuzzer, &mut self.state, &mut nop_mgr, input)?;
            let exec_time = libafl_bolts::current_time().checked_sub(exec_start);
            self.inner
                .observers_mut()
                .post_exec_all(&mut self.state, input, &exit_kind)?;
            let observers = (*self.inner.observers()).clone();
            let mut obs = ExecutionObservation::new(exit_kind, observers);
            obs.exec_time = exec_time;

            if let Some(start_id) = request.start_id {
                obs.id = Some(start_id + idx as u64);
            }
            if let Some(mut tag) = request.tag {
                tag.input_id += idx as u64;
                obs.tag = Some(tag);
            }

            self.observations_buf.push(obs);
        }

        Ok(&self.observations_buf)
    }
}

/// A dual target executor that routes executions to a primary executor (for standard coverage runs)
/// or a secondary specialized executor (when the request's [`ExecutionMode`] matches the
/// secondary mode).
#[derive(Debug)]
pub struct DualTargetExecutor<E1, E2> {
    primary: E1,
    secondary: E2,
    secondary_mode: ExecutionMode,
}

impl<E1, E2> DualTargetExecutor<E1, E2> {
    /// Create a new dual target executor routing the given [`ExecutionMode`] to `secondary`.
    ///
    /// # Panics
    /// Panics (or fails at compile time when evaluated in a `const` context) if `secondary_mode` is
    /// [`ExecutionMode::Normal`], which is the primary executor's mode and would render the primary
    /// unreachable.
    pub const fn new(primary: E1, secondary: E2, secondary_mode: ExecutionMode) -> Self {
        assert!(
            !secondary_mode.is_normal(),
            "DualTargetExecutor: secondary_mode cannot be ExecutionMode::Normal (that is the primary executor's mode)"
        );
        Self {
            primary,
            secondary,
            secondary_mode,
        }
    }

    /// Create a dual target executor routing [`ExecutionMode::CmpLog`] to `secondary`.
    pub const fn cmplog(primary: E1, secondary: E2) -> Self {
        Self::new(primary, secondary, ExecutionMode::CmpLog)
    }

    /// Create a dual target executor routing [`ExecutionMode::Tracing`] to `secondary`.
    pub const fn tracing(primary: E1, secondary: E2) -> Self {
        Self::new(primary, secondary, ExecutionMode::Tracing)
    }

    /// Access the primary executor.
    pub fn primary(&self) -> &E1 {
        &self.primary
    }

    /// Access the primary executor (mutable).
    pub fn primary_mut(&mut self) -> &mut E1 {
        &mut self.primary
    }

    /// Access the secondary executor.
    pub fn secondary(&self) -> &E2 {
        &self.secondary
    }

    /// Access the secondary executor (mutable).
    pub fn secondary_mut(&mut self) -> &mut E2 {
        &mut self.secondary
    }

    /// The [`ExecutionMode`] routed to the secondary executor.
    pub const fn secondary_mode(&self) -> ExecutionMode {
        self.secondary_mode
    }
}

impl<E1, E2, I, OT> TargetExecutor<I, OT> for DualTargetExecutor<E1, E2>
where
    E1: TargetExecutor<I, OT>,
    E2: TargetExecutor<I, OT>,
    OT: Clone,
{
    fn execute_input(&mut self, input: &I) -> Result<ExecutionObservation<OT>, Error> {
        self.primary.execute_input(input)
    }

    fn execute_scheduled(
        &mut self,
        item: &ScheduledInput<I>,
    ) -> Result<ExecutionObservation<OT>, Error> {
        if item.mode() == self.secondary_mode {
            self.secondary.execute_scheduled(item)
        } else {
            self.primary.execute_scheduled(item)
        }
    }

    fn execute_batch<'a>(
        &'a mut self,
        inputs: &[I],
    ) -> Result<&'a [ExecutionObservation<OT>], Error> {
        self.primary.execute_batch(inputs)
    }

    fn execute_borrowed_batch<'a>(
        &'a mut self,
        inputs: &[&I],
    ) -> Result<&'a [ExecutionObservation<OT>], Error> {
        self.primary.execute_borrowed_batch(inputs)
    }

    fn execute_request<'a>(
        &'a mut self,
        request: &ExecutionRequest<I>,
    ) -> Result<&'a [ExecutionObservation<OT>], Error> {
        if request.mode() == self.secondary_mode {
            self.secondary.execute_request(request)
        } else {
            self.primary.execute_request(request)
        }
    }
}

/// A target executor that accepts inputs for execution and returns observations *out of order*.
///
/// Where a [`TargetExecutor`] runs an input to completion before returning, an
/// `AsyncTargetExecutor` decouples submission from completion: [`submit`](Self::submit) hands an
/// input to a worker and returns immediately, and [`poll`](Self::poll) / [`wait`](Self::wait)
/// collect whichever executions have finished, in whatever order they finished in.
///
/// Correlation is by handle: every returned [`ExecutionObservation`] carries the
/// [`ScheduledInput::id`] of the input that produced it, and its
/// [`ExecutionTag`](crate::fuzzer::ExecutionTag), so the engine can match results back to the
/// stage and testcase that generated them regardless of completion order.
///
/// Drive one with [`AsyncFuzzLoop`], or by hand:
///
/// ```ignore
/// while let batch = fuzzer.next_n(&mut state, &mut mgr, pool.free_capacity())? {
///     for scheduled in batch {
///         pool.submit(scheduled)?;
///     }
///     fuzzer.report_observations(&mut state, &mut mgr, pool.wait()?)?;
/// }
/// ```
pub trait AsyncTargetExecutor<I, OT> {
    /// The maximum number of executions that may be in flight at once.
    fn capacity(&self) -> usize;

    /// The number of executions submitted but not yet collected.
    fn in_flight(&self) -> usize;

    /// How many more executions [`Self::submit`] accepts right now.
    fn free_capacity(&self) -> usize {
        self.capacity().saturating_sub(self.in_flight())
    }

    /// Hand a scheduled input to a worker without waiting for it to run.
    ///
    /// # Errors
    /// Returns [`Error::illegal_state`] if the executor is already at capacity, or if no worker
    /// is able to accept the input.
    fn submit(&mut self, scheduled: ScheduledInput<I>) -> Result<(), Error>;

    /// Collect every execution that has finished so far. Never blocks; may return an empty slice.
    ///
    /// # Errors
    /// Returns the first error reported by a worker.
    fn poll(&mut self) -> Result<&[ExecutionObservation<OT>], Error>;

    /// Block until at least one in-flight execution finishes, then collect all finished ones.
    ///
    /// Returns an empty slice when nothing is in flight.
    ///
    /// # Errors
    /// Returns the first error reported by a worker.
    fn wait(&mut self) -> Result<&[ExecutionObservation<OT>], Error>;

    /// Block until every in-flight execution has finished, and collect them all.
    ///
    /// # Errors
    /// Returns the first error reported by a worker.
    fn drain(&mut self) -> Result<&[ExecutionObservation<OT>], Error>;
}

/// Driver loop connecting a [`FuzzingEngine`] to an [`AsyncTargetExecutor`].
///
/// The loop is deliberately tiny, because the engine already is the state machine: keep the pool
/// saturated with whatever the engine hands out, then hand back whatever the pool completes.
#[derive(Debug)]
pub struct AsyncFuzzLoop;

impl AsyncFuzzLoop {
    /// Keep `pool` saturated until the campaign finishes or a stop is requested.
    ///
    /// # Errors
    /// Propagates engine and executor errors.
    pub fn run<E, EM, I, OT, S, Z>(
        engine: &mut Z,
        pool: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<u64, Error>
    where
        E: AsyncTargetExecutor<I, OT>,
        I: Clone,
        S: FuzzerState<I>,
        Z: FuzzingEngine<EM, I, OT, S>,
    {
        Self::run_for(engine, pool, state, manager, None)
    }

    /// Like [`AsyncFuzzLoop::run`], but stops once `max_observations` results have been reported,
    /// draining whatever is still in flight. Returns the number of observations reported.
    ///
    /// # Errors
    /// Propagates engine and executor errors.
    pub fn run_for<E, EM, I, OT, S, Z>(
        engine: &mut Z,
        pool: &mut E,
        state: &mut S,
        manager: &mut EM,
        max_observations: Option<u64>,
    ) -> Result<u64, Error>
    where
        E: AsyncTargetExecutor<I, OT>,
        I: Clone,
        S: FuzzerState<I>,
        Z: FuzzingEngine<EM, I, OT, S>,
    {
        let mut reported = 0;
        loop {
            let scheduled = Self::saturate(engine, pool, state, manager)?;
            if scheduled == 0 && pool.in_flight() == 0 {
                return Ok(reported);
            }

            let completed = pool.wait()?;
            reported += completed.len() as u64;
            engine.report_observations(state, manager, completed)?;

            if max_observations.is_some_and(|max| reported >= max) {
                let remaining = pool.drain()?;
                reported += remaining.len() as u64;
                engine.report_observations(state, manager, remaining)?;
                return Ok(reported);
            }
        }
    }

    /// Pull inputs from the engine until the pool is full, returning how many were submitted.
    fn saturate<E, EM, I, OT, S, Z>(
        engine: &mut Z,
        pool: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<usize, Error>
    where
        E: AsyncTargetExecutor<I, OT>,
        I: Clone,
        S: FuzzerState<I>,
        Z: FuzzingEngine<EM, I, OT, S>,
    {
        let free = pool.free_capacity();
        if free == 0 {
            return Ok(0);
        }
        let batch = engine.next_n(state, manager, free)?;
        let scheduled = batch.len();
        for input in batch {
            pool.submit(input)?;
        }
        Ok(scheduled)
    }
}

/// Driver loop connecting a [`FuzzingEngine`] and a [`TargetExecutor`].
#[derive(Debug)]
pub struct FuzzLoop;

impl FuzzLoop {
    /// Run the fuzz loop until completion or stop request.
    pub fn run<E, EM, F, I, OT, S>(
        engine: &mut F,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<(), Error>
    where
        F: FuzzingEngine<EM, I, OT, S>,
        E: TargetExecutor<I, OT>,
    {
        loop {
            match engine.step(state, manager)? {
                EngineStep::Execute(req) => {
                    let results = executor.execute_request(&req)?;
                    engine.report_observations(state, manager, results)?;
                }
                EngineStep::Progress => {}
                EngineStep::Completed => break Ok(()),
            }
        }
    }

    /// Run the fuzz loop for a given number of iterations.
    pub fn run_for<E, EM, F, I, OT, S>(
        engine: &mut F,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        iters: u64,
    ) -> Result<u64, Error>
    where
        F: FuzzingEngine<EM, I, OT, S>,
        E: TargetExecutor<I, OT>,
    {
        let mut count = 0;
        while count < iters {
            match engine.step(state, manager)? {
                EngineStep::Execute(req) => {
                    let results = executor.execute_request(&req)?;
                    engine.report_observations(state, manager, results)?;
                    count += req.inputs.len() as u64;
                }
                EngineStep::Progress => {}
                EngineStep::Completed => break,
            }
        }
        Ok(count)
    }

    /// Reconcile any pending in-process restart exit kind and notify the active stage's `post_exec` handler.
    pub fn reconcile_post_restart<EM, F, I, OT, S>(
        engine: &mut F,
        observers: &OT,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<(), Error>
    where
        F: FuzzingEngine<EM, I, OT, S>,
        S: crate::state::HasInFlightExecutions<I>,
        I: Clone,
    {
        if let Some(exit_kind) = state.pending_exit_kind() {
            let exec_time = state.pending_exec_time();
            state.set_pending_exit_kind(None);
            state.set_pending_exec_time(None);
            let crash_idx = state.current_input_idx().saturating_sub(1);
            let id = state.current_batch_start_id() + crash_idx as u64;
            let _ = state.take_active_input(id);
            if let Some(input) = state.current_inputs().get(crash_idx).cloned() {
                engine.post_exec_after_restart(
                    state,
                    manager,
                    crate::fuzzer::BorrowedObservation {
                        input: &input,
                        observers,
                        exit_kind,
                        id: Some(id),
                        tag: None,
                        exec_time,
                    },
                )?;
            }
        }
        Ok(())
    }

    /// Run the fuzz loop directly with any standard [`Executor`] (such as [`InProcessExecutor`](crate::executors::InProcessExecutor)),
    /// passing `engine` itself as the fuzzer (`Z = F`).
    ///
    /// This passes the live `&mut state`, `&mut manager`, and `&mut engine` directly into each `executor.run_target(...)`
    /// execution, ensuring `InProcessExecutor`'s signal and exception handlers have live references to state
    /// and event manager for crash reporting and restarting.
    pub fn run_executor<E, EM, F, I, S>(
        engine: &mut F,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<(), Error>
    where
        F: FuzzingEngine<EM, I, E::Observers, S>,
        E: HasObservers + Executor<EM, I, S, F>,
        E::Observers: ObserversTuple<I, S>,
        S: crate::state::HasInFlightExecutions<I> + MaybeHasClientPerfMonitor,
        I: Debug + Clone,
    {
        Self::run_executor_for(engine, executor, state, manager, u64::MAX).map(|_| ())
    }

    /// Run the fuzz loop directly with any standard [`Executor`] (such as [`InProcessExecutor`](crate::executors::InProcessExecutor))
    /// and an explicit fuzzer object.
    pub fn run_executor_with_fuzzer<E, EM, F, I, S, Z>(
        engine: &mut F,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        fuzzer: &mut Z,
    ) -> Result<(), Error>
    where
        F: FuzzingEngine<EM, I, E::Observers, S>,
        E: HasObservers + Executor<EM, I, S, Z>,
        E::Observers: ObserversTuple<I, S>,
        S: crate::state::HasInFlightExecutions<I> + MaybeHasClientPerfMonitor,
        I: Debug + Clone,
    {
        Self::run_executor_for_with_fuzzer(engine, executor, state, manager, fuzzer, u64::MAX)
            .map(|_| ())
    }

    /// Run the fuzz loop with a standard [`Executor`] for a given number of iterations, passing `engine` as the fuzzer.
    pub fn run_executor_for<E, EM, F, I, S>(
        engine: &mut F,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        iters: u64,
    ) -> Result<u64, Error>
    where
        F: FuzzingEngine<EM, I, E::Observers, S>,
        E: HasObservers + Executor<EM, I, S, F>,
        E::Observers: ObserversTuple<I, S>,
        S: crate::state::HasInFlightExecutions<I> + MaybeHasClientPerfMonitor,
        I: Debug + Clone,
    {
        let mut count = 0;
        while count < iters {
            Self::reconcile_post_restart(engine, &*executor.observers(), state, manager)?;
            match engine.step(state, manager)? {
                EngineStep::Execute(req) => {
                    let req_len = req.inputs.len();
                    while state.current_input_idx() < req_len {
                        let idx = state.current_input_idx();
                        let input = &req.inputs[idx];

                        start_timer!(state);
                        executor.observers_mut().pre_exec_all(state, input)?;
                        mark_feature_time!(state, PerfFeature::PreExecObservers);

                        let exec_start = libafl_bolts::current_time();
                        start_timer!(state);
                        let exit_kind = executor.run_target(engine, state, manager, input)?;
                        mark_feature_time!(state, PerfFeature::TargetExecution);
                        let exec_time = libafl_bolts::current_time().checked_sub(exec_start);

                        start_timer!(state);
                        executor
                            .observers_mut()
                            .post_exec_all(state, input, &exit_kind)?;
                        mark_feature_time!(state, PerfFeature::PostExecObservers);

                        let id = Some(state.current_batch_start_id() + idx as u64);
                        let tag = state.current_batch_tag().map(|mut t| {
                            t.input_id = state.current_batch_start_id() + idx as u64;
                            t
                        });
                        engine.process_execution(
                            state,
                            manager,
                            crate::fuzzer::BorrowedObservation {
                                input,
                                observers: &*executor.observers(),
                                exit_kind,
                                id,
                                tag,
                                exec_time,
                            },
                        )?;
                        state.set_current_input_idx(idx + 1);
                        count += 1;
                    }
                }
                EngineStep::Progress => {}
                EngineStep::Completed => break,
            }
        }
        state.clear_current_inputs();
        Ok(count)
    }

    /// Run the fuzz loop with a standard [`Executor`] and an explicit fuzzer for a given number of iterations.
    pub fn run_executor_for_with_fuzzer<E, EM, F, I, S, Z>(
        engine: &mut F,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        fuzzer: &mut Z,
        iters: u64,
    ) -> Result<u64, Error>
    where
        F: FuzzingEngine<EM, I, E::Observers, S>,
        E: HasObservers + Executor<EM, I, S, Z>,
        E::Observers: ObserversTuple<I, S>,
        S: crate::state::HasInFlightExecutions<I> + MaybeHasClientPerfMonitor,
        I: Debug + Clone,
    {
        let mut count = 0;
        while count < iters {
            Self::reconcile_post_restart(engine, &*executor.observers(), state, manager)?;
            match engine.step(state, manager)? {
                EngineStep::Execute(req) => {
                    let req_len = req.inputs.len();
                    while state.current_input_idx() < req_len {
                        let idx = state.current_input_idx();
                        let input = &req.inputs[idx];

                        start_timer!(state);
                        executor.observers_mut().pre_exec_all(state, input)?;
                        mark_feature_time!(state, PerfFeature::PreExecObservers);

                        let exec_start = libafl_bolts::current_time();
                        start_timer!(state);
                        let exit_kind = executor.run_target(fuzzer, state, manager, input)?;
                        mark_feature_time!(state, PerfFeature::TargetExecution);
                        let exec_time = libafl_bolts::current_time().checked_sub(exec_start);

                        start_timer!(state);
                        executor
                            .observers_mut()
                            .post_exec_all(state, input, &exit_kind)?;
                        mark_feature_time!(state, PerfFeature::PostExecObservers);

                        let id = Some(state.current_batch_start_id() + idx as u64);
                        let tag = state.current_batch_tag().map(|mut t| {
                            t.input_id = state.current_batch_start_id() + idx as u64;
                            t
                        });
                        engine.process_execution(
                            state,
                            manager,
                            crate::fuzzer::BorrowedObservation {
                                input,
                                observers: &*executor.observers(),
                                exit_kind,
                                id,
                                tag,
                                exec_time,
                            },
                        )?;
                        state.set_current_input_idx(idx + 1);
                        count += 1;
                    }
                }
                EngineStep::Progress => {}
                EngineStep::Completed => break,
            }
        }
        state.clear_current_inputs();
        Ok(count)
    }

    /// Step the fuzz loop once, driving the engine and executing any returned requests against the target executor.
    pub fn step<'a, E, EM, F, I, OT, S>(
        engine: &mut F,
        executor: &'a mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<FuzzLoopStep<'a, I, OT>, Error>
    where
        F: FuzzingEngine<EM, I, OT, S>,
        E: TargetExecutor<I, OT>,
    {
        let step = engine.step(state, manager)?;
        match step {
            EngineStep::Execute(ref req) => {
                let results = executor.execute_request(req)?;
                engine.report_observations(state, manager, results)?;
                Ok(FuzzLoopStep::new(step, Some(results)))
            }
            EngineStep::Progress | EngineStep::Completed => Ok(FuzzLoopStep::new(step, None)),
        }
    }
}

/// Result of a single step through [`FuzzLoop::step`].
#[derive(Debug)]
pub struct FuzzLoopStep<'a, I, OT> {
    /// The step action performed by the engine.
    pub step: EngineStep<I>,
    /// Any execution observations produced by executing the request against the target executor.
    pub observations: Option<&'a [ExecutionObservation<OT>]>,
}

impl<'a, I, OT> FuzzLoopStep<'a, I, OT> {
    /// Create a new fuzz loop step result.
    #[must_use]
    pub fn new(step: EngineStep<I>, observations: Option<&'a [ExecutionObservation<OT>]>) -> Self {
        Self { step, observations }
    }
}

/// Extension trait to convert any [`Executor`] into a [`StdTargetExecutor`].
pub trait IntoTargetExecutor<S = ()>: HasObservers + Sized {
    /// Convert this executor into a [`StdTargetExecutor`].
    fn into_target_executor(self) -> StdTargetExecutor<Self, S>;
}

impl<E: HasObservers, S: Default> IntoTargetExecutor<S> for E {
    fn into_target_executor(self) -> StdTargetExecutor<Self, S> {
        StdTargetExecutor::with_state(self)
    }
}

#[cfg(test)]
mod tests {
    use alloc::boxed::Box;
    use core::sync::atomic::{AtomicUsize, Ordering};

    use libafl_bolts::Error;

    use super::*;
    use crate::{
        events::NopEventManager,
        executors::{ExitKind, HasObservers},
        fuzzer::{ExecutionMode, NopFuzzer, ScheduledInput},
        inputs::BytesInput,
        state::NopState,
    };

    #[derive(Debug, Default)]
    struct CountingState {
        runs: usize,
    }

    #[derive(Debug)]
    struct MockExecutor {
        exit_kind: ExitKind,
    }

    impl MockExecutor {
        fn new(exit_kind: ExitKind) -> Self {
            Self { exit_kind }
        }
    }

    impl HasObservers for MockExecutor {
        type Observers = ();

        fn observers(
            &self,
        ) -> libafl_bolts::tuples::RefIndexable<&Self::Observers, Self::Observers> {
            libafl_bolts::tuples::RefIndexable::from(&())
        }

        fn observers_mut(
            &mut self,
        ) -> libafl_bolts::tuples::RefIndexable<&mut Self::Observers, Self::Observers> {
            // Empty tuple has zero size
            libafl_bolts::tuples::RefIndexable::from(Box::leak(Box::new(())))
        }
    }

    impl Executor<NopEventManager, BytesInput, CountingState, NopFuzzer> for MockExecutor {
        fn run_target(
            &mut self,
            _fuzzer: &mut NopFuzzer,
            state: &mut CountingState,
            _mgr: &mut NopEventManager,
            _input: &BytesInput,
        ) -> Result<ExitKind, Error> {
            state.runs += 1;
            Ok(self.exit_kind)
        }
    }

    impl Executor<NopEventManager, BytesInput, NopState<BytesInput>, NopFuzzer> for MockExecutor {
        fn run_target(
            &mut self,
            _fuzzer: &mut NopFuzzer,
            _state: &mut NopState<BytesInput>,
            _mgr: &mut NopEventManager,
            _input: &BytesInput,
        ) -> Result<ExitKind, Error> {
            Ok(self.exit_kind)
        }
    }

    #[test]
    fn test_std_target_executor_persists_state_across_executions() {
        let mut exec = StdTargetExecutor::<MockExecutor, CountingState>::with_state(
            MockExecutor::new(ExitKind::Ok),
        );
        let input = BytesInput::new(vec![1, 2, 3]);
        assert_eq!(exec.state().runs, 0);
        exec.execute_input(&input).unwrap();
        assert_eq!(exec.state().runs, 1);
        exec.execute_input(&input).unwrap();
        assert_eq!(exec.state().runs, 2);
    }

    #[test]
    fn test_parallel_target_executor_reuses_single_executor() {
        static FACTORY_CALLS: AtomicUsize = AtomicUsize::new(0);

        let factory = || {
            FACTORY_CALLS.fetch_add(1, Ordering::SeqCst);
            StdTargetExecutor::<MockExecutor, NopState<BytesInput>>::with_state(MockExecutor::new(
                ExitKind::Ok,
            ))
        };

        let mut parallel = ParallelTargetExecutor::new(1, factory);
        let input = BytesInput::new(vec![4, 5]);
        parallel.execute_input(&input).unwrap();
        parallel.execute_input(&input).unwrap();
        parallel.execute_batch(&[input]).unwrap();
        assert_eq!(FACTORY_CALLS.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_dual_target_executor_tracing_routes_correctly() {
        let primary = StdTargetExecutor::<MockExecutor, NopState<BytesInput>>::with_state(
            MockExecutor::new(ExitKind::Ok),
        );
        let secondary = StdTargetExecutor::<MockExecutor, NopState<BytesInput>>::with_state(
            MockExecutor::new(ExitKind::Timeout),
        );
        let mut dual = DualTargetExecutor::tracing(primary, secondary);

        let normal_item = ScheduledInput::new(10, BytesInput::new(vec![0xAA]));
        let tracing_item =
            ScheduledInput::with_mode(11, BytesInput::new(vec![0xBB]), ExecutionMode::Tracing);

        let normal_obs = dual.execute_scheduled(&normal_item).unwrap();
        assert_eq!(normal_obs.exit_kind, ExitKind::Ok);

        let tracing_obs = dual.execute_scheduled(&tracing_item).unwrap();
        assert_eq!(tracing_obs.exit_kind, ExitKind::Timeout);
    }

    #[test]
    #[should_panic(expected = "DualTargetExecutor: secondary_mode cannot be ExecutionMode::Normal")]
    fn test_dual_target_executor_rejects_normal_mode() {
        let primary = StdTargetExecutor::<MockExecutor, NopState<BytesInput>>::with_state(
            MockExecutor::new(ExitKind::Ok),
        );
        let secondary = StdTargetExecutor::<MockExecutor, NopState<BytesInput>>::with_state(
            MockExecutor::new(ExitKind::Timeout),
        );
        let _ = DualTargetExecutor::new(primary, secondary, ExecutionMode::Normal);
    }
}
