//! The `Fuzzer` is the main struct for a fuzz campaign.

use alloc::string::ToString;
use core::{fmt::Debug, marker::PhantomData, time::Duration};

use serde::{de::DeserializeOwned, Serialize};

#[cfg(feature = "introspection")]
use crate::monitors::PerfFeature;
#[cfg(test)]
use crate::state::NopState;
use crate::{
    bolts::current_time,
    corpus::{Corpus, Testcase},
    events::{Event, EventConfig, EventFirer, EventProcessor, ProgressReporter},
    executors::{Executor, ExitKind, HasObservers},
    feedbacks::Feedback,
    inputs::Input,
    mark_feature_time,
    observers::ObserversTuple,
    schedulers::Scheduler,
    stages::StagesTuple,
    start_timer,
    state::{HasClientPerfMonitor, HasCorpus, HasExecutions, HasSolutions, State},
    Error,
};

/// Send a monitor update all 15 (or more) seconds
const STATS_TIMEOUT_DEFAULT: Duration = Duration::from_secs(15);

/// Holds a scheduler
pub trait HasScheduler<CS, I, S>
where
    CS: Scheduler<Input = I, State = S>,
    I: Input,
{
    /// The scheduler
    fn scheduler(&self) -> &CS;

    /// The scheduler (mutable)
    fn scheduler_mut(&mut self) -> &mut CS;
}

/// Holds an feedback
pub trait HasFeedback<F, I, S>
where
    F: Feedback<Input = I, State = S>,
    I: Input,
    S: HasClientPerfMonitor,
{
    /// The feedback
    fn feedback(&self) -> &F;

    /// The feedback (mutable)
    fn feedback_mut(&mut self) -> &mut F;
}

/// Holds an objective feedback
pub trait HasObjective<I, OF, S>
where
    OF: Feedback<Input = I, State = S>,
    I: Input,
    S: HasClientPerfMonitor,
{
    /// The objective feedback
    fn objective(&self) -> &OF;

    /// The objective feedback (mutable)
    fn objective_mut(&mut self) -> &mut OF;
}

/// Evaluate if an input is interesting using the feedback
pub trait ExecutionProcessor {
    /// The [`Observers`]
    type Observers: ObserversTuple<Self::Input, Self::State>;
    /// The [`Input`]
    type Input: Input;
    /// The [`State`]
    type State: State<Input = Self::Input>;

    /// Evaluate if a set of observation channels has an interesting state
    fn process_execution<EM>(
        &mut self,
        state: &mut Self::State,
        manager: &mut EM,
        input: Self::Input,
        observers: &Self::Observers,
        exit_kind: &ExitKind,
        send_events: bool,
    ) -> Result<(ExecuteInputResult, Option<usize>), Error>
    where
        EM: EventFirer<Input = Self::Input, State = Self::State>;
}

/// Evaluate an input modifying the state of the fuzzer
pub trait EvaluatorObservers: Sized {
    /// The [`Input`] used
    type Input: Input;
    /// The [`State`]
    type State: State<Input = Self::Input>;
    /// The [`Observers`]
    type Observers: ObserversTuple<Self::Input, Self::State>;

    /// Runs the input and triggers observers and feedback,
    /// returns if is interesting an (option) the index of the new
    /// [`crate::corpus::Testcase`] in the [`crate::corpus::Corpus`]
    fn evaluate_input_with_observers<E, EM>(
        &mut self,
        state: &mut Self::State,
        executor: &mut E,
        manager: &mut EM,
        input: Self::Input,
        send_events: bool,
    ) -> Result<(ExecuteInputResult, Option<usize>), Error>
    where
        E: Executor<EM, Self::Input, Self::State, Self>
            + HasObservers<Input = Self::Input, Observers = Self::Observers, State = Self::State>,
        EM: EventFirer<Input = Self::Input, State = Self::State>;
}

/// Evaluate an input modifying the state of the fuzzer
pub trait Evaluator<E, EM> {
    /// The [`Input`]
    type Input: Input;
    /// The [`State`]
    type State: State<Input = Self::Input>;

    /// Runs the input and triggers observers and feedback,
    /// returns if is interesting an (option) the index of the new [`crate::corpus::Testcase`] in the corpus
    fn evaluate_input(
        &mut self,
        state: &mut Self::State,
        executor: &mut E,
        manager: &mut EM,
        input: Self::Input,
    ) -> Result<(ExecuteInputResult, Option<usize>), Error> {
        self.evaluate_input_events(state, executor, manager, input, true)
    }

    /// Runs the input and triggers observers and feedback,
    /// returns if is interesting an (option) the index of the new testcase in the corpus
    /// This version has a boolean to decide if send events to the manager.
    fn evaluate_input_events(
        &mut self,
        state: &mut Self::State,
        executor: &mut E,
        manager: &mut EM,
        input: Self::Input,
        send_events: bool,
    ) -> Result<(ExecuteInputResult, Option<usize>), Error>;

    /// Runs the input and triggers observers and feedback.
    /// Adds an input, to the corpus even if it's not considered `interesting` by the `feedback`.
    /// Returns the `index` of the new testcase in the corpus.
    /// Usually, you want to use [`Evaluator::evaluate_input`], unless you know what you are doing.
    fn add_input(
        &mut self,
        state: &mut Self::State,
        executor: &mut E,
        manager: &mut EM,
        input: Self::Input,
    ) -> Result<usize, Error>;
}

/// The main fuzzer trait.
pub trait Fuzzer<E, EM, I, S, ST>
where
    I: Input,
    EM: ProgressReporter<Input = I, State = S>,
    S: HasExecutions + HasClientPerfMonitor,
{
    /// Fuzz for a single iteration.
    /// Returns the index of the last fuzzed corpus item.
    /// (Note: An iteration represents a complete run of every stage.
    /// Therefore it does not mean that the harness is executed for once,
    /// because each stage could run the harness for multiple times)
    ///
    /// If you use this fn in a restarting scenario to only run for `n` iterations,
    /// before exiting, make sure you call `event_mgr.on_restart(&mut state)?;`.
    /// This way, the state will be available in the next, respawned, iteration.
    fn fuzz_one(
        &mut self,
        stages: &mut ST,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<usize, Error>;

    /// Fuzz forever (or until stopped)
    fn fuzz_loop(
        &mut self,
        stages: &mut ST,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<usize, Error> {
        let mut last = current_time();
        let monitor_timeout = STATS_TIMEOUT_DEFAULT;
        loop {
            self.fuzz_one(stages, executor, state, manager)?;
            last = manager.maybe_report_progress(state, last, monitor_timeout)?;
        }
    }

    /// Fuzz for n iterations.
    /// Returns the index of the last fuzzed corpus item.
    /// (Note: An iteration represents a complete run of every stage.
    /// therefore the number n is not always equal to the number of the actual harness executions,
    /// because each stage could run the harness for multiple times)
    ///
    /// If you use this fn in a restarting scenario to only run for `n` iterations,
    /// before exiting, make sure you call `event_mgr.on_restart(&mut state)?;`.
    /// This way, the state will be available in the next, respawned, iteration.
    fn fuzz_loop_for(
        &mut self,
        stages: &mut ST,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        iters: u64,
    ) -> Result<usize, Error> {
        if iters == 0 {
            return Err(Error::illegal_argument(
                "Cannot fuzz for 0 iterations!".to_string(),
            ));
        }

        let mut ret = 0;
        let mut last = current_time();
        let monitor_timeout = STATS_TIMEOUT_DEFAULT;

        for _ in 0..iters {
            ret = self.fuzz_one(stages, executor, state, manager)?;
            last = manager.maybe_report_progress(state, last, monitor_timeout)?;
        }

        // If we would assume the fuzzer loop will always exit after this, we could do this here:
        // manager.on_restart(state)?;
        // But as the state may grow to a few megabytes,
        // for now we won' and the user has to do it (unless we find a way to do this on `Drop`).

        Ok(ret)
    }
}

/// The corpus this input should be added to
#[derive(Debug, PartialEq, Eq)]
pub enum ExecuteInputResult {
    /// No special input
    None,
    /// This input should be stored in the corpus
    Corpus,
    /// This input leads to a solution
    Solution,
}

/// Your default fuzzer instance, for everyday use.
#[derive(Debug)]
pub struct StdFuzzer<CS, F, I, OF, OT, S>
where
    CS: Scheduler<Input = I, State = S>,
    F: Feedback<Input = I, State = S>,
    I: Input,
    OF: Feedback<Input = I, State = S>,
    S: HasClientPerfMonitor,
{
    scheduler: CS,
    feedback: F,
    objective: OF,
    phantom: PhantomData<(I, OT, S)>,
}

impl<CS, F, I, OF, OT, S> HasScheduler<CS, I, S> for StdFuzzer<CS, F, I, OF, OT, S>
where
    CS: Scheduler<Input = I, State = S>,
    F: Feedback<Input = I, State = S>,
    I: Input,
    OF: Feedback<Input = I, State = S>,
    S: HasClientPerfMonitor,
{
    fn scheduler(&self) -> &CS {
        &self.scheduler
    }

    fn scheduler_mut(&mut self) -> &mut CS {
        &mut self.scheduler
    }
}

impl<CS, F, I, OF, OT, S> HasFeedback<F, I, S> for StdFuzzer<CS, F, I, OF, OT, S>
where
    CS: Scheduler<Input = I, State = S>,
    F: Feedback<Input = I, State = S>,
    I: Input,
    OF: Feedback<Input = I, State = S>,
    S: HasClientPerfMonitor,
{
    fn feedback(&self) -> &F {
        &self.feedback
    }

    fn feedback_mut(&mut self) -> &mut F {
        &mut self.feedback
    }
}

impl<CS, F, I, OF, OT, S> HasObjective<I, OF, S> for StdFuzzer<CS, F, I, OF, OT, S>
where
    CS: Scheduler<Input = I, State = S>,
    F: Feedback<Input = I, State = S>,
    I: Input,
    OF: Feedback<Input = I, State = S>,
    S: HasClientPerfMonitor,
{
    fn objective(&self) -> &OF {
        &self.objective
    }

    fn objective_mut(&mut self) -> &mut OF {
        &mut self.objective
    }
}

impl<CS, F, I, OF, OT, S> ExecutionProcessor for StdFuzzer<CS, F, I, OF, OT, S>
where
    CS: Scheduler<Input = I, State = S>,
    F: Feedback<Input = I, State = S>,
    I: Input,
    OF: Feedback<Input = I, State = S>,
    OT: ObserversTuple<I, S> + Serialize + DeserializeOwned,
    S: HasCorpus<Input = I>
        + HasSolutions<Input = I>
        + HasClientPerfMonitor
        + HasExecutions
        + State<Input = I>,
{
    type Observers = OT;
    type Input = I;
    type State = S;

    /// Evaluate if a set of observation channels has an interesting state
    fn process_execution<EM>(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        input: I,
        observers: &OT,
        exit_kind: &ExitKind,
        send_events: bool,
    ) -> Result<(ExecuteInputResult, Option<usize>), Error>
    where
        EM: EventFirer<Input = Self::Input, State = Self::State>,
    {
        let mut res = ExecuteInputResult::None;

        #[cfg(not(feature = "introspection"))]
        let is_solution = self
            .objective_mut()
            .is_interesting(state, manager, &input, observers, exit_kind)?;

        #[cfg(feature = "introspection")]
        let is_solution = self
            .objective_mut()
            .is_interesting_introspection(state, manager, &input, observers, exit_kind)?;

        if is_solution {
            res = ExecuteInputResult::Solution;
        } else {
            #[cfg(not(feature = "introspection"))]
            let is_corpus = self
                .feedback_mut()
                .is_interesting(state, manager, &input, observers, exit_kind)?;

            #[cfg(feature = "introspection")]
            let is_corpus = self
                .feedback_mut()
                .is_interesting_introspection(state, manager, &input, observers, exit_kind)?;

            if is_corpus {
                res = ExecuteInputResult::Corpus;
            }
        }

        match res {
            ExecuteInputResult::None => {
                self.feedback_mut().discard_metadata(state, &input)?;
                self.objective_mut().discard_metadata(state, &input)?;
                Ok((res, None))
            }
            ExecuteInputResult::Corpus => {
                // Not a solution
                self.objective_mut().discard_metadata(state, &input)?;

                // Add the input to the main corpus
                let mut testcase = Testcase::with_executions(input.clone(), *state.executions());
                self.feedback_mut().append_metadata(state, &mut testcase)?;
                let idx = state.corpus_mut().add(testcase)?;
                self.scheduler_mut().on_add(state, idx)?;

                if send_events {
                    // TODO set None for fast targets
                    let observers_buf = if manager.configuration() == EventConfig::AlwaysUnique {
                        None
                    } else {
                        Some(manager.serialize_observers::<OT>(observers)?)
                    };
                    manager.fire(
                        state,
                        Event::NewTestcase {
                            input,
                            observers_buf,
                            exit_kind: *exit_kind,
                            corpus_size: state.corpus().count(),
                            client_config: manager.configuration(),
                            time: current_time(),
                            executions: *state.executions(),
                        },
                    )?;
                }
                Ok((res, Some(idx)))
            }
            ExecuteInputResult::Solution => {
                // Not interesting
                self.feedback_mut().discard_metadata(state, &input)?;

                // The input is a solution, add it to the respective corpus
                let mut testcase = Testcase::with_executions(input, *state.executions());
                self.objective_mut().append_metadata(state, &mut testcase)?;
                state.solutions_mut().add(testcase)?;

                if send_events {
                    manager.fire(
                        state,
                        Event::Objective {
                            objective_size: state.solutions().count(),
                        },
                    )?;
                }

                Ok((res, None))
            }
        }
    }
}

impl<CS, F, I, OF, OT, S> EvaluatorObservers for StdFuzzer<CS, F, I, OF, OT, S>
where
    CS: Scheduler<Input = I, State = S>,
    OT: ObserversTuple<I, S> + Serialize + DeserializeOwned,
    F: Feedback<Input = I, State = S>,
    I: Input,
    OF: Feedback<Input = I, State = S>,
    S: HasCorpus<Input = I>
        + HasSolutions<Input = I>
        + HasClientPerfMonitor
        + HasExecutions
        + State<Input = I>,
{
    type Input = I;
    type State = S;
    type Observers = OT;

    /// Process one input, adding to the respective corpora if needed and firing the right events
    #[inline]
    fn evaluate_input_with_observers<E, EM>(
        &mut self,
        state: &mut S,
        executor: &mut E,
        manager: &mut EM,
        input: I,
        send_events: bool,
    ) -> Result<(ExecuteInputResult, Option<usize>), Error>
    where
        E: Executor<EM, I, S, Self> + HasObservers<Input = I, Observers = OT, State = S>,
        EM: EventFirer<Input = I, State = S>,
    {
        let exit_kind = self.execute_input(state, executor, manager, &input)?;
        let observers = executor.observers();
        self.process_execution(state, manager, input, observers, &exit_kind, send_events)
    }
}

impl<CS, E, EM, F, I, OF, OT, S> Evaluator<E, EM> for StdFuzzer<CS, F, I, OF, OT, S>
where
    CS: Scheduler<Input = I, State = S>,
    E: HasObservers<State = S, Observers = OT, Input = I> + Executor<EM, I, S, Self>,
    EM: EventFirer<Input = I, State = S>,
    F: Feedback<Input = I, State = S>,
    I: Input,
    OF: Feedback<Input = I, State = S>,
    OT: ObserversTuple<I, S> + Serialize + DeserializeOwned,
    S: HasCorpus<Input = I>
        + HasSolutions<Input = I>
        + HasClientPerfMonitor
        + HasExecutions
        + State<Input = I>,
{
    type Input = I;
    type State = S;

    /// Process one input, adding to the respective corpora if needed and firing the right events
    #[inline]
    fn evaluate_input_events(
        &mut self,
        state: &mut S,
        executor: &mut E,
        manager: &mut EM,
        input: I,
        send_events: bool,
    ) -> Result<(ExecuteInputResult, Option<usize>), Error> {
        self.evaluate_input_with_observers(state, executor, manager, input, send_events)
    }

    /// Adds an input, even if it's not considered `interesting` by any of the executors
    fn add_input(
        &mut self,
        state: &mut S,
        executor: &mut E,
        manager: &mut EM,
        input: I,
    ) -> Result<usize, Error> {
        let exit_kind = self.execute_input(state, executor, manager, &input)?;
        let observers = executor.observers();
        // Always consider this to be "interesting"

        // Not a solution
        self.objective_mut().discard_metadata(state, &input)?;

        // Add the input to the main corpus
        let mut testcase = Testcase::with_executions(input.clone(), *state.executions());
        self.feedback_mut().append_metadata(state, &mut testcase)?;
        let idx = state.corpus_mut().add(testcase)?;
        self.scheduler_mut().on_add(state, idx)?;

        let observers_buf = if manager.configuration() == EventConfig::AlwaysUnique {
            None
        } else {
            Some(manager.serialize_observers::<OT>(observers)?)
        };
        manager.fire(
            state,
            Event::NewTestcase {
                input,
                observers_buf,
                exit_kind,
                corpus_size: state.corpus().count(),
                client_config: manager.configuration(),
                time: current_time(),
                executions: *state.executions(),
            },
        )?;
        Ok(idx)
    }
}

impl<CS, E, EM, F, I, OF, OT, S, ST> Fuzzer<E, EM, I, S, ST> for StdFuzzer<CS, F, I, OF, OT, S>
where
    CS: Scheduler<Input = I, State = S>,
    EM: ProgressReporter<Input = I, State = S>
        + EventProcessor<E, Self, Input = I, State = S, Observers = OT>,
    F: Feedback<Input = I, State = S>,
    I: Input,
    OF: Feedback<Input = I, State = S>,
    S: HasClientPerfMonitor + HasExecutions,
    ST: StagesTuple<E, EM, S, Self>,
{
    fn fuzz_one(
        &mut self,
        stages: &mut ST,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<usize, Error> {
        // Init timer for scheduler
        #[cfg(feature = "introspection")]
        state.introspection_monitor_mut().start_timer();

        // Get the next index from the scheduler
        let idx = self.scheduler.next(state)?;

        // Mark the elapsed time for the scheduler
        #[cfg(feature = "introspection")]
        state.introspection_monitor_mut().mark_scheduler_time();

        // Mark the elapsed time for the scheduler
        #[cfg(feature = "introspection")]
        state.introspection_monitor_mut().reset_stage_index();

        // Execute all stages
        stages.perform_all(self, executor, state, manager, idx)?;

        // Init timer for manager
        #[cfg(feature = "introspection")]
        state.introspection_monitor_mut().start_timer();

        // Execute the manager
        manager.process(self, state, executor)?;

        // Mark the elapsed time for the manager
        #[cfg(feature = "introspection")]
        state.introspection_monitor_mut().mark_manager_time();

        Ok(idx)
    }
}

impl<CS, F, I, OF, OT, S> StdFuzzer<CS, F, I, OF, OT, S>
where
    CS: Scheduler<Input = I, State = S>,
    F: Feedback<Input = I, State = S>,
    I: Input + Debug,
    OF: Feedback<Input = I, State = S>,
    S: State<Input = I> + HasExecutions + HasClientPerfMonitor,
{
    /// Create a new `StdFuzzer` with standard behavior.
    pub fn new(scheduler: CS, feedback: F, objective: OF) -> Self {
        Self {
            scheduler,
            feedback,
            objective,
            phantom: PhantomData,
        }
    }

    /// Runs the input and triggers observers and feedback
    pub fn execute_input<E, EM>(
        &mut self,
        state: &mut S,
        executor: &mut E,
        event_mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, Error>
    where
        E: Executor<EM, I, S, Self> + HasObservers<Input = I, Observers = OT, State = S>,
        OT: ObserversTuple<I, S>,
    {
        start_timer!(state);
        executor.observers_mut().pre_exec_all(state, input)?;
        mark_feature_time!(state, PerfFeature::PreExecObservers);

        *state.executions_mut() += 1;

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

/// Structs with this trait will execute an [`Input`]
pub trait ExecutesInput<E, EM> {
    /// The [`Input`] executed
    type Input: Input;
    /// The [`State`] for this executor
    type State: State<Input = Self::Input>;

    /// Runs the input and triggers observers and feedback
    fn execute_input(
        &mut self,
        state: &mut Self::State,
        executor: &mut E,
        event_mgr: &mut EM,
        input: &Self::Input,
    ) -> Result<ExitKind, Error>;
}

impl<CS, E, EM, F, I, OF, OT, S> ExecutesInput<E, EM> for StdFuzzer<CS, F, I, OF, OT, S>
where
    CS: Scheduler<Input = I, State = S>,
    F: Feedback<Input = I, State = S>,
    I: Input,
    OT: ObserversTuple<I, S>,
    OF: Feedback<Input = I, State = S>,
    E: Executor<EM, I, S, Self> + HasObservers<State = S, Input = I, Observers = OT>,
    S: HasExecutions + HasClientPerfMonitor + State<Input = I>,
{
    type Input = I;
    type State = S;

    /// Runs the input and triggers observers and feedback
    fn execute_input(
        &mut self,
        state: &mut S,
        executor: &mut E,
        event_mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, Error>
    where
        E: Executor<EM, I, S, Self>,
        OT: ObserversTuple<I, S>,
    {
        start_timer!(state);
        executor.observers_mut().pre_exec_all(state, input)?;
        mark_feature_time!(state, PerfFeature::PreExecObservers);

        *state.executions_mut() += 1;

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

#[cfg(test)]
#[derive(Clone, Debug)]
pub(crate) struct NopFuzzer;

#[cfg(test)]
impl NopFuzzer {
    pub fn new() -> Self {
        NopFuzzer {}
    }
}

#[cfg(test)]
impl<ST, E, I, EM> Fuzzer<E, EM, I, NopState<I>, ST> for NopFuzzer
where
    I: Input,
    EM: ProgressReporter<Input = I, State = NopState<I>>,
{
    fn fuzz_one(
        &mut self,
        _stages: &mut ST,
        _executor: &mut E,
        _state: &mut NopState<I>,
        _manager: &mut EM,
    ) -> Result<usize, Error> {
        unimplemented!()
    }
}

#[cfg(feature = "python")]
#[allow(missing_docs)]
/// `Fuzzer` Python bindings
pub mod pybind {
    use alloc::{boxed::Box, vec::Vec};

    use pyo3::prelude::*;

    use crate::{
        bolts::ownedref::OwnedPtrMut,
        events::pybind::PythonEventManager,
        executors::pybind::PythonExecutor,
        feedbacks::pybind::PythonFeedback,
        fuzzer::{Evaluator, Fuzzer, StdFuzzer},
        inputs::BytesInput,
        observers::pybind::PythonObserversTuple,
        schedulers::QueueScheduler,
        stages::pybind::PythonStagesTuple,
        state::pybind::{PythonStdState, PythonStdStateWrapper},
    };

    /// `StdFuzzer` with fixed generics
    pub type PythonStdFuzzer = StdFuzzer<
        QueueScheduler<BytesInput, PythonStdState>,
        PythonFeedback,
        BytesInput,
        PythonFeedback,
        PythonObserversTuple,
        PythonStdState,
    >;

    /// Python class for StdFuzzer
    #[pyclass(unsendable, name = "StdFuzzer")]
    #[derive(Debug)]
    pub struct PythonStdFuzzerWrapper {
        /// Rust wrapped StdFuzzer object
        pub inner: OwnedPtrMut<PythonStdFuzzer>,
    }

    impl PythonStdFuzzerWrapper {
        pub fn wrap(r: &mut PythonStdFuzzer) -> Self {
            Self {
                inner: OwnedPtrMut::Ptr(r),
            }
        }

        #[must_use]
        pub fn unwrap(&self) -> &PythonStdFuzzer {
            self.inner.as_ref()
        }

        pub fn unwrap_mut(&mut self) -> &mut PythonStdFuzzer {
            self.inner.as_mut()
        }
    }

    #[pymethods]
    impl PythonStdFuzzerWrapper {
        #[new]
        fn new(py_feedback: PythonFeedback, py_objective: PythonFeedback) -> Self {
            Self {
                inner: OwnedPtrMut::Owned(Box::new(StdFuzzer::new(
                    QueueScheduler::new(),
                    py_feedback,
                    py_objective,
                ))),
            }
        }

        fn add_input(
            &mut self,
            py_state: &mut PythonStdStateWrapper,
            py_executor: &mut PythonExecutor,
            py_mgr: &mut PythonEventManager,
            input: Vec<u8>,
        ) -> usize {
            self.inner
                .as_mut()
                .add_input(
                    py_state.unwrap_mut(),
                    py_executor,
                    py_mgr,
                    BytesInput::new(input),
                )
                .expect("Failed to add input")
        }

        fn fuzz_loop(
            &mut self,
            py_executor: &mut PythonExecutor,
            py_state: &mut PythonStdStateWrapper,
            py_mgr: &mut PythonEventManager,
            stages_tuple: &mut PythonStagesTuple,
        ) {
            self.inner
                .as_mut()
                .fuzz_loop(stages_tuple, py_executor, py_state.unwrap_mut(), py_mgr)
                .expect("Failed to generate the initial corpus");
        }
    }

    /// Register the classes to the python module
    pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
        m.add_class::<PythonStdFuzzerWrapper>()?;
        Ok(())
    }
}
