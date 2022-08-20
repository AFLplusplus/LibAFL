//! The `Fuzzer` is the main struct for a fuzz campaign.

use alloc::string::ToString;
use core::time::Duration;

#[cfg(feature = "introspection")]
use crate::monitors::PerfFeature;
use crate::{
    bolts::current_time,
    corpus::{Corpus, Testcase},
    events::{Event, EventConfig, EventFirer, EventManager, ProgressReporter},
    executors::{Executor, ExitKind, HasObservers},
    feedbacks::Feedback,
    inputs::Input,
    mark_feature_time,
    observers::ObserversTuple,
    schedulers::Scheduler,
    stages::StagesTuple,
    start_timer,
    state::{HasClientPerfMonitor, HasCorpus, HasExecutions, HasSolutions},
    Error,
};

/// Send a monitor update all 15 (or more) seconds
const STATS_TIMEOUT_DEFAULT: Duration = Duration::from_secs(15);

/// Holds a scheduler
pub trait HasScheduler {
    type Scheduler: Scheduler;

    /// The scheduler
    fn scheduler(&self) -> &Self::Scheduler;

    /// The scheduler (mutable)
    fn scheduler_mut(&mut self) -> &mut Self::Scheduler;
}

/// Holds an feedback
pub trait HasFeedback {
    type Feedback: Feedback;

    /// The feedback
    fn feedback(&self) -> &Self::Feedback;

    /// The feedback (mutable)
    fn feedback_mut(&mut self) -> &mut Self::Feedback;
}

/// Holds an objective feedback
pub trait HasObjective {
    type Objective: Feedback;

    /// The objective feedback
    fn objective(&self) -> &Self::Objective;

    /// The objective feedback (mutable)
    fn objective_mut(&mut self) -> &mut Self::Objective;
}

/// Evaluate if an input is interesting using the feedback
pub trait ExecutionProcessor
where
    Self: HasObservers,
{
    /// Evaluate if a set of observation channels has an interesting state
    fn process_execution<EM>(
        &mut self,
        state: &mut <<Self as HasObservers>::Observers as ObserversTuple>::State,
        manager: &mut EM,
        input: <<Self as HasObservers>::Observers as ObserversTuple>::Input,
        observers: &Self::Observers,
        exit_kind: &ExitKind,
        send_events: bool,
    ) -> Result<(ExecuteInputResult, Option<usize>), Error>
    where
        EM: EventFirer;
}

/// Evaluate an input modifying the state of the fuzzer
pub trait EvaluatorObservers: Sized {
    type Input: Input;
    type State;

    /// Runs the input and triggers observers and feedback,
    /// returns if is interesting an (option) the index of the new testcase in the corpus
    fn evaluate_input_with_observers<E, EM>(
        &mut self,
        state: &mut Self::State,
        executor: &mut E,
        manager: &mut EM,
        input: Self::Input,
        send_events: bool,
    ) -> Result<(ExecuteInputResult, Option<usize>), Error>
    where
        E: Executor + HasObservers,
        EM: EventManager<Fuzzer = Self>;
}

/// Evaluate an input modifying the state of the fuzzer
pub trait Evaluator {
    type Executor;
    type EventManager;
    type Input: Input;
    type State;

    /// Runs the input and triggers observers and feedback,
    /// returns if is interesting an (option) the index of the new testcase in the corpus
    fn evaluate_input(
        &mut self,
        state: &mut Self::State,
        executor: &mut Self::Executor,
        manager: &mut Self::EventManager,
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
        executor: &mut Self::Executor,
        manager: &mut Self::EventManager,
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
        executor: &mut Self::Executor,
        manager: &mut Self::EventManager,
        input: Self::Input,
    ) -> Result<usize, Error>;
}

/// The main fuzzer trait.
pub trait Fuzzer {
    type Executor;
    type Input: Input;
    type State: HasExecutions + HasClientPerfMonitor;
    type EventManager: ProgressReporter;
    type Stages;

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
        stages: &mut Self::Stages,
        executor: &mut Self::Executor,
        state: &mut Self::State,
        manager: &mut Self::EventManager,
    ) -> Result<usize, Error>;

    /// Fuzz forever (or until stopped)
    fn fuzz_loop(
        &mut self,
        stages: &mut Self::Stages,
        executor: &mut Self::Executor,
        state: &mut Self::State,
        manager: &mut Self::EventManager,
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
        stages: &mut Self::Stages,
        executor: &mut Self::Executor,
        state: &mut Self::State,
        manager: &mut Self::EventManager,
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
pub struct StdFuzzer {
    scheduler: <Self as HasScheduler>::Scheduler,
    feedback: <Self as HasFeedback>::Feedback,
    objective: <Self as HasObjective>::Objective,
}

impl HasScheduler for StdFuzzer {
    fn scheduler(&self) -> &Self::Scheduler {
        &self.scheduler
    }

    fn scheduler_mut(&mut self) -> &mut Self::Scheduler {
        &mut self.scheduler
    }
}

impl<CS, F, I, OF, S> HasFeedback for StdFuzzer {
    fn feedback(&self) -> &Self::Feedback {
        &self.feedback
    }

    fn feedback_mut(&mut self) -> &mut Self::Feedback {
        &mut self.feedback
    }
}

impl<CS, F, I, OF, S> HasObservers for StdFuzzer {
    fn observers(&self) -> &Self::Observers {
        &self.observers
    }

    fn observers_mut(&mut self) -> &mut Self::Observers {
        &mut self.observers
    }
}

impl ExecutionProcessor for StdFuzzer {
    /// Evaluate if a set of observation channels has an interesting state
    fn process_execution<EM>(
        &mut self,
        state: &mut <Self as Fuzzer>::State,
        manager: &mut EM,
        input: Self::Input,
        observers: &Self::Observers,
        exit_kind: &ExitKind,
        send_events: bool,
    ) -> Result<(ExecuteInputResult, Option<usize>), Error>
    where
        EM: EventFirer,
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
                        Some(manager.serialize_observers(observers)?)
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

impl<CS, F, I, OF, S> EvaluatorObservers for StdFuzzer
where
    CS: Scheduler,
    F: Feedback,
    I: Input,
    OF: Feedback,
    S: HasCorpus + HasSolutions + HasClientPerfMonitor + HasExecutions,
{
    /// Process one input, adding to the respective corpuses if needed and firing the right events
    #[inline]
    fn evaluate_input_with_observers<E, EM>(
        &mut self,
        state: &mut Self::State,
        executor: &mut E,
        manager: &mut EM,
        input: I,
        send_events: bool,
    ) -> Result<(ExecuteInputResult, Option<usize>), Error>
    where
        E: Executor + HasObservers,
        EM: EventManager<Fuzzer = Self>,
    {
        let exit_kind = self.execute_input(state, executor, manager, &input)?;
        let observers = executor.observers();
        self.process_execution(state, manager, input, observers, &exit_kind, send_events)
    }
}

impl<CS, E, EM, F, I, OF, S> Evaluator for StdFuzzer
where
    CS: Scheduler,
    E: Executor + HasObservers,
    EM: EventManager<Fuzzer = Self>,
    F: Feedback,
    I: Input,
    OF: Feedback,
    S: HasCorpus + HasSolutions + HasClientPerfMonitor + HasExecutions,
{
    /// Process one input, adding to the respective corpuses if needed and firing the right events
    #[inline]
    fn evaluate_input_events(
        &mut self,
        state: &mut Self::State,
        executor: &mut E,
        manager: &mut EM,
        input: I,
        send_events: bool,
    ) -> Result<(ExecuteInputResult, Option<usize>), Error> {
        self.evaluate_input_with_observers(state, executor, manager, input, send_events)
    }

    /// Adds an input, even if it's not conisered `interesting` by any of the executors
    fn add_input(
        &mut self,
        state: &mut Self::State,
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
            Some(manager.serialize_observers(observers)?)
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

impl<CS, E, EM, F, I, OF, S, ST> Fuzzer for StdFuzzer
where
    CS: Scheduler,
    EM: EventManager,
    F: Feedback,
    I: Input,
    S: HasClientPerfMonitor + HasExecutions,
    OF: Feedback,
    ST: StagesTuple<E, EM, S, Self>,
{
    fn fuzz_one(
        &mut self,
        stages: &mut ST,
        executor: &mut E,
        state: &mut Self::State,
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

impl<CS, F, OF> StdFuzzer
where
    Self: HasScheduler + HasFeedback + HasObjective,
{
    /// Create a new `StdFuzzer` with standard behavior.
    pub fn new(scheduler: CS, feedback: F, objective: OF) -> Self {
        Self {
            scheduler,
            feedback,
            objective,
        }
    }

    /// Runs the input and triggers observers and feedback
    pub fn execute_input<E, EM>(
        &mut self,
        state: &mut <Self as Fuzzer>::State,
        executor: &mut E,
        event_mgr: &mut EM,
        input: &<Self as Fuzzer>::Input,
    ) -> Result<ExitKind, Error>
    where
        E: Executor + HasObservers,
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
pub trait ExecutesInput {
    type Input: Input;
    type Fuzzer;
    type State;

    /// Runs the input and triggers observers and feedback
    fn execute_input<E, EM>(
        &mut self,
        state: &mut Self::State,
        executor: &mut E,
        event_mgr: &mut EM,
        input: &Self::Input,
    ) -> Result<ExitKind, Error>
    where
        E: Executor + HasObservers;
}

impl ExecutesInput for StdFuzzer {
    /// Runs the input and triggers observers and feedback
    fn execute_input<E, EM>(
        &mut self,
        state: &mut Self::State,
        executor: &mut E,
        event_mgr: &mut EM,
        input: &Self::Input,
    ) -> Result<ExitKind, Error>
    where
        E: Executor + HasObservers,
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
        QueueScheduler,
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
