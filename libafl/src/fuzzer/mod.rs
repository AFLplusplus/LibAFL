//! The `Fuzzer` is the main struct for a fuzz campaign.

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

#[cfg(feature = "introspection")]
use crate::monitors::PerfFeature;

use alloc::string::ToString;
use core::{marker::PhantomData, time::Duration};

/// Send a monitor update all 15 (or more) seconds
const STATS_TIMEOUT_DEFAULT: Duration = Duration::from_secs(15);

/// Holds a scheduler
pub trait HasScheduler<CS, I, S>
where
    CS: Scheduler<I, S>,
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
    F: Feedback<I, S>,
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
    OF: Feedback<I, S>,
    I: Input,
    S: HasClientPerfMonitor,
{
    /// The objective feedback
    fn objective(&self) -> &OF;

    /// The objective feedback (mutable)
    fn objective_mut(&mut self) -> &mut OF;
}

/// Evaluate if an input is interesting using the feedback
pub trait ExecutionProcessor<I, OT, S>
where
    OT: ObserversTuple<I, S>,
    I: Input,
{
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
        EM: EventFirer<I>;
}

/// Evaluate an input modifying the state of the fuzzer
pub trait EvaluatorObservers<I, OT, S>: Sized
where
    I: Input,
    OT: ObserversTuple<I, S>,
{
    /// Runs the input and triggers observers and feedback,
    /// returns if is interesting an (option) the index of the new testcase in the corpus
    fn evaluate_input_with_observers<E, EM>(
        &mut self,
        state: &mut S,
        executor: &mut E,
        manager: &mut EM,
        input: I,
        send_events: bool,
    ) -> Result<(ExecuteInputResult, Option<usize>), Error>
    where
        E: Executor<EM, I, S, Self> + HasObservers<I, OT, S>,
        EM: EventManager<E, I, S, Self>;
}

/// Evaluate an input modifying the state of the fuzzer
pub trait Evaluator<E, EM, I, S> {
    /// Runs the input and triggers observers and feedback,
    /// returns if is interesting an (option) the index of the new testcase in the corpus
    fn evaluate_input(
        &mut self,
        state: &mut S,
        executor: &mut E,
        manager: &mut EM,
        input: I,
    ) -> Result<(ExecuteInputResult, Option<usize>), Error> {
        self.evaluate_input_events(state, executor, manager, input, true)
    }

    /// Runs the input and triggers observers and feedback,
    /// returns if is interesting an (option) the index of the new testcase in the corpus
    /// This version has a boolean to decide if send events to the manager.
    fn evaluate_input_events(
        &mut self,
        state: &mut S,
        executor: &mut E,
        manager: &mut EM,
        input: I,
        send_events: bool,
    ) -> Result<(ExecuteInputResult, Option<usize>), Error>;

    /// Runs the input and triggers observers and feedback.
    /// Adds an input, to the corpus even if it's not considered `interesting` by the `feedback`.
    /// Returns the `index` of the new testcase in the corpus.
    /// Usually, you want to use [`Evaluator::evaluate_input`], unless you know what you are doing.
    fn add_input(
        &mut self,
        state: &mut S,
        executor: &mut E,
        manager: &mut EM,
        input: I,
    ) -> Result<usize, Error>;
}

/// The main fuzzer trait.
pub trait Fuzzer<E, EM, I, S, ST>
where
    I: Input,
    EM: ProgressReporter<I>,
    S: HasExecutions + HasClientPerfMonitor,
{
    /// Fuzz for a single iteration.
    /// Returns the index of the last fuzzed corpus item.
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
            return Err(Error::IllegalArgument(
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
#[derive(Debug, PartialEq)]
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
    CS: Scheduler<I, S>,
    F: Feedback<I, S>,
    I: Input,
    OF: Feedback<I, S>,
    S: HasClientPerfMonitor,
{
    scheduler: CS,
    feedback: F,
    objective: OF,
    phantom: PhantomData<(I, OT, S)>,
}

impl<CS, F, I, OF, OT, S> HasScheduler<CS, I, S> for StdFuzzer<CS, F, I, OF, OT, S>
where
    CS: Scheduler<I, S>,
    F: Feedback<I, S>,
    I: Input,
    OF: Feedback<I, S>,
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
    CS: Scheduler<I, S>,
    F: Feedback<I, S>,
    I: Input,
    OF: Feedback<I, S>,
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
    CS: Scheduler<I, S>,
    F: Feedback<I, S>,
    I: Input,
    OF: Feedback<I, S>,
    S: HasClientPerfMonitor,
{
    fn objective(&self) -> &OF {
        &self.objective
    }

    fn objective_mut(&mut self) -> &mut OF {
        &mut self.objective
    }
}

impl<CS, F, I, OF, OT, S> ExecutionProcessor<I, OT, S> for StdFuzzer<CS, F, I, OF, OT, S>
where
    CS: Scheduler<I, S>,
    F: Feedback<I, S>,
    I: Input,
    OF: Feedback<I, S>,
    OT: ObserversTuple<I, S> + serde::Serialize + serde::de::DeserializeOwned,
    S: HasCorpus<I> + HasSolutions<I> + HasClientPerfMonitor + HasExecutions,
{
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
        EM: EventFirer<I>,
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

impl<CS, F, I, OF, OT, S> EvaluatorObservers<I, OT, S> for StdFuzzer<CS, F, I, OF, OT, S>
where
    CS: Scheduler<I, S>,
    OT: ObserversTuple<I, S> + serde::Serialize + serde::de::DeserializeOwned,
    F: Feedback<I, S>,
    I: Input,
    OF: Feedback<I, S>,
    S: HasCorpus<I> + HasSolutions<I> + HasClientPerfMonitor + HasExecutions,
{
    /// Process one input, adding to the respective corpuses if needed and firing the right events
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
        E: Executor<EM, I, S, Self> + HasObservers<I, OT, S>,
        EM: EventManager<E, I, S, Self>,
    {
        let exit_kind = self.execute_input(state, executor, manager, &input)?;
        let observers = executor.observers();
        self.process_execution(state, manager, input, observers, &exit_kind, send_events)
    }
}

impl<CS, E, EM, F, I, OF, OT, S> Evaluator<E, EM, I, S> for StdFuzzer<CS, F, I, OF, OT, S>
where
    CS: Scheduler<I, S>,
    E: Executor<EM, I, S, Self> + HasObservers<I, OT, S>,
    OT: ObserversTuple<I, S> + serde::Serialize + serde::de::DeserializeOwned,
    EM: EventManager<E, I, S, Self>,
    F: Feedback<I, S>,
    I: Input,
    OF: Feedback<I, S>,
    S: HasCorpus<I> + HasSolutions<I> + HasClientPerfMonitor + HasExecutions,
{
    /// Process one input, adding to the respective corpuses if needed and firing the right events
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

    /// Adds an input, even if it's not conisered `interesting` by any of the executors
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

impl<CS, E, EM, F, I, OF, OT, S, ST> Fuzzer<E, EM, I, S, ST> for StdFuzzer<CS, F, I, OF, OT, S>
where
    CS: Scheduler<I, S>,
    EM: EventManager<E, I, S, Self>,
    F: Feedback<I, S>,
    I: Input,
    S: HasClientPerfMonitor + HasExecutions,
    OF: Feedback<I, S>,
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
    CS: Scheduler<I, S>,
    F: Feedback<I, S>,
    I: Input,
    OF: Feedback<I, S>,
    S: HasExecutions + HasClientPerfMonitor,
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
        E: Executor<EM, I, S, Self> + HasObservers<I, OT, S>,
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
pub trait ExecutesInput<I, OT, S, Z>
where
    I: Input,
    OT: ObserversTuple<I, S>,
{
    /// Runs the input and triggers observers and feedback
    fn execute_input<E, EM>(
        &mut self,
        state: &mut S,
        executor: &mut E,
        event_mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, Error>
    where
        E: Executor<EM, I, S, Z> + HasObservers<I, OT, S>,
        OT: ObserversTuple<I, S>;
}

impl<CS, F, I, OF, OT, S> ExecutesInput<I, OT, S, Self> for StdFuzzer<CS, F, I, OF, OT, S>
where
    CS: Scheduler<I, S>,
    F: Feedback<I, S>,
    I: Input,
    OT: ObserversTuple<I, S>,
    OF: Feedback<I, S>,
    S: HasExecutions + HasClientPerfMonitor,
{
    /// Runs the input and triggers observers and feedback
    fn execute_input<E, EM>(
        &mut self,
        state: &mut S,
        executor: &mut E,
        event_mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, Error>
    where
        E: Executor<EM, I, S, Self> + HasObservers<I, OT, S>,
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

#[cfg(feature = "python")]
/// `Fuzzer` Python bindings
pub mod pybind {
    use crate::feedbacks::{CrashFeedback, MaxMapFeedback};
    use crate::fuzzer::{Fuzzer, StdFuzzer};
    use crate::inputs::BytesInput;
    use crate::schedulers::QueueScheduler;
    use pyo3::prelude::*;

    macro_rules! define_python_fuzzer {
        ($type_name:ident, $struct_name:ident, $py_name:tt, $datatype:ty, $my_std_state_type_name: ident, $std_state_name: ident,
            $event_manager_name: ident, $map_observer_name: ident, $max_map_feedback_py_name: ident, $executor_name: ident, $stage_tuple_name: ident) => {
            use crate::events::pybind::$event_manager_name;
            use crate::executors::pybind::$executor_name;
            use crate::feedbacks::map::pybind::$max_map_feedback_py_name;
            use crate::observers::map::pybind::$map_observer_name;
            use crate::stages::owned::pybind::$stage_tuple_name;
            use crate::state::pybind::{$my_std_state_type_name, $std_state_name};

            /// `StdFuzzer` with fixed generics
            pub type $type_name = StdFuzzer<
                QueueScheduler,
                MaxMapFeedback<BytesInput, $map_observer_name, $my_std_state_type_name, $datatype>,
                BytesInput,
                CrashFeedback,
                ($map_observer_name, ()),
                $my_std_state_type_name,
            >;
            /// Python class for StdFuzzer
            #[pyclass(unsendable, name = $py_name)]
            #[derive(Debug)]
            pub struct $struct_name {
                /// Rust wrapped StdFuzzer object
                pub std_fuzzer: $type_name,
            }

            #[pymethods]
            impl $struct_name {
                #[new]
                fn new(py_max_map_feedback: $max_map_feedback_py_name) -> Self {
                    Self {
                        std_fuzzer: StdFuzzer::new(
                            QueueScheduler::new(),
                            py_max_map_feedback.max_map_feedback,
                            CrashFeedback::new(),
                        ),
                    }
                }

                fn fuzz_loop(
                    &mut self,
                    py_executor: &mut $executor_name,
                    py_state: &mut $std_state_name,
                    py_mgr: &mut $event_manager_name,
                    stage_tuple: &mut $stage_tuple_name,
                ) {
                    self.std_fuzzer
                        .fuzz_loop(
                            &mut stage_tuple.stages_owned_list,
                            py_executor,
                            &mut py_state.std_state,
                            py_mgr,
                        )
                        .expect("Failed to generate the initial corpus".into());
                }
            }
        };
    }

    define_python_fuzzer!(
        MyStdFuzzerI8,
        PythonStdFuzzerI8,
        "StdFuzzerI8",
        i8,
        MyStdStateI8,
        PythonStdStateI8,
        PythonEventManagerI8,
        PythonMapObserverI8,
        PythonMaxMapFeedbackI8,
        PythonExecutorI8,
        PythonStagesOwnedListI8
    );

    define_python_fuzzer!(
        MyStdFuzzerI16,
        PythonStdFuzzerI16,
        "StdFuzzerI16",
        i16,
        MyStdStateI16,
        PythonStdStateI16,
        PythonEventManagerI16,
        PythonMapObserverI16,
        PythonMaxMapFeedbackI16,
        PythonExecutorI16,
        PythonStagesOwnedListI16
    );

    define_python_fuzzer!(
        MyStdFuzzerI32,
        PythonStdFuzzerI32,
        "StdFuzzerI32",
        i32,
        MyStdStateI32,
        PythonStdStateI32,
        PythonEventManagerI32,
        PythonMapObserverI32,
        PythonMaxMapFeedbackI32,
        PythonExecutorI32,
        PythonStagesOwnedListI32
    );

    define_python_fuzzer!(
        MyStdFuzzerI64,
        PythonStdFuzzerI64,
        "StdFuzzerI64",
        i64,
        MyStdStateI64,
        PythonStdStateI64,
        PythonEventManagerI64,
        PythonMapObserverI64,
        PythonMaxMapFeedbackI64,
        PythonExecutorI64,
        PythonStagesOwnedListI64
    );

    define_python_fuzzer!(
        MyStdFuzzerU8,
        PythonStdFuzzerU8,
        "StdFuzzerU8",
        u8,
        MyStdStateU8,
        PythonStdStateU8,
        PythonEventManagerU8,
        PythonMapObserverU8,
        PythonMaxMapFeedbackU8,
        PythonExecutorU8,
        PythonStagesOwnedListU8
    );

    define_python_fuzzer!(
        MyStdFuzzerU16,
        PythonStdFuzzerU16,
        "StdFuzzerU16",
        u16,
        MyStdStateU16,
        PythonStdStateU16,
        PythonEventManagerU16,
        PythonMapObserverU16,
        PythonMaxMapFeedbackU16,
        PythonExecutorU16,
        PythonStagesOwnedListU16
    );

    define_python_fuzzer!(
        MyStdFuzzerU32,
        PythonStdFuzzerU32,
        "StdFuzzerU32",
        u32,
        MyStdStateU32,
        PythonStdStateU32,
        PythonEventManagerU32,
        PythonMapObserverU32,
        PythonMaxMapFeedbackU32,
        PythonExecutorU32,
        PythonStagesOwnedListU32
    );

    define_python_fuzzer!(
        MyStdFuzzerU64,
        PythonStdFuzzerU64,
        "StdFuzzerU64",
        u64,
        MyStdStateU64,
        PythonStdStateU64,
        PythonEventManagerU64,
        PythonMapObserverU64,
        PythonMaxMapFeedbackU64,
        PythonExecutorU64,
        PythonStagesOwnedListU64
    );

    /// Register the classes to the python module
    pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
        m.add_class::<PythonStdFuzzerI8>()?;
        m.add_class::<PythonStdFuzzerI16>()?;
        m.add_class::<PythonStdFuzzerI32>()?;
        m.add_class::<PythonStdFuzzerI64>()?;

        m.add_class::<PythonStdFuzzerU8>()?;
        m.add_class::<PythonStdFuzzerU16>()?;
        m.add_class::<PythonStdFuzzerU32>()?;
        m.add_class::<PythonStdFuzzerU64>()?;
        Ok(())
    }
}
