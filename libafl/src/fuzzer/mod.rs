//! The `Fuzzer` is the main struct for a fuzz campaign.

use alloc::string::ToString;
use core::{fmt::Debug, marker::PhantomData, time::Duration};

use libafl_bolts::current_time;
use serde::{de::DeserializeOwned, Serialize};

use crate::{
    corpus::{Corpus, CorpusId, HasCurrentCorpusIdx, HasTestcase, Testcase},
    events::{Event, EventConfig, EventFirer, EventProcessor, ProgressReporter},
    executors::{Executor, ExitKind, HasObservers},
    feedbacks::Feedback,
    inputs::UsesInput,
    mark_feature_time,
    observers::ObserversTuple,
    schedulers::Scheduler,
    stages::{HasCurrentStage, StagesTuple},
    start_timer,
    state::{
        HasCorpus, HasExecutions, HasImported, HasLastReportTime, HasMetadata, HasSolutions,
        UsesState,
    },
    Error,
};
#[cfg(feature = "introspection")]
use crate::{monitors::PerfFeature, state::HasClientPerfMonitor};

/// Send a monitor update all 15 (or more) seconds
const STATS_TIMEOUT_DEFAULT: Duration = Duration::from_secs(15);

/// Holds a scheduler
pub trait HasScheduler: UsesState
where
    Self::State: HasCorpus,
{
    /// The [`Scheduler`] for this fuzzer
    type Scheduler: Scheduler<State = Self::State>;

    /// The scheduler
    fn scheduler(&self) -> &Self::Scheduler;

    /// The scheduler (mutable)
    fn scheduler_mut(&mut self) -> &mut Self::Scheduler;
}

/// Holds an feedback
pub trait HasFeedback: UsesState {
    /// The feedback type
    type Feedback: Feedback<Self::State>;

    /// The feedback
    fn feedback(&self) -> &Self::Feedback;

    /// The feedback (mutable)
    fn feedback_mut(&mut self) -> &mut Self::Feedback;
}

/// Holds an objective feedback
pub trait HasObjective: UsesState {
    /// The type of the [`Feedback`] used to find objectives for this fuzzer
    type Objective: Feedback<Self::State>;

    /// The objective feedback
    fn objective(&self) -> &Self::Objective;

    /// The objective feedback (mutable)
    fn objective_mut(&mut self) -> &mut Self::Objective;
}

/// Evaluates if an input is interesting using the feedback
pub trait ExecutionProcessor<OT>: UsesState {
    /// Evaluate if a set of observation channels has an interesting state
    fn process_execution<EM>(
        &mut self,
        state: &mut Self::State,
        manager: &mut EM,
        input: <Self::State as UsesInput>::Input,
        observers: &OT,
        exit_kind: &ExitKind,
        send_events: bool,
    ) -> Result<(ExecuteInputResult, Option<CorpusId>), Error>
    where
        EM: EventFirer<State = Self::State>;
}

/// Evaluates an input modifying the state of the fuzzer
pub trait EvaluatorObservers<OT>: UsesState + Sized {
    /// Runs the input and triggers observers and feedback,
    /// returns if is interesting an (option) the index of the new
    /// [`crate::corpus::Testcase`] in the [`crate::corpus::Corpus`]
    fn evaluate_input_with_observers<E, EM>(
        &mut self,
        state: &mut Self::State,
        executor: &mut E,
        manager: &mut EM,
        input: <Self::State as UsesInput>::Input,
        send_events: bool,
    ) -> Result<(ExecuteInputResult, Option<CorpusId>), Error>
    where
        E: Executor<EM, Self> + HasObservers<Observers = OT, State = Self::State>,
        EM: EventFirer<State = Self::State>;
}

/// Evaluate an input modifying the state of the fuzzer
pub trait Evaluator<E, EM>: UsesState
where
    E: UsesState<State = Self::State>,
    EM: UsesState<State = Self::State>,
{
    /// Runs the input and triggers observers and feedback,
    /// returns if is interesting an (option) the index of the new [`crate::corpus::Testcase`] in the corpus
    fn evaluate_input(
        &mut self,
        state: &mut Self::State,
        executor: &mut E,
        manager: &mut EM,
        input: <Self::State as UsesInput>::Input,
    ) -> Result<(ExecuteInputResult, Option<CorpusId>), Error> {
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
        input: <Self::State as UsesInput>::Input,
        send_events: bool,
    ) -> Result<(ExecuteInputResult, Option<CorpusId>), Error>;

    /// Runs the input and triggers observers and feedback.
    /// Adds an input, to the corpus even if it's not considered `interesting` by the `feedback`.
    /// Returns the `index` of the new testcase in the corpus.
    /// Usually, you want to use [`Evaluator::evaluate_input`], unless you know what you are doing.
    fn add_input(
        &mut self,
        state: &mut Self::State,
        executor: &mut E,
        manager: &mut EM,
        input: <Self::State as UsesInput>::Input,
    ) -> Result<CorpusId, Error>;
}

/// The main fuzzer trait.
pub trait Fuzzer<E, EM, ST>: Sized + UsesState
where
    Self::State: HasMetadata + HasExecutions + HasLastReportTime,
    E: UsesState<State = Self::State>,
    EM: ProgressReporter<State = Self::State>,
    ST: StagesTuple<E, EM, Self::State, Self>,
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
        state: &mut EM::State,
        manager: &mut EM,
    ) -> Result<CorpusId, Error>;

    /// Fuzz forever (or until stopped)
    fn fuzz_loop(
        &mut self,
        stages: &mut ST,
        executor: &mut E,
        state: &mut EM::State,
        manager: &mut EM,
    ) -> Result<(), Error> {
        let monitor_timeout = STATS_TIMEOUT_DEFAULT;
        loop {
            manager.maybe_report_progress(state, monitor_timeout)?;
            self.fuzz_one(stages, executor, state, manager)?;
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
        state: &mut EM::State,
        manager: &mut EM,
        iters: u64,
    ) -> Result<CorpusId, Error> {
        if iters == 0 {
            return Err(Error::illegal_argument(
                "Cannot fuzz for 0 iterations!".to_string(),
            ));
        }

        let mut ret = None;
        let monitor_timeout = STATS_TIMEOUT_DEFAULT;

        for _ in 0..iters {
            manager.maybe_report_progress(state, monitor_timeout)?;
            ret = Some(self.fuzz_one(stages, executor, state, manager)?);
        }

        manager.report_progress(state)?;

        // If we would assume the fuzzer loop will always exit after this, we could do this here:
        // manager.on_restart(state)?;
        // But as the state may grow to a few megabytes,
        // for now we won't, and the user has to do it (unless we find a way to do this on `Drop`).

        Ok(ret.unwrap())
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
pub struct StdFuzzer<CS, F, OF, OT>
where
    CS: Scheduler,
    F: Feedback<CS::State>,
    OF: Feedback<CS::State>,
    CS::State: HasCorpus,
{
    scheduler: CS,
    feedback: F,
    objective: OF,
    phantom: PhantomData<OT>,
}

impl<CS, F, OF, OT> UsesState for StdFuzzer<CS, F, OF, OT>
where
    CS: Scheduler,
    F: Feedback<CS::State>,
    OF: Feedback<CS::State>,
    CS::State: HasCorpus,
{
    type State = CS::State;
}

impl<CS, F, OF, OT> HasScheduler for StdFuzzer<CS, F, OF, OT>
where
    CS: Scheduler,
    F: Feedback<CS::State>,
    OF: Feedback<CS::State>,
    CS::State: HasCorpus,
{
    type Scheduler = CS;

    fn scheduler(&self) -> &CS {
        &self.scheduler
    }

    fn scheduler_mut(&mut self) -> &mut CS {
        &mut self.scheduler
    }
}

impl<CS, F, OF, OT> HasFeedback for StdFuzzer<CS, F, OF, OT>
where
    CS: Scheduler,
    F: Feedback<CS::State>,
    OF: Feedback<CS::State>,
    CS::State: HasCorpus,
{
    type Feedback = F;

    fn feedback(&self) -> &Self::Feedback {
        &self.feedback
    }

    fn feedback_mut(&mut self) -> &mut Self::Feedback {
        &mut self.feedback
    }
}

impl<CS, F, OF, OT> HasObjective for StdFuzzer<CS, F, OF, OT>
where
    CS: Scheduler,
    F: Feedback<CS::State>,
    OF: Feedback<CS::State>,
    CS::State: HasCorpus,
{
    type Objective = OF;

    fn objective(&self) -> &OF {
        &self.objective
    }

    fn objective_mut(&mut self) -> &mut OF {
        &mut self.objective
    }
}

impl<CS, F, OF, OT> ExecutionProcessor<OT> for StdFuzzer<CS, F, OF, OT>
where
    CS: Scheduler,
    F: Feedback<CS::State>,
    OF: Feedback<CS::State>,
    OT: ObserversTuple<CS::State> + Serialize + DeserializeOwned,
    CS::State: HasCorpus + HasSolutions + HasExecutions + HasCorpus + HasImported,
{
    /// Evaluate if a set of observation channels has an interesting state
    fn process_execution<EM>(
        &mut self,
        state: &mut Self::State,
        manager: &mut EM,
        input: <Self::State as UsesInput>::Input,
        observers: &OT,
        exit_kind: &ExitKind,
        send_events: bool,
    ) -> Result<(ExecuteInputResult, Option<CorpusId>), Error>
    where
        EM: EventFirer<State = Self::State>,
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
                self.feedback_mut()
                    .append_metadata(state, manager, observers, &mut testcase)?;
                let idx = state.corpus_mut().add(testcase)?;
                self.scheduler_mut().on_add(state, idx)?;

                if send_events {
                    // TODO set None for fast targets
                    let observers_buf = if manager.configuration() == EventConfig::AlwaysUnique {
                        None
                    } else {
                        manager.serialize_observers::<OT>(observers)?
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
                            forward_id: None,
                        },
                    )?;
                } else {
                    // This testcase is from the other fuzzers.
                    *state.imported_mut() += 1;
                }
                Ok((res, Some(idx)))
            }
            ExecuteInputResult::Solution => {
                // Not interesting
                self.feedback_mut().discard_metadata(state, &input)?;

                let executions = *state.executions();
                // The input is a solution, add it to the respective corpus
                let mut testcase = Testcase::with_executions(input, executions);
                testcase.set_parent_id_optional(*state.corpus().current());
                self.objective_mut()
                    .append_metadata(state, manager, observers, &mut testcase)?;
                state.solutions_mut().add(testcase)?;

                if send_events {
                    manager.fire(
                        state,
                        Event::Objective {
                            objective_size: state.solutions().count(),
                            executions,
                            time: current_time(),
                        },
                    )?;
                }

                Ok((res, None))
            }
        }
    }
}

impl<CS, F, OF, OT> EvaluatorObservers<OT> for StdFuzzer<CS, F, OF, OT>
where
    CS: Scheduler,
    OT: ObserversTuple<CS::State> + Serialize + DeserializeOwned,
    F: Feedback<CS::State>,
    OF: Feedback<CS::State>,
    CS::State: HasCorpus + HasSolutions + HasExecutions + HasImported,
{
    /// Process one input, adding to the respective corpora if needed and firing the right events
    #[inline]
    fn evaluate_input_with_observers<E, EM>(
        &mut self,
        state: &mut Self::State,
        executor: &mut E,
        manager: &mut EM,
        input: <Self::State as UsesInput>::Input,
        send_events: bool,
    ) -> Result<(ExecuteInputResult, Option<CorpusId>), Error>
    where
        E: Executor<EM, Self> + HasObservers<Observers = OT, State = Self::State>,
        EM: EventFirer<State = Self::State>,
    {
        let exit_kind = self.execute_input(state, executor, manager, &input)?;
        let observers = executor.observers();

        self.scheduler.on_evaluation(state, &input, observers)?;

        self.process_execution(state, manager, input, observers, &exit_kind, send_events)
    }
}

impl<CS, E, EM, F, OF, OT> Evaluator<E, EM> for StdFuzzer<CS, F, OF, OT>
where
    CS: Scheduler,
    E: HasObservers<State = CS::State, Observers = OT> + Executor<EM, Self>,
    EM: EventFirer<State = CS::State>,
    F: Feedback<CS::State>,
    OF: Feedback<CS::State>,
    OT: ObserversTuple<CS::State> + Serialize + DeserializeOwned,
    CS::State: HasCorpus + HasSolutions + HasExecutions + HasImported,
{
    /// Process one input, adding to the respective corpora if needed and firing the right events
    #[inline]
    fn evaluate_input_events(
        &mut self,
        state: &mut Self::State,
        executor: &mut E,
        manager: &mut EM,
        input: <Self::State as UsesInput>::Input,
        send_events: bool,
    ) -> Result<(ExecuteInputResult, Option<CorpusId>), Error> {
        self.evaluate_input_with_observers(state, executor, manager, input, send_events)
    }

    /// Adds an input, even if it's not considered `interesting` by any of the executors
    fn add_input(
        &mut self,
        state: &mut Self::State,
        executor: &mut E,
        manager: &mut EM,
        input: <Self::State as UsesInput>::Input,
    ) -> Result<CorpusId, Error> {
        let exit_kind = self.execute_input(state, executor, manager, &input)?;
        let observers = executor.observers();
        // Always consider this to be "interesting"
        let mut testcase = Testcase::with_executions(input.clone(), *state.executions());

        // Maybe a solution
        #[cfg(not(feature = "introspection"))]
        let is_solution = self
            .objective_mut()
            .is_interesting(state, manager, &input, observers, &exit_kind)?;

        #[cfg(feature = "introspection")]
        let is_solution = self
            .objective_mut()
            .is_interesting_introspection(state, manager, &input, observers, &exit_kind)?;

        if is_solution {
            self.objective_mut()
                .append_metadata(state, manager, observers, &mut testcase)?;
            let idx = state.solutions_mut().add(testcase)?;

            let executions = *state.executions();
            manager.fire(
                state,
                Event::Objective {
                    objective_size: state.solutions().count(),
                    executions,
                    time: current_time(),
                },
            )?;
            return Ok(idx);
        }

        // Not a solution
        self.objective_mut().discard_metadata(state, &input)?;

        // several is_interesting implementations collect some data about the run, later used in
        // append_metadata; we *must* invoke is_interesting here to collect it
        #[cfg(not(feature = "introspection"))]
        let _is_corpus = self
            .feedback_mut()
            .is_interesting(state, manager, &input, observers, &exit_kind)?;

        #[cfg(feature = "introspection")]
        let _is_corpus = self
            .feedback_mut()
            .is_interesting_introspection(state, manager, &input, observers, &exit_kind)?;

        // Add the input to the main corpus
        self.feedback_mut()
            .append_metadata(state, manager, observers, &mut testcase)?;
        let idx = state.corpus_mut().add(testcase)?;
        self.scheduler_mut().on_add(state, idx)?;

        let observers_buf = if manager.configuration() == EventConfig::AlwaysUnique {
            None
        } else {
            manager.serialize_observers::<OT>(observers)?
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
                forward_id: None,
            },
        )?;
        Ok(idx)
    }
}

impl<CS, E, EM, F, OF, OT, ST> Fuzzer<E, EM, ST> for StdFuzzer<CS, F, OF, OT>
where
    CS: Scheduler,
    E: UsesState<State = CS::State>,
    EM: ProgressReporter + EventProcessor<E, Self, State = CS::State>,
    F: Feedback<CS::State>,
    OF: Feedback<CS::State>,
    CS::State: HasExecutions
        + HasMetadata
        + HasCorpus
        + HasTestcase
        + HasImported
        + HasLastReportTime
        + HasCurrentCorpusIdx
        + HasCurrentStage,
    ST: StagesTuple<E, EM, CS::State, Self>,
{
    fn fuzz_one(
        &mut self,
        stages: &mut ST,
        executor: &mut E,
        state: &mut CS::State,
        manager: &mut EM,
    ) -> Result<CorpusId, Error> {
        // Init timer for scheduler
        #[cfg(feature = "introspection")]
        state.introspection_monitor_mut().start_timer();

        // Get the next index from the scheduler
        let idx = if let Some(idx) = state.current_corpus_idx()? {
            idx // we are resuming
        } else {
            let idx = self.scheduler.next(state)?;
            state.set_corpus_idx(idx)?; // set up for resume
            idx
        };

        // Mark the elapsed time for the scheduler
        #[cfg(feature = "introspection")]
        state.introspection_monitor_mut().mark_scheduler_time();

        // Mark the elapsed time for the scheduler
        #[cfg(feature = "introspection")]
        state.introspection_monitor_mut().reset_stage_index();

        // Execute all stages
        stages.perform_all(self, executor, state, manager)?;

        // Init timer for manager
        #[cfg(feature = "introspection")]
        state.introspection_monitor_mut().start_timer();

        // Execute the manager
        manager.process(self, state, executor)?;

        // Mark the elapsed time for the manager
        #[cfg(feature = "introspection")]
        state.introspection_monitor_mut().mark_manager_time();

        {
            if let Ok(mut testcase) = state.testcase_mut(idx) {
                let scheduled_count = testcase.scheduled_count();
                // increase scheduled count, this was fuzz_level in afl
                testcase.set_scheduled_count(scheduled_count + 1);
            }
        }

        state.clear_corpus_idx()?;

        Ok(idx)
    }
}

impl<CS, F, OF, OT> StdFuzzer<CS, F, OF, OT>
where
    CS: Scheduler,
    F: Feedback<CS::State>,
    OF: Feedback<CS::State>,
    CS::State: UsesInput + HasExecutions + HasCorpus,
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
        state: &mut CS::State,
        executor: &mut E,
        event_mgr: &mut EM,
        input: &<CS::State as UsesInput>::Input,
    ) -> Result<ExitKind, Error>
    where
        E: Executor<EM, Self> + HasObservers<Observers = OT, State = CS::State>,
        EM: UsesState<State = CS::State>,
        OT: ObserversTuple<CS::State>,
    {
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

/// Structs with this trait will execute an input
pub trait ExecutesInput<E, EM>: UsesState
where
    E: UsesState<State = Self::State>,
    EM: UsesState<State = Self::State>,
{
    /// Runs the input and triggers observers and feedback
    fn execute_input(
        &mut self,
        state: &mut Self::State,
        executor: &mut E,
        event_mgr: &mut EM,
        input: &<Self::State as UsesInput>::Input,
    ) -> Result<ExitKind, Error>;
}

impl<CS, E, EM, F, OF> ExecutesInput<E, EM> for StdFuzzer<CS, F, OF, E::Observers>
where
    CS: Scheduler,
    F: Feedback<CS::State>,
    OF: Feedback<CS::State>,
    E: Executor<EM, Self> + HasObservers<State = CS::State>,
    EM: UsesState<State = CS::State>,
    CS::State: UsesInput + HasExecutions + HasCorpus,
{
    /// Runs the input and triggers observers and feedback
    fn execute_input(
        &mut self,
        state: &mut CS::State,
        executor: &mut E,
        event_mgr: &mut EM,
        input: &<CS::State as UsesInput>::Input,
    ) -> Result<ExitKind, Error> {
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

#[cfg(test)]
pub mod test {
    use core::marker::PhantomData;

    use libafl_bolts::Error;

    use crate::{
        corpus::CorpusId,
        events::ProgressReporter,
        stages::{HasCurrentStage, StagesTuple},
        state::{HasExecutions, HasLastReportTime, HasMetadata, State, UsesState},
        Fuzzer,
    };

    #[derive(Clone, Debug)]
    pub struct NopFuzzer<S> {
        phantom: PhantomData<S>,
    }

    impl<S> NopFuzzer<S> {
        #[must_use]
        pub fn new() -> Self {
            Self {
                phantom: PhantomData,
            }
        }
    }

    impl<S> Default for NopFuzzer<S> {
        fn default() -> Self {
            Self::new()
        }
    }

    impl<S> UsesState for NopFuzzer<S>
    where
        S: State,
    {
        type State = S;
    }

    impl<ST, E, EM> Fuzzer<E, EM, ST> for NopFuzzer<E::State>
    where
        E: UsesState,
        EM: ProgressReporter<State = E::State>,
        ST: StagesTuple<E, EM, E::State, Self>,
        E::State: HasMetadata + HasExecutions + HasLastReportTime + HasCurrentStage,
    {
        fn fuzz_one(
            &mut self,
            _stages: &mut ST,
            _executor: &mut E,
            _state: &mut EM::State,
            _manager: &mut EM,
        ) -> Result<CorpusId, Error> {
            unimplemented!()
        }
    }
}

#[cfg(feature = "python")]
#[allow(missing_docs)]
/// `Fuzzer` Python bindings
pub mod pybind {
    use alloc::{boxed::Box, vec::Vec};

    use libafl_bolts::ownedref::OwnedMutPtr;
    use pyo3::prelude::*;

    use crate::{
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
        QueueScheduler<PythonStdState>,
        PythonFeedback,
        PythonFeedback,
        PythonObserversTuple,
    >;

    /// Python class for StdFuzzer
    #[pyclass(unsendable, name = "StdFuzzer")]
    #[derive(Debug)]
    pub struct PythonStdFuzzerWrapper {
        /// Rust wrapped StdFuzzer object
        pub inner: OwnedMutPtr<PythonStdFuzzer>,
    }

    impl PythonStdFuzzerWrapper {
        pub fn wrap(r: &mut PythonStdFuzzer) -> Self {
            Self {
                inner: OwnedMutPtr::Ptr(r),
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
                inner: OwnedMutPtr::Owned(Box::new(StdFuzzer::new(
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
                .0
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
