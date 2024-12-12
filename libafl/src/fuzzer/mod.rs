//! The `Fuzzer` is the main struct for a fuzz campaign.

use alloc::{string::ToString, vec::Vec};
use core::{fmt::Debug, marker::PhantomData, time::Duration};

use libafl_bolts::current_time;
use serde::{de::DeserializeOwned, Serialize};

#[cfg(feature = "introspection")]
use crate::monitors::PerfFeature;
use crate::{
    corpus::{Corpus, CorpusId, HasCurrentCorpusId, HasTestcase, Testcase},
    events::{Event, EventConfig, EventFirer, EventProcessor, ProgressReporter},
    executors::{Executor, ExitKind, HasObservers},
    feedbacks::Feedback,
    inputs::UsesInput,
    mark_feature_time,
    observers::ObserversTuple,
    schedulers::Scheduler,
    stages::{HasCurrentStageId, StagesTuple},
    start_timer,
    state::{
        HasCorpus, HasCurrentTestcase, HasExecutions, HasLastFoundTime, HasLastReportTime,
        HasSolutions, State, Stoppable, UsesState,
    },
    Error, HasMetadata,
};

/// Send a monitor update all 15 (or more) seconds
pub(crate) const STATS_TIMEOUT_DEFAULT: Duration = Duration::from_secs(15);

/// Holds a scheduler
pub trait HasScheduler: UsesState
where
    Self::State: HasCorpus,
{
    /// The [`Scheduler`] for this fuzzer
    type Scheduler: Scheduler<Self::Input, Self::State>;

    /// The scheduler
    fn scheduler(&self) -> &Self::Scheduler;

    /// The scheduler (mutable)
    fn scheduler_mut(&mut self) -> &mut Self::Scheduler;
}

/// Holds an feedback
pub trait HasFeedback: UsesState {
    /// The feedback type
    type Feedback;

    /// The feedback
    fn feedback(&self) -> &Self::Feedback;

    /// The feedback (mutable)
    fn feedback_mut(&mut self) -> &mut Self::Feedback;
}

/// Holds an objective feedback
pub trait HasObjective: UsesState {
    /// The type of the [`Feedback`] used to find objectives for this fuzzer
    type Objective;

    /// The objective feedback
    fn objective(&self) -> &Self::Objective;

    /// The objective feedback (mutable)
    fn objective_mut(&mut self) -> &mut Self::Objective;
}

/// Evaluates if an input is interesting using the feedback
pub trait ExecutionProcessor<EM, OT>: UsesState {
    /// Check the outcome of the execution, find if it is worth for corpus or objectives
    fn check_results(
        &mut self,
        state: &mut Self::State,
        manager: &mut EM,
        input: &<Self::State as UsesInput>::Input,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<ExecuteInputResult, Error>
    where
        EM: EventFirer<State = Self::State>,
        OT: ObserversTuple<<Self as UsesInput>::Input, Self::State>;

    /// Process `ExecuteInputResult`. Add to corpus, solution or ignore
    #[allow(clippy::too_many_arguments)]
    fn process_execution(
        &mut self,
        state: &mut Self::State,
        manager: &mut EM,
        input: &<Self::State as UsesInput>::Input,
        exec_res: &ExecuteInputResult,
        observers: &OT,
    ) -> Result<Option<CorpusId>, Error>
    where
        EM: EventFirer<State = Self::State>,
        OT: ObserversTuple<<Self as UsesInput>::Input, Self::State>;

    /// serialize and send event via manager
    fn serialize_and_dispatch(
        &mut self,
        state: &mut Self::State,
        manager: &mut EM,
        input: <Self::State as UsesInput>::Input,
        exec_res: &ExecuteInputResult,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<(), Error>
    where
        EM: EventFirer<State = Self::State>,
        OT: ObserversTuple<<Self as UsesInput>::Input, Self::State> + Serialize;

    /// send event via manager
    fn dispatch_event(
        &mut self,
        state: &mut Self::State,
        manager: &mut EM,
        input: <Self::State as UsesInput>::Input,
        exec_res: &ExecuteInputResult,
        obs_buf: Option<Vec<u8>>,
        exit_kind: &ExitKind,
    ) -> Result<(), Error>
    where
        EM: EventFirer<State = Self::State>;

    /// Evaluate if a set of observation channels has an interesting state
    fn evaluate_execution(
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
        OT: ObserversTuple<<Self as UsesInput>::Input, Self::State> + Serialize;
}

/// Evaluates an input modifying the state of the fuzzer
pub trait EvaluatorObservers<EM, OT>: UsesState + Sized {
    /// Runs the input and triggers observers and feedback,
    /// returns if is interesting an (option) the index of the new
    /// [`crate::corpus::Testcase`] in the [`crate::corpus::Corpus`]
    fn evaluate_input_with_observers<E>(
        &mut self,
        state: &mut Self::State,
        executor: &mut E,
        manager: &mut EM,
        input: <Self::State as UsesInput>::Input,
        send_events: bool,
    ) -> Result<(ExecuteInputResult, Option<CorpusId>), Error>
    where
        E: Executor<EM, Self, State = Self::State> + HasObservers<Observers = OT>,
        EM: EventFirer<State = Self::State>;
}

/// Evaluate an input modifying the state of the fuzzer
pub trait Evaluator<E, EM>: UsesState {
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

    /// Adds the input to the corpus as disabled a input.
    /// Used during initial corpus loading.
    /// Disabled testcases are only used for splicing
    /// Returns the `index` of the new testcase in the corpus.
    /// Usually, you want to use [`Evaluator::evaluate_input`], unless you know what you are doing.
    fn add_disabled_input(
        &mut self,
        state: &mut Self::State,
        input: <Self::State as UsesInput>::Input,
    ) -> Result<CorpusId, Error>;
}

/// The main fuzzer trait.
pub trait Fuzzer<E, EM, ST>: Sized + UsesState
where
    Self::State: HasMetadata + HasExecutions + HasLastReportTime + Stoppable,
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
        state: &mut Self::State,
        manager: &mut EM,
    ) -> Result<CorpusId, Error>;

    /// Fuzz forever (or until stopped)
    fn fuzz_loop(
        &mut self,
        stages: &mut ST,
        executor: &mut E,
        state: &mut Self::State,
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
        state: &mut Self::State,
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
pub struct StdFuzzer<CS, F, OF, S> {
    scheduler: CS,
    feedback: F,
    objective: OF,
    phantom: PhantomData<S>,
}

impl<CS, F, OF, S> UsesState for StdFuzzer<CS, F, OF, S>
where
    S: State,
{
    type State = S;
}

impl<CS, F, OF, S> HasScheduler for StdFuzzer<CS, F, OF, S>
where
    S: State + HasCorpus,
    CS: Scheduler<S::Input, S>,
{
    type Scheduler = CS;

    fn scheduler(&self) -> &CS {
        &self.scheduler
    }

    fn scheduler_mut(&mut self) -> &mut CS {
        &mut self.scheduler
    }
}

impl<CS, F, OF, S> HasFeedback for StdFuzzer<CS, F, OF, S>
where
    S: State,
{
    type Feedback = F;

    fn feedback(&self) -> &Self::Feedback {
        &self.feedback
    }

    fn feedback_mut(&mut self) -> &mut Self::Feedback {
        &mut self.feedback
    }
}

impl<CS, F, OF, S> HasObjective for StdFuzzer<CS, F, OF, S>
where
    S: State,
{
    type Objective = OF;

    fn objective(&self) -> &OF {
        &self.objective
    }

    fn objective_mut(&mut self) -> &mut OF {
        &mut self.objective
    }
}

impl<CS, EM, F, OF, OT, S> ExecutionProcessor<EM, OT> for StdFuzzer<CS, F, OF, S>
where
    CS: Scheduler<S::Input, S>,
    F: Feedback<EM, S::Input, OT, S>,
    OF: Feedback<EM, S::Input, OT, S>,
    S: HasCorpus + HasSolutions + HasExecutions + HasCorpus + HasCurrentCorpusId + State,
    S::Corpus: Corpus<Input = S::Input>,    //delete me
    S::Solutions: Corpus<Input = S::Input>, //delete me
{
    fn check_results(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        input: &S::Input,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<ExecuteInputResult, Error>
    where
        EM: EventFirer<State = Self::State>,
        OT: ObserversTuple<Self::Input, Self::State>,
    {
        let mut res = ExecuteInputResult::None;

        #[cfg(not(feature = "introspection"))]
        let is_solution = self
            .objective_mut()
            .is_interesting(state, manager, input, observers, exit_kind)?;

        #[cfg(feature = "introspection")]
        let is_solution = self
            .objective_mut()
            .is_interesting_introspection(state, manager, input, observers, exit_kind)?;

        if is_solution {
            res = ExecuteInputResult::Solution;
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
                res = ExecuteInputResult::Corpus;
            }
        }
        Ok(res)
    }

    fn evaluate_execution(
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
        OT: ObserversTuple<Self::Input, Self::State> + Serialize,
    {
        let exec_res = self.check_results(state, manager, &input, observers, exit_kind)?;
        let corpus_id = self.process_execution(state, manager, &input, &exec_res, observers)?;
        if send_events {
            self.serialize_and_dispatch(state, manager, input, &exec_res, observers, exit_kind)?;
        }
        Ok((exec_res, corpus_id))
    }

    fn serialize_and_dispatch(
        &mut self,
        state: &mut Self::State,
        manager: &mut EM,
        input: <Self::State as UsesInput>::Input,
        exec_res: &ExecuteInputResult,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<(), Error>
    where
        EM: EventFirer<State = Self::State>,
        OT: ObserversTuple<Self::Input, Self::State> + Serialize,
    {
        // Now send off the event
        let observers_buf = match exec_res {
            ExecuteInputResult::Corpus => {
                if manager.should_send() {
                    // TODO set None for fast targets
                    if manager.configuration() == EventConfig::AlwaysUnique {
                        None
                    } else {
                        manager.serialize_observers::<OT>(observers)?
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
        state: &mut Self::State,
        manager: &mut EM,
        input: <Self::State as UsesInput>::Input,
        exec_res: &ExecuteInputResult,
        observers_buf: Option<Vec<u8>>,
        exit_kind: &ExitKind,
    ) -> Result<(), Error>
    where
        EM: EventFirer<State = Self::State>,
    {
        // Now send off the event
        match exec_res {
            ExecuteInputResult::Corpus => {
                if manager.should_send() {
                    manager.fire(
                        state,
                        Event::NewTestcase {
                            input,
                            observers_buf,
                            exit_kind: *exit_kind,
                            corpus_size: state.corpus().count(),
                            client_config: manager.configuration(),
                            time: current_time(),
                            forward_id: None,
                            #[cfg(all(unix, feature = "std", feature = "multi_machine"))]
                            node_id: None,
                        },
                    )?;
                }
            }
            ExecuteInputResult::Solution => {
                if manager.should_send() {
                    manager.fire(
                        state,
                        Event::Objective {
                            objective_size: state.solutions().count(),
                            time: current_time(),
                        },
                    )?;
                }
            }
            ExecuteInputResult::None => (),
        }
        Ok(())
    }

    /// Evaluate if a set of observation channels has an interesting state
    fn process_execution(
        &mut self,
        state: &mut Self::State,
        manager: &mut EM,
        input: &S::Input,
        exec_res: &ExecuteInputResult,
        observers: &OT,
    ) -> Result<Option<CorpusId>, Error>
    where
        EM: EventFirer<State = Self::State>,
        OT: ObserversTuple<Self::Input, Self::State>,
    {
        match exec_res {
            ExecuteInputResult::None => {
                self.feedback_mut().discard_metadata(state, input)?;
                self.objective_mut().discard_metadata(state, input)?;
                Ok(None)
            }
            ExecuteInputResult::Corpus => {
                // Not a solution
                self.objective_mut().discard_metadata(state, input)?;

                // Add the input to the main corpus
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
            ExecuteInputResult::Solution => {
                // Not interesting
                self.feedback_mut().discard_metadata(state, input)?;

                // The input is a solution, add it to the respective corpus
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
}

impl<CS, EM, F, OF, OT, S> EvaluatorObservers<EM, OT> for StdFuzzer<CS, F, OF, S>
where
    CS: Scheduler<S::Input, S>,
    OT: ObserversTuple<S::Input, S> + Serialize + DeserializeOwned,
    F: Feedback<EM, S::Input, OT, S>,
    OF: Feedback<EM, S::Input, OT, S>,
    S: HasCorpus + HasSolutions + HasExecutions + State,
    S::Corpus: Corpus<Input = S::Input>,    //delete me
    S::Solutions: Corpus<Input = S::Input>, //delete me
{
    /// Process one input, adding to the respective corpora if needed and firing the right events
    #[inline]
    fn evaluate_input_with_observers<E>(
        &mut self,
        state: &mut S,
        executor: &mut E,
        manager: &mut EM,
        input: S::Input,
        send_events: bool,
    ) -> Result<(ExecuteInputResult, Option<CorpusId>), Error>
    where
        E: Executor<EM, Self, State = S> + HasObservers<Observers = OT>,
        EM: EventFirer<State = S>,
    {
        let exit_kind = self.execute_input(state, executor, manager, &input)?;
        let observers = executor.observers();

        self.scheduler.on_evaluation(state, &input, &*observers)?;

        self.evaluate_execution(state, manager, input, &*observers, &exit_kind, send_events)
    }
}

impl<CS, E, EM, F, OF, S> Evaluator<E, EM> for StdFuzzer<CS, F, OF, S>
where
    CS: Scheduler<S::Input, S>,
    E: HasObservers + Executor<EM, Self, State = S>,
    E::Observers: ObserversTuple<S::Input, S> + Serialize + DeserializeOwned,
    EM: EventFirer<State = S>,
    F: Feedback<EM, S::Input, E::Observers, S>,
    OF: Feedback<EM, S::Input, E::Observers, S>,
    S: HasCorpus + HasSolutions + HasExecutions + HasLastFoundTime + State,
    S::Corpus: Corpus<Input = S::Input>,    //delete me
    S::Solutions: Corpus<Input = S::Input>, //delete me
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
    fn add_disabled_input(
        &mut self,
        state: &mut Self::State,
        input: <Self::State as UsesInput>::Input,
    ) -> Result<CorpusId, Error> {
        let mut testcase = Testcase::from(input.clone());
        testcase.set_disabled(true);
        // Add the disabled input to the main corpus
        let id = state.corpus_mut().add_disabled(testcase)?;
        Ok(id)
    }
    /// Adds an input, even if it's not considered `interesting` by any of the executors
    fn add_input(
        &mut self,
        state: &mut Self::State,
        executor: &mut E,
        manager: &mut EM,
        input: <Self::State as UsesInput>::Input,
    ) -> Result<CorpusId, Error> {
        *state.last_found_time_mut() = current_time();

        let exit_kind = self.execute_input(state, executor, manager, &input)?;
        let observers = executor.observers();
        // Always consider this to be "interesting"
        let mut testcase = Testcase::from(input.clone());

        // Maybe a solution
        #[cfg(not(feature = "introspection"))]
        let is_solution: bool =
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
            #[cfg(feature = "track_hit_feedbacks")]
            self.objective_mut()
                .append_hit_feedbacks(testcase.hit_objectives_mut())?;
            self.objective_mut()
                .append_metadata(state, manager, &*observers, &mut testcase)?;
            let id = state.solutions_mut().add(testcase)?;

            manager.fire(
                state,
                Event::Objective {
                    objective_size: state.solutions().count(),
                    time: current_time(),
                },
            )?;
            return Ok(id);
        }

        // Not a solution
        self.objective_mut().discard_metadata(state, &input)?;

        // several is_interesting implementations collect some data about the run, later used in
        // append_metadata; we *must* invoke is_interesting here to collect it
        #[cfg(not(feature = "introspection"))]
        let _corpus_worthy =
            self.feedback_mut()
                .is_interesting(state, manager, &input, &*observers, &exit_kind)?;

        #[cfg(feature = "introspection")]
        let _corpus_worthy = self.feedback_mut().is_interesting_introspection(
            state,
            manager,
            &input,
            &*observers,
            &exit_kind,
        )?;

        #[cfg(feature = "track_hit_feedbacks")]
        self.feedback_mut()
            .append_hit_feedbacks(testcase.hit_feedbacks_mut())?;
        // Add the input to the main corpus
        self.feedback_mut()
            .append_metadata(state, manager, &*observers, &mut testcase)?;
        let id = state.corpus_mut().add(testcase)?;
        self.scheduler_mut().on_add(state, id)?;

        let observers_buf = if manager.configuration() == EventConfig::AlwaysUnique {
            None
        } else {
            manager.serialize_observers::<E::Observers>(&*observers)?
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
                forward_id: None,
                #[cfg(all(unix, feature = "std", feature = "multi_machine"))]
                node_id: None,
            },
        )?;
        Ok(id)
    }
}

impl<CS, E, EM, F, OF, S, ST> Fuzzer<E, EM, ST> for StdFuzzer<CS, F, OF, S>
where
    CS: Scheduler<S::Input, S>,
    E: UsesState<State = S>,
    EM: ProgressReporter + EventProcessor<E, Self, State = S>,
    S: HasExecutions
        + HasMetadata
        + HasCorpus
        + HasLastReportTime
        + HasTestcase
        + HasCurrentCorpusId
        + HasCurrentStageId
        + State,
    ST: StagesTuple<E, EM, S, Self>,
{
    fn fuzz_one(
        &mut self,
        stages: &mut ST,
        executor: &mut E,
        state: &mut Self::State,
        manager: &mut EM,
    ) -> Result<CorpusId, Error> {
        // Init timer for scheduler
        #[cfg(feature = "introspection")]
        state.introspection_monitor_mut().start_timer();

        // Get the next index from the scheduler
        let id = if let Some(id) = state.current_corpus_id()? {
            id // we are resuming
        } else {
            let id = self.scheduler.next(state)?;
            state.set_corpus_id(id)?; // set up for resume
            id
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
}

impl<CS, F, OF, S> StdFuzzer<CS, F, OF, S>
where
    CS: Scheduler<S::Input, S>,
    S: UsesInput + HasExecutions + HasCorpus + State,
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

    /// Runs the input and triggers observers
    pub fn execute_input<E, EM>(
        &mut self,
        state: &mut <Self as UsesState>::State,
        executor: &mut E,
        event_mgr: &mut EM,
        input: &<<Self as UsesState>::State as UsesInput>::Input,
    ) -> Result<ExitKind, Error>
    where
        E: Executor<EM, Self, State = <Self as UsesState>::State> + HasObservers,
        E::Observers: ObserversTuple<<Self as UsesInput>::Input, <Self as UsesState>::State>,
        EM: UsesState<State = <Self as UsesState>::State>,
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

impl<CS, E, EM, F, OF, S> ExecutesInput<E, EM> for StdFuzzer<CS, F, OF, S>
where
    CS: Scheduler<S::Input, S>,
    E: Executor<EM, Self, State = S> + HasObservers,
    E::Observers: ObserversTuple<<Self as UsesInput>::Input, <Self as UsesState>::State>,
    EM: UsesState<State = Self::State>,
    S: UsesInput + HasExecutions + HasCorpus + State,
{
    /// Runs the input and triggers observers and feedback
    fn execute_input(
        &mut self,
        state: &mut S,
        executor: &mut E,
        event_mgr: &mut EM,
        input: &S::Input,
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

/// A [`NopFuzzer`] that does nothing
#[derive(Clone, Debug)]
pub struct NopFuzzer<S> {
    phantom: PhantomData<S>,
}

impl<S> NopFuzzer<S> {
    /// Creates a new [`NopFuzzer`]
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
    EM: ProgressReporter<State = Self::State> + EventProcessor<E, Self>,
    ST: StagesTuple<E, EM, Self::State, Self>,
    Self::State: HasMetadata + HasExecutions + HasLastReportTime + HasCurrentStageId,
{
    fn fuzz_one(
        &mut self,
        _stages: &mut ST,
        _executor: &mut E,
        _state: &mut EM::State,
        _manager: &mut EM,
    ) -> Result<CorpusId, Error> {
        unimplemented!("NopFuzzer cannot fuzz");
    }
}
