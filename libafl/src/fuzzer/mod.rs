//! The `Fuzzer` is the main struct for a fuzz campaign.

use crate::{
    bolts::current_time,
    corpus::{Corpus, CorpusScheduler, Testcase},
    events::{Event, EventConfig, EventFirer, EventManager},
    executors::{Executor, ExitKind, HasObservers},
    feedbacks::Feedback,
    inputs::Input,
    mark_feature_time,
    observers::ObserversTuple,
    stages::StagesTuple,
    start_timer,
    state::{HasClientPerfMonitor, HasCorpus, HasExecutions, HasSolutions},
    Error,
};

#[cfg(feature = "introspection")]
use crate::monitors::PerfFeature;
#[cfg(feature = "introspection")]
use alloc::boxed::Box;

use alloc::string::ToString;
use core::{marker::PhantomData, time::Duration};

/// Send a monitor update all 15 (or more) seconds
const STATS_TIMEOUT_DEFAULT: Duration = Duration::from_secs(15);

/// Holds a scheduler
pub trait HasCorpusScheduler<CS, I, S>
where
    CS: CorpusScheduler<I, S>,
    I: Input,
{
    /// The scheduler
    fn scheduler(&self) -> &CS;

    /// The scheduler (mut)
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

    /// The feedback (mut)
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

    /// The objective feedback (mut)
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
        EM: EventFirer<I, S>;
}

/// Evaluate an input modyfing the state of the fuzzer
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

/// Evaluate an input modyfing the state of the fuzzer
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
pub trait Fuzzer<E, EM, I, S, ST> {
    /// Fuzz for a single iteration
    /// Returns the index of the last fuzzed corpus item
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
            last = Self::maybe_report_monitor(state, manager, last, monitor_timeout)?;
        }
    }

    /// Fuzz for n iterations
    /// Returns the index of the last fuzzed corpus item
    ///
    /// If you use this fn in a restarting scenario to only run for `n` iterations,
    /// before exiting, make sure you call `event_mgr.on_restart(&mut state)?;`.
    /// This way, the state will be available in the next, respawned, iteration.
    fn fuzz_loop_for(
        &mut self,
        stages: &mut ST,
        state: &mut S,
        executor: &mut E,
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
            last = Self::maybe_report_monitor(state, manager, last, monitor_timeout)?;
        }

        // If we would assume the fuzzer loop will always exit after this, we could do this here:
        // manager.on_restart(state)?;
        // But as the state may grow to a few megabytes,
        // for now we won' and the user has to do it (unless we find a way to do this on `Drop`).

        Ok(ret)
    }

    /// Given the last time, if `monitor_timeout` seconds passed, send off an info/monitor/heartbeat message to the broker.
    /// Returns the new `last` time (so the old one, unless `monitor_timeout` time has passed and monitor have been sent)
    /// Will return an [`crate::Error`], if the monitor could not be sent.
    fn maybe_report_monitor(
        state: &mut S,
        manager: &mut EM,
        last: Duration,
        monitor_timeout: Duration,
    ) -> Result<Duration, Error>;
}

#[derive(Debug, PartialEq)]
pub enum ExecuteInputResult {
    None,
    Corpus,
    Solution,
}

/// Your default fuzzer instance, for everyday use.
#[derive(Debug)]
pub struct StdFuzzer<C, CS, F, I, OF, OT, S, SC>
where
    CS: CorpusScheduler<I, S>,
    F: Feedback<I, S>,
    I: Input,
    OF: Feedback<I, S>,
    S: HasClientPerfMonitor,
{
    scheduler: CS,
    feedback: F,
    objective: OF,
    phantom: PhantomData<(C, I, OT, S, SC)>,
}

impl<C, CS, F, I, OF, OT, S, SC> HasCorpusScheduler<CS, I, S>
    for StdFuzzer<C, CS, F, I, OF, OT, S, SC>
where
    CS: CorpusScheduler<I, S>,
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

impl<C, CS, F, I, OF, OT, S, SC> HasFeedback<F, I, S> for StdFuzzer<C, CS, F, I, OF, OT, S, SC>
where
    CS: CorpusScheduler<I, S>,
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

impl<C, CS, F, I, OF, OT, S, SC> HasObjective<I, OF, S> for StdFuzzer<C, CS, F, I, OF, OT, S, SC>
where
    CS: CorpusScheduler<I, S>,
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

impl<C, CS, F, I, OF, OT, S, SC> ExecutionProcessor<I, OT, S>
    for StdFuzzer<C, CS, F, I, OF, OT, S, SC>
where
    C: Corpus<I>,
    SC: Corpus<I>,
    CS: CorpusScheduler<I, S>,
    F: Feedback<I, S>,
    I: Input,
    OF: Feedback<I, S>,
    OT: ObserversTuple<I, S> + serde::Serialize + serde::de::DeserializeOwned,
    S: HasCorpus<C, I> + HasSolutions<SC, I> + HasClientPerfMonitor + HasExecutions,
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
        EM: EventFirer<I, S>,
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
                let mut testcase = Testcase::new(input.clone());
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
                let mut testcase = Testcase::new(input);
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

impl<C, CS, F, I, OF, OT, S, SC> EvaluatorObservers<I, OT, S>
    for StdFuzzer<C, CS, F, I, OF, OT, S, SC>
where
    C: Corpus<I>,
    CS: CorpusScheduler<I, S>,
    OT: ObserversTuple<I, S> + serde::Serialize + serde::de::DeserializeOwned,
    F: Feedback<I, S>,
    I: Input,
    OF: Feedback<I, S>,
    S: HasExecutions + HasCorpus<C, I> + HasSolutions<SC, I> + HasClientPerfMonitor,
    SC: Corpus<I>,
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

impl<C, CS, E, EM, F, I, OF, OT, S, SC> Evaluator<E, EM, I, S>
    for StdFuzzer<C, CS, F, I, OF, OT, S, SC>
where
    C: Corpus<I>,
    CS: CorpusScheduler<I, S>,
    E: Executor<EM, I, S, Self> + HasObservers<I, OT, S>,
    OT: ObserversTuple<I, S> + serde::Serialize + serde::de::DeserializeOwned,
    EM: EventManager<E, I, S, Self>,
    F: Feedback<I, S>,
    I: Input,
    OF: Feedback<I, S>,
    S: HasExecutions + HasCorpus<C, I> + HasSolutions<SC, I> + HasClientPerfMonitor,
    SC: Corpus<I>,
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
        let mut testcase = Testcase::new(input.clone());
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

impl<C, CS, E, EM, F, I, OF, OT, S, ST, SC> Fuzzer<E, EM, I, S, ST>
    for StdFuzzer<C, CS, F, I, OF, OT, S, SC>
where
    CS: CorpusScheduler<I, S>,
    EM: EventManager<E, I, S, Self>,
    F: Feedback<I, S>,
    I: Input,
    S: HasExecutions + HasClientPerfMonitor,
    OF: Feedback<I, S>,
    ST: StagesTuple<E, EM, S, Self>,
{
    #[inline]
    fn maybe_report_monitor(
        state: &mut S,
        manager: &mut EM,
        last: Duration,
        monitor_timeout: Duration,
    ) -> Result<Duration, Error> {
        let cur = current_time();
        // default to 0 here to avoid crashes on clock skew
        if cur.checked_sub(last).unwrap_or_default() > monitor_timeout {
            // Default no introspection implmentation
            #[cfg(not(feature = "introspection"))]
            manager.fire(
                state,
                Event::UpdateMonitor {
                    executions: *state.executions(),
                    time: cur,
                    phantom: PhantomData,
                },
            )?;

            // If performance monitor are requested, fire the `UpdatePerfMonitor` event
            #[cfg(feature = "introspection")]
            {
                state
                    .introspection_monitor_mut()
                    .set_current_time(crate::bolts::cpu::read_time_counter());

                // Send the current monitor over to the manager. This `.clone` shouldn't be
                // costly as `ClientPerfMonitor` impls `Copy` since it only contains `u64`s
                manager.fire(
                    state,
                    Event::UpdatePerfMonitor {
                        executions: *state.executions(),
                        time: cur,
                        introspection_monitor: Box::new(state.introspection_monitor().clone()),
                        phantom: PhantomData,
                    },
                )?;
            }

            Ok(cur)
        } else {
            if cur.as_millis() % 1000 == 0 {}
            Ok(last)
        }
    }

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

impl<C, CS, F, I, OF, OT, S, SC> StdFuzzer<C, CS, F, I, OF, OT, S, SC>
where
    CS: CorpusScheduler<I, S>,
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

        start_timer!(state);
        let exit_kind = executor.run_target(self, state, event_mgr, input)?;
        mark_feature_time!(state, PerfFeature::TargetExecution);

        *state.executions_mut() += 1;

        start_timer!(state);
        executor.observers_mut().post_exec_all(state, input)?;
        mark_feature_time!(state, PerfFeature::PostExecObservers);

        Ok(exit_kind)
    }
}
