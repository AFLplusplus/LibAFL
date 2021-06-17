//! The `Fuzzer` is the main struct for a fuzz campaign.

use crate::{
    bolts::current_time,
    corpus::{Corpus, CorpusScheduler, Testcase},
    events::{Event, EventFirer, EventManager},
    executors::{Executor, ExitKind, HasObservers},
    feedbacks::Feedback,
    inputs::Input,
    mark_feature_time,
    observers::ObserversTuple,
    stages::StagesTuple,
    start_timer,
    state::{HasClientPerfStats, HasCorpus, HasExecutions, HasSolutions},
    Error,
};

#[cfg(feature = "introspection")]
use crate::stats::PerfFeature;
#[cfg(feature = "introspection")]
use alloc::boxed::Box;

use alloc::string::ToString;
use core::{marker::PhantomData, time::Duration};

/// Send a stats update all 3 (or more) seconds
const STATS_TIMEOUT_DEFAULT: Duration = Duration::from_millis(3 * 1000);

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
        let stats_timeout = STATS_TIMEOUT_DEFAULT;
        loop {
            self.fuzz_one(stages, executor, state, manager)?;
            last = Self::maybe_report_stats(state, manager, last, stats_timeout)?;
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
        let stats_timeout = STATS_TIMEOUT_DEFAULT;

        for _ in 0..iters {
            ret = self.fuzz_one(stages, executor, state, manager)?;
            last = Self::maybe_report_stats(state, manager, last, stats_timeout)?;
        }

        // If we would assume the fuzzer loop will always exit after this, we could do this here:
        // manager.on_restart(state)?;
        // But as the state may grow to a few megabytes,
        // for now we won' and the user has to do it (unless we find a way to do this on `Drop`).

        Ok(ret)
    }

    /// Given the last time, if `stats_timeout` seconds passed, send off an info/stats/heartbeat message to the broker.
    /// Returns the new `last` time (so the old one, unless `stats_timeout` time has passed and stats have been sent)
    /// Will return an [`crate::Error`], if the stats could not be sent.
    fn maybe_report_stats(
        state: &mut S,
        manager: &mut EM,
        last: Duration,
        stats_timeout: Duration,
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
    OT: ObserversTuple<I, S>,
    S: HasCorpus<C, I> + HasSolutions<SC, I> + HasClientPerfStats + HasExecutions,
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

        start_timer!(state);
        let is_solution = self
            .objective_mut()
            .is_interesting(state, manager, &input, observers, &exit_kind)?;
        mark_feature_time!(state, PerfFeature::GetObjectivesInterestingAll);

        if is_solution {
            res = ExecuteInputResult::Solution;
        } else {
            #[cfg(not(feature = "introspection"))]
            let is_corpus = self
                .feedback_mut()
                .is_interesting(state, manager, &input, observers, &exit_kind)?;

            #[cfg(feature = "introspection")]
            let is_corpus = {
                // Init temporary feedback stats here. We can't use the typical pattern above
                // since we need a `mut self` for `feedbacks_mut`, so we can't also hand a
                // new `mut self` to `is_interesting_with_perf`. We use this stack
                // variable to get the stats and then update the feedbacks directly
                let mut feedback_stats = [0_u64; crate::stats::NUM_FEEDBACKS];
                let feedback_index = 0;
                let is_corpus = self.feedback_mut().is_interesting_with_perf(
                    state,
                    manager,
                    &input,
                    observers,
                    &exit_kind,
                    &mut feedback_stats,
                    feedback_index,
                )?;

                // Update the feedback stats
                state
                    .introspection_stats_mut()
                    .update_feedbacks(feedback_stats);

                // Return the total fitness
                is_corpus
            };

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
                    let observers_buf = manager.serialize_observers(observers)?;
                    manager.fire(
                        state,
                        Event::NewTestcase {
                            input,
                            observers_buf,
                            corpus_size: state.corpus().count(),
                            client_config: "TODO".into(),
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
    OT: ObserversTuple<I, S>,
    F: Feedback<I, S>,
    I: Input,
    OF: Feedback<I, S>,
    S: HasExecutions + HasCorpus<C, I> + HasSolutions<SC, I> + HasClientPerfStats,
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
    OT: ObserversTuple<I, S>,
    EM: EventManager<E, I, S, Self>,
    F: Feedback<I, S>,
    I: Input,
    OF: Feedback<I, S>,
    S: HasExecutions + HasCorpus<C, I> + HasSolutions<SC, I> + HasClientPerfStats,
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
        let _ = self.execute_input(state, executor, manager, &input)?;
        let observers = executor.observers();
        // Always consider this to be "interesting"

        // Not a solution
        self.objective_mut().discard_metadata(state, &input)?;

        // Add the input to the main corpus
        let mut testcase = Testcase::new(input.clone());
        self.feedback_mut().append_metadata(state, &mut testcase)?;
        let idx = state.corpus_mut().add(testcase)?;
        self.scheduler_mut().on_add(state, idx)?;

        let observers_buf = manager.serialize_observers(observers)?;
        manager.fire(
            state,
            Event::NewTestcase {
                input,
                observers_buf,
                corpus_size: state.corpus().count(),
                client_config: "TODO".into(),
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
    S: HasExecutions + HasClientPerfStats,
    OF: Feedback<I, S>,
    ST: StagesTuple<E, EM, S, Self>,
{
    #[inline]
    fn maybe_report_stats(
        state: &mut S,
        manager: &mut EM,
        last: Duration,
        stats_timeout: Duration,
    ) -> Result<Duration, Error> {
        let cur = current_time();
        // default to 0 here to avoid crashes on clock skew
        if cur.checked_sub(last).unwrap_or_default() > stats_timeout {
            // Default no introspection implmentation
            #[cfg(not(feature = "introspection"))]
            manager.fire(
                state,
                Event::UpdateStats {
                    executions: *state.executions(),
                    time: cur,
                    phantom: PhantomData,
                },
            )?;

            // If performance stats are requested, fire the `UpdatePerfStats` event
            #[cfg(feature = "introspection")]
            {
                state
                    .introspection_stats_mut()
                    .set_current_time(crate::bolts::cpu::read_time_counter());

                // Send the current stats over to the manager. This `.clone` shouldn't be
                // costly as `ClientPerfStats` impls `Copy` since it only contains `u64`s
                manager.fire(
                    state,
                    Event::UpdatePerfStats {
                        executions: *state.executions(),
                        time: cur,
                        introspection_stats: Box::new(*state.introspection_stats()),
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
        state.introspection_stats_mut().start_timer();

        // Get the next index from the scheduler
        let idx = self.scheduler.next(state)?;

        // Mark the elapsed time for the scheduler
        #[cfg(feature = "introspection")]
        state.introspection_stats_mut().mark_scheduler_time();

        // Mark the elapsed time for the scheduler
        #[cfg(feature = "introspection")]
        state.introspection_stats_mut().reset_stage_index();

        // Execute all stages
        stages.perform_all(self, executor, state, manager, idx)?;

        // Init timer for manager
        #[cfg(feature = "introspection")]
        state.introspection_stats_mut().start_timer();

        // Execute the manager
        manager.process(self, state, executor)?;

        // Mark the elapsed time for the manager
        #[cfg(feature = "introspection")]
        state.introspection_stats_mut().mark_manager_time();

        Ok(idx)
    }
}

impl<C, CS, F, I, OF, OT, S, SC> StdFuzzer<C, CS, F, I, OF, OT, S, SC>
where
    CS: CorpusScheduler<I, S>,
    F: Feedback<I, S>,
    I: Input,
    OF: Feedback<I, S>,
    S: HasExecutions + HasClientPerfStats,
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
