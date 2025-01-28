//! The `Fuzzer` is the main struct for a fuzz campaign.

use alloc::{string::ToString, vec::Vec};
use core::{fmt::Debug, time::Duration};
#[cfg(feature = "std")]
use std::hash::Hash;

#[cfg(feature = "std")]
use fastbloom::BloomFilter;
use libafl_bolts::{current_time, tuples::MatchName};

#[cfg(feature = "introspection")]
use crate::monitors::PerfFeature;
use crate::{
    corpus::{Corpus, CorpusId, HasCurrentCorpusId, HasTestcase, Testcase},
    events::{
        CanSerializeObserver, Event, EventConfig, EventFirer, EventProcessor, ProgressReporter,
    },
    executors::{Executor, ExitKind, HasObservers},
    feedbacks::Feedback,
    inputs::Input,
    mark_feature_time,
    observers::ObserversTuple,
    schedulers::Scheduler,
    stages::{HasCurrentStageId, StagesTuple},
    start_timer,
    state::{
        HasCorpus, HasCurrentTestcase, HasExecutions, HasLastFoundTime, HasLastReportTime,
        HasSolutions, MaybeHasClientPerfMonitor, Stoppable,
    },
    Error, HasMetadata,
};

/// Send a monitor update all 15 (or more) seconds
pub(crate) const STATS_TIMEOUT_DEFAULT: Duration = Duration::from_secs(15);

/// Holds a scheduler
pub trait HasScheduler<I, S> {
    /// The [`Scheduler`] for this fuzzer
    type Scheduler: Scheduler<I, S>;

    /// The scheduler
    fn scheduler(&self) -> &Self::Scheduler;

    /// The scheduler (mutable)
    fn scheduler_mut(&mut self) -> &mut Self::Scheduler;
}

/// Holds an feedback
pub trait HasFeedback {
    /// The feedback type
    type Feedback;

    /// The feedback
    fn feedback(&self) -> &Self::Feedback;

    /// The feedback (mutable)
    fn feedback_mut(&mut self) -> &mut Self::Feedback;
}

/// Holds an objective feedback
pub trait HasObjective {
    /// The type of the [`Feedback`] used to find objectives for this fuzzer
    type Objective;

    /// The objective feedback
    fn objective(&self) -> &Self::Objective;

    /// The objective feedback (mutable)
    fn objective_mut(&mut self) -> &mut Self::Objective;
}

pub trait HasInputFilter<I> {
    /// The type of the [`InputFilter`] attached to this fuzzer
    type InputFilter;

    /// The input filter
    fn input_filter(&self) -> &Self::InputFilter;

    /// The input filter (mutable)
    fn input_filter_mut(&mut self) -> &mut Slef::InputFilter;
}

/// The main fuzzer trait.
pub trait Fuzzer<E, EM, I, S, ST> {
    /// Fuzz for a single iteration.
    /// Returns the index of the last fuzzed corpus item.
    /// (Note: An iteration represents a complete run of every stage.
    /// Therefore, it does not mean that the harness is executed for once,
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
    ) -> Result<CorpusId, Error>;

    /// Fuzz forever (or until stopped)
    fn fuzz_loop(
        &mut self,
        stages: &mut ST,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<(), Error>;

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
    ) -> Result<CorpusId, Error>;
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
pub struct StdFuzzer<CS, F, IF, OF> {
    scheduler: CS,
    feedback: F,
    objective: OF,
    input_filter: IF,
}

impl<CS, F, I, IF, OF, S> HasScheduler<I, S> for StdFuzzer<CS, F, IF, OF>
where
    CS: Scheduler<I, S>,
{
    type Scheduler = CS;

    fn scheduler(&self) -> &CS {
        &self.scheduler
    }

    fn scheduler_mut(&mut self) -> &mut CS {
        &mut self.scheduler
    }
}

impl<CS, F, IF, OF> HasFeedback for StdFuzzer<CS, F, IF, OF> {
    type Feedback = F;

    fn feedback(&self) -> &Self::Feedback {
        &self.feedback
    }

    fn feedback_mut(&mut self) -> &mut Self::Feedback {
        &mut self.feedback
    }
}

impl<CS, F, IF, OF> HasObjective for StdFuzzer<CS, F, IF, OF> {
    type Objective = OF;

    fn objective(&self) -> &OF {
        &self.objective
    }

    fn objective_mut(&mut self) -> &mut OF {
        &mut self.objective
    }
}

pub fn check_results<EM, I, OT, S, Z>(
    fuzzer: &mut Z,
    state: &mut S,
    manager: &mut EM,
    input: &I,
    observers: &OT,
    exit_kind: &ExitKind,
) -> Result<ExecuteInputResult, Error>
where
    Z: HasObjective + HasFeedback,
    Z::Objective: Feedback<EM, I, OT, S>,
    Z::Feedback: Feedback<EM, I, OT, S>,
{
    let mut res = ExecuteInputResult::None;

    #[cfg(not(feature = "introspection"))]
    let is_solution = fuzzer
        .objective_mut()
        .is_interesting(state, manager, input, observers, exit_kind)?;

    #[cfg(feature = "introspection")]
    let is_solution = fuzzer
        .objective_mut()
        .is_interesting_introspection(state, manager, input, observers, exit_kind)?;

    if is_solution {
        res = ExecuteInputResult::Solution;
    } else {
        #[cfg(not(feature = "introspection"))]
        let corpus_worthy = fuzzer
            .feedback_mut()
            .is_interesting(state, manager, input, observers, exit_kind)?;

        #[cfg(feature = "introspection")]
        let corpus_worthy = fuzzer
            .feedback_mut()
            .is_interesting_introspection(state, manager, input, observers, exit_kind)?;

        if corpus_worthy {
            res = ExecuteInputResult::Corpus;
        }
    }
    Ok(res)
}

/// Evaluate if a set of observation channels has an interesting state
pub fn process_execution<EM, I, OT, S, Z>(
    fuzzer: &mut Z,
    state: &mut S,
    manager: &mut EM,
    input: &I,
    exec_res: &ExecuteInputResult,
    observers: &OT,
) -> Result<Option<CorpusId>, Error>
where
    S: HasCorpus<I> + HasCurrentTestcase<I> + HasSolutions<I>,
    I: Input,
    Z: HasObjective + HasFeedback + HasScheduler<I, S>,
    Z::Objective: Feedback<EM, I, OT, S>,
    Z::Feedback: Feedback<EM, I, OT, S>,
{
    match exec_res {
        ExecuteInputResult::None => {
            fuzzer.feedback_mut().discard_metadata(state, input)?;
            fuzzer.objective_mut().discard_metadata(state, input)?;
            Ok(None)
        }
        ExecuteInputResult::Corpus => {
            // Not a solution
            fuzzer.objective_mut().discard_metadata(state, input)?;

            // Add the input to the main corpus
            let mut testcase = Testcase::from(input.clone());
            #[cfg(feature = "track_hit_feedbacks")]
            fuzzer
                .feedback_mut()
                .append_hit_feedbacks(testcase.hit_feedbacks_mut())?;
            fuzzer
                .feedback_mut()
                .append_metadata(state, manager, observers, &mut testcase)?;
            let id = state.corpus_mut().add(testcase)?;
            fuzzer.scheduler_mut().on_add(state, id)?;

            Ok(Some(id))
        }
        ExecuteInputResult::Solution => {
            // Not interesting
            fuzzer.feedback_mut().discard_metadata(state, input)?;

            // The input is a solution, add it to the respective corpus
            let mut testcase = Testcase::from(input.clone());
            testcase.set_parent_id_optional(*state.corpus().current());
            if let Ok(mut tc) = state.current_testcase_mut() {
                tc.found_objective();
            }
            #[cfg(feature = "track_hit_feedbacks")]
            fuzzer
                .objective_mut()
                .append_hit_feedbacks(testcase.hit_objectives_mut())?;
            fuzzer
                .objective_mut()
                .append_metadata(state, manager, observers, &mut testcase)?;
            state.solutions_mut().add(testcase)?;

            Ok(None)
        }
    }
}

pub fn serialize_and_dispatch<EM, I, OT, S>(
    state: &mut S,
    manager: &mut EM,
    input: I,
    exec_res: &ExecuteInputResult,
    observers: &OT,
    exit_kind: &ExitKind,
) -> Result<(), Error>
where
    EM: EventFirer<I, S> + CanSerializeObserver<OT>,
    S: HasCorpus<I> + HasSolutions<I>,
{
    // Now send off the event
    let observers_buf = match exec_res {
        ExecuteInputResult::Corpus => {
            if manager.should_send() {
                // TODO set None for fast targets
                if manager.configuration() == EventConfig::AlwaysUnique {
                    None
                } else {
                    manager.serialize_observers(observers)?
                }
            } else {
                None
            }
        }
        _ => None,
    };

    dispatch_event(state, manager, input, exec_res, observers_buf, exit_kind)?;
    Ok(())
}

pub fn dispatch_event<EM, I, S>(
    state: &mut S,
    manager: &mut EM,
    input: I,
    exec_res: &ExecuteInputResult,
    observers_buf: Option<Vec<u8>>,
    exit_kind: &ExitKind,
) -> Result<(), Error>
where
    EM: EventFirer<I, S>,
    S: HasCorpus<I> + HasSolutions<I>,
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
                        #[cfg(feature = "share_objectives")]
                        input,

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

pub fn evaluate_execution<EM, I, OT, S, Z>(
    fuzzer: &mut Z,
    state: &mut S,
    manager: &mut EM,
    input: I,
    observers: &OT,
    exit_kind: &ExitKind,
    send_events: bool,
) -> Result<(ExecuteInputResult, Option<CorpusId>), Error>
where
    EM: EventFirer<I, S> + CanSerializeObserver<OT>,
    I: Input,
    S: HasCorpus<I> + HasCurrentTestcase<I> + HasSolutions<I> + HasLastFoundTime,
    Z: HasObjective + HasFeedback + HasScheduler<I, S>,
    Z::Objective: Feedback<EM, I, OT, S>,
    Z::Feedback: Feedback<EM, I, OT, S>,
{
    let exec_res = check_results(fuzzer, state, manager, &input, observers, exit_kind)?;
    let corpus_id = process_execution(fuzzer, state, manager, &input, &exec_res, observers)?;
    if send_events {
        serialize_and_dispatch(state, manager, input, &exec_res, observers, exit_kind)?;
    }
    if exec_res != ExecuteInputResult::None {
        *state.last_found_time_mut() = current_time();
    }
    Ok((exec_res, corpus_id))
}

/// Process one input, adding to the respective corpora if needed and firing the right events
#[inline]
pub fn evaluate_input_with_observers<E, EM, I, S, Z>(
    fuzzer: &mut Z,
    state: &mut S,
    executor: &mut E,
    manager: &mut EM,
    input: I,
    send_events: bool,
) -> Result<(ExecuteInputResult, Option<CorpusId>), Error>
where
    E: HasObservers,
    E::Observers: MatchName,
    EM: EventFirer<I, S> + CanSerializeObserver<E::Observers>,
    I: Input,
    S: HasCorpus<I> + HasCurrentTestcase<I> + HasSolutions<I> + HasLastFoundTime,
    Z: HasObjective + HasFeedback + HasScheduler<I, S> + ExecutesInput<E, EM, I, S>,
    Z::Objective: Feedback<EM, I, E::Observers, S>,
    Z::Feedback: Feedback<EM, I, E::Observers, S>,
{
    let exit_kind = fuzzer.execute_input(state, executor, manager, &input)?;
    let observers = executor.observers();

    fuzzer
        .scheduler_mut()
        .on_evaluation(state, &input, &*observers)?;

    evaluate_execution(
        fuzzer,
        state,
        manager,
        input,
        &*observers,
        &exit_kind,
        send_events,
    )
}

pub trait InputFilter<I> {
    fn should_execute(&mut self, input: &I) -> bool;
}

/// A pseudo-filter that will execute each input.
#[derive(Debug)]
pub struct NopInputFilter;
impl<I> InputFilter<I> for NopInputFilter {
    #[inline]
    #[must_use]
    fn should_execute(&mut self, _input: &I) -> bool {
        true
    }
}

/// A filter that probabilistically prevents duplicate execution of the same input based on a bloom filter.
#[cfg(feature = "std")]
#[derive(Debug)]
pub struct BloomInputFilter {
    bloom: BloomFilter,
}

#[cfg(feature = "std")]
impl BloomInputFilter {
    #[must_use]
    fn new(items_count: usize, fp_p: f64) -> Self {
        let bloom = BloomFilter::with_false_pos(fp_p).expected_items(items_count);
        Self { bloom }
    }
}

#[cfg(feature = "std")]
impl<I: Hash> InputFilter<I> for BloomInputFilter {
    #[inline]
    #[must_use]
    fn should_execute(&mut self, input: &I) -> bool {
        !self.bloom.insert(input)
    }
}

pub fn evaluate_filtered<E, EM, I, S, Z>(
    fuzzer: &mut Z,
    state: &mut S,
    executor: &mut E,
    manager: &mut EM,
    input: I,
) -> Result<(ExecuteInputResult, Option<CorpusId>), Error>
where
    E: HasObservers,
    E::Observers: MatchName,
    EM: EventFirer<I, S> + CanSerializeObserver<E::Observers>,
    I: Input,
    S: HasCorpus<I> + HasCurrentTestcase<I> + HasSolutions<I> + HasLastFoundTime,
    Z: HasObjective
        + HasFeedback
        + HasScheduler<I, S>
        + ExecutesInput<E, EM, I, S>
        + HasInputFilter<I>,
    Z::Objective: Feedback<EM, I, E::Observers, S>,
    Z::Feedback: Feedback<EM, I, E::Observers, S>,
    Z::InputFilter: InputFilter<I>,
{
    if fuzzer.input_filter_mut().should_execute(&input) {
        evaluate_input_with_observers(fuzzer, state, executor, manager, input, true)
    } else {
        Ok((ExecuteInputResult::None, None))
    }
}

/// Adds an input, even if it's not considered `interesting` by any of the executors
pub fn add_input<E, EM, I, S, Z>(
    fuzzer: &mut Z,
    state: &mut S,
    executor: &mut E,
    manager: &mut EM,
    input: I,
) -> Result<CorpusId, Error>
where
    E: HasObservers,
    EM: EventFirer<I, S> + CanSerializeObserver<E::Observers>,
    I: Clone,
    S: HasLastFoundTime + HasSolutions<I> + HasCorpus<I>,
    Z: ExecutesInput<E, EM, I, S> + HasObjective + HasFeedback + HasScheduler<I, S>,
    Z::Objective: Feedback<EM, I, E::Observers, S>,
    Z::Feedback: Feedback<EM, I, E::Observers, S>,
{
    *state.last_found_time_mut() = current_time();

    let exit_kind = fuzzer.execute_input(state, executor, manager, &input)?;
    let observers = executor.observers();
    // Always consider this to be "interesting"
    let mut testcase = Testcase::from(input.clone());

    // Maybe a solution
    #[cfg(not(feature = "introspection"))]
    let is_solution: bool =
        fuzzer
            .objective_mut()
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
        fuzzer
            .objective_mut()
            .append_hit_feedbacks(testcase.hit_objectives_mut())?;
        fuzzer
            .objective_mut()
            .append_metadata(state, manager, &*observers, &mut testcase)?;
        let id = state.solutions_mut().add(testcase)?;

        manager.fire(
            state,
            Event::Objective {
                #[cfg(feature = "share_objectives")]
                input,

                objective_size: state.solutions().count(),
                time: current_time(),
            },
        )?;
        return Ok(id);
    }

    // Not a solution
    fuzzer.objective_mut().discard_metadata(state, &input)?;

    // several is_interesting implementations collect some data about the run, later used in
    // append_metadata; we *must* invoke is_interesting here to collect it
    #[cfg(not(feature = "introspection"))]
    let _corpus_worthy =
        fuzzer
            .feedback_mut()
            .is_interesting(state, manager, &input, &*observers, &exit_kind)?;

    #[cfg(feature = "introspection")]
    let _corpus_worthy = fuzzer.feedback_mut().is_interesting_introspection(
        state,
        manager,
        &input,
        &*observers,
        &exit_kind,
    )?;

    #[cfg(feature = "track_hit_feedbacks")]
    fuzzer
        .feedback_mut()
        .append_hit_feedbacks(testcase.hit_feedbacks_mut())?;
    // Add the input to the main corpus
    fuzzer
        .feedback_mut()
        .append_metadata(state, manager, &*observers, &mut testcase)?;
    let id = state.corpus_mut().add(testcase)?;
    fuzzer.scheduler_mut().on_add(state, id)?;

    let observers_buf = if manager.configuration() == EventConfig::AlwaysUnique {
        None
    } else {
        manager.serialize_observers(&*observers)?
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

pub fn add_disabled_input<I, S>(state: &mut S, input: I) -> Result<CorpusId, Error>
where
    S: HasCorpus<I>,
    I: Clone,
{
    let mut testcase = Testcase::from(input.clone());
    testcase.set_disabled(true);
    // Add the disabled input to the main corpus
    let id = state.corpus_mut().add_disabled(testcase)?;
    Ok(id)
}

impl<CS, E, EM, F, I, IF, OF, S, ST> Fuzzer<E, EM, I, S, ST> for StdFuzzer<CS, F, IF, OF>
where
    CS: Scheduler<I, S>,
    EM: ProgressReporter<S> + EventProcessor<E, S, Self>,
    S: HasExecutions
        + HasMetadata
        + HasCorpus<I>
        + HasLastReportTime
        + HasTestcase<I>
        + HasCurrentCorpusId
        + HasCurrentStageId
        + Stoppable
        + MaybeHasClientPerfMonitor,
    ST: StagesTuple<E, EM, S, Self>,
{
    fn fuzz_one(
        &mut self,
        stages: &mut ST,
        executor: &mut E,
        state: &mut S,
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

    fn fuzz_loop(
        &mut self,
        stages: &mut ST,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<(), Error> {
        let monitor_timeout = STATS_TIMEOUT_DEFAULT;
        loop {
            manager.maybe_report_progress(state, monitor_timeout)?;

            self.fuzz_one(stages, executor, state, manager)?;
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

        // If we assumed the fuzzer loop will always exit after this, we could do this here:
        // manager.on_restart(state)?;
        // But as the state may grow to a few megabytes,
        // for now we won't, and the user has to do it (unless we find a way to do this on `Drop`).

        Ok(ret.unwrap())
    }
}

impl<CS, F, IF, OF> StdFuzzer<CS, F, IF, OF> {
    /// Create a new [`StdFuzzer`] with standard behavior and the provided duplicate input execution filter.
    pub fn with_input_filter(scheduler: CS, feedback: F, objective: OF, input_filter: IF) -> Self {
        Self {
            scheduler,
            feedback,
            objective,
            input_filter,
        }
    }
}

impl<CS, F, OF> StdFuzzer<CS, F, NopInputFilter, OF> {
    /// Create a new [`StdFuzzer`] with standard behavior and no duplicate input execution filtering.
    pub fn new(scheduler: CS, feedback: F, objective: OF) -> Self {
        Self::with_input_filter(scheduler, feedback, objective, NopInputFilter)
    }
}

#[cfg(feature = "std")] // hashing requires std
impl<CS, F, OF> StdFuzzer<CS, F, BloomInputFilter, OF> {
    /// Create a new [`StdFuzzer`], which, with a certain certainty, executes each input only once.
    ///
    /// This is achieved by hashing each input and using a bloom filter to differentiate inputs.
    ///
    /// Use this implementation if hashing each input is very fast compared to executing potential duplicate inputs.
    pub fn with_bloom_input_filter(
        scheduler: CS,
        feedback: F,
        objective: OF,
        items_count: usize,
        fp_p: f64,
    ) -> Self {
        let input_filter = BloomInputFilter::new(items_count, fp_p);
        Self::with_input_filter(scheduler, feedback, objective, input_filter)
    }
}

impl<CS, F, I, IF, OF> HasInputFilter<I> for StdFuzzer<CS, F, IF, OF> {
    type InputFilter = IF;

    fn input_filter(&self) -> &Self::InputFilter {
        &self.input_filter
    }

    fn input_filter_mut(&mut self) -> &mut Slef::InputFilter {
        &mut self.input_filter
    }
}

/// Structs with this trait will execute an input
pub trait ExecutesInput<E, EM, I, S> {
    /// Runs the input and triggers observers and feedback
    fn execute_input(
        &mut self,
        state: &mut S,
        executor: &mut E,
        event_mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, Error>;
}

impl<CS, E, EM, F, I, IF, OF, S> ExecutesInput<E, EM, I, S> for StdFuzzer<CS, F, IF, OF>
where
    CS: Scheduler<I, S>,
    E: Executor<EM, I, S, Self> + HasObservers,
    E::Observers: ObserversTuple<I, S>,
    S: HasExecutions + HasCorpus<I> + MaybeHasClientPerfMonitor,
{
    /// Runs the input and triggers observers and feedback
    fn execute_input(
        &mut self,
        state: &mut S,
        executor: &mut E,
        event_mgr: &mut EM,
        input: &I,
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
pub struct NopFuzzer {}

impl NopFuzzer {
    /// Creates a new [`NopFuzzer`]
    #[must_use]
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for NopFuzzer {
    fn default() -> Self {
        Self::new()
    }
}

impl<E, EM, I, S, ST> Fuzzer<E, EM, I, S, ST> for NopFuzzer
where
    EM: ProgressReporter<S> + EventProcessor<E, S, Self>,
    ST: StagesTuple<E, EM, S, Self>,
    S: HasMetadata + HasExecutions + HasLastReportTime + HasCurrentStageId,
{
    fn fuzz_one(
        &mut self,
        _stages: &mut ST,
        _executor: &mut E,
        _state: &mut S,
        _manager: &mut EM,
    ) -> Result<CorpusId, Error> {
        unimplemented!("NopFuzzer cannot fuzz");
    }

    fn fuzz_loop(
        &mut self,
        _stages: &mut ST,
        _executor: &mut E,
        _state: &mut S,
        _manager: &mut EM,
    ) -> Result<(), Error> {
        unimplemented!("NopFuzzer cannot fuzz");
    }

    fn fuzz_loop_for(
        &mut self,
        _stages: &mut ST,
        _executor: &mut E,
        _state: &mut S,
        _manager: &mut EM,
        _iters: u64,
    ) -> Result<CorpusId, Error> {
        unimplemented!("NopFuzzer cannot fuzz");
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use core::cell::RefCell;

    use libafl_bolts::rands::StdRand;

    use super::{Evaluator, StdFuzzer};
    use crate::{
        corpus::InMemoryCorpus,
        events::NopEventManager,
        executors::{ExitKind, InProcessExecutor},
        inputs::BytesInput,
        schedulers::StdScheduler,
        state::StdState,
    };

    #[test]
    fn filtered_execution() {
        let execution_count = RefCell::new(0);
        let scheduler = StdScheduler::new();
        let mut fuzzer = StdFuzzer::with_bloom_input_filter(scheduler, (), (), 100, 1e-4);
        let mut state = StdState::new(
            StdRand::new(),
            InMemoryCorpus::new(),
            InMemoryCorpus::new(),
            &mut (),
            &mut (),
        )
        .unwrap();
        let mut manager = NopEventManager::new();
        let mut harness = |_input: &BytesInput| {
            *execution_count.borrow_mut() += 1;
            ExitKind::Ok
        };
        let mut executor =
            InProcessExecutor::new(&mut harness, (), &mut fuzzer, &mut state, &mut manager)
                .unwrap();
        let input = BytesInput::new(vec![1, 2, 3]);
        assert!(fuzzer
            .evaluate_input(&mut state, &mut executor, &mut manager, input.clone())
            .is_ok());
        assert_eq!(1, *execution_count.borrow()); // evaluate_input does not add it to the filter

        assert!(fuzzer
            .evaluate_filtered(&mut state, &mut executor, &mut manager, input.clone())
            .is_ok());
        assert_eq!(2, *execution_count.borrow()); // at to the filter

        assert!(fuzzer
            .evaluate_filtered(&mut state, &mut executor, &mut manager, input.clone())
            .is_ok());
        assert_eq!(2, *execution_count.borrow()); // the harness is not called

        assert!(fuzzer
            .evaluate_input(&mut state, &mut executor, &mut manager, input.clone())
            .is_ok());
        assert_eq!(3, *execution_count.borrow()); // evaluate_input ignores filters
    }
}
