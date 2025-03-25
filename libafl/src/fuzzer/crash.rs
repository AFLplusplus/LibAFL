//! The `Fuzzer` is the main struct for a fuzz campaign.

use alloc::{string::ToString, vec::Vec};
use core::fmt::Debug;
#[cfg(feature = "std")]
use core::hash::Hash;

#[cfg(feature = "std")]
use fastbloom::BloomFilter;
use libafl_bolts::{current_time, tuples::MatchName};
use serde::{Serialize, de::DeserializeOwned};

#[cfg(feature = "introspection")]
use crate::monitors::stats::PerfFeature;
use crate::{
    Error, HasMetadata,
    corpus::{Corpus, CorpusId, HasCurrentCorpusId, HasTestcase, Testcase},
    events::{Event, EventConfig, EventFirer, EventReceiver, ProgressReporter, SendExiting},
    executors::{Executor, ExitKind, HasObservers},
    feedbacks::Feedback,
    fuzzer::{
        Evaluator, EvaluatorObservers, EventProcessor, ExecuteInputResult, ExecutionProcessor,
        Fuzzer, HasFeedback, HasObjective, HasScheduler, STATS_TIMEOUT_DEFAULT,
    },
    inputs::Input,
    mark_feature_time,
    observers::ObserversTuple,
    schedulers::Scheduler,
    stages::StagesTuple,
    start_timer,
    state::{
        HasCorpus, HasCurrentStageId, HasCurrentTestcase, HasExecutions, HasImported,
        HasLastFoundTime, HasLastReportTime, HasSolutions, MaybeHasClientPerfMonitor, Stoppable,
    },
};

/// The fuzzer that picks solutions too.
pub struct CrashExploreFuzzer<CS, CSC, F, IF, OF> {
    scheduler: CS,
    crash_scheduler: CSC,
    feedback: F,
    objective: OF,
    input_filter: IF,
    // Handles whether to share objective testcases among nodes
    share_objectives: bool,
}

impl<CS, CSC, F, I, IF, OF, S> HasScheduler<I, S> for CrashExploreFuzzer<CS, CSC, F, IF, OF>
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

impl<CS, CSC, F, IF, OF> HasFeedback for CrashExploreFuzzer<CS, CSC, F, IF, OF> {
    type Feedback = F;

    fn feedback(&self) -> &Self::Feedback {
        &self.feedback
    }

    fn feedback_mut(&mut self) -> &mut Self::Feedback {
        &mut self.feedback
    }
}

impl<CS, CSC, F, IF, OF> HasObjective for CrashExploreFuzzer<CS, CSC, F, IF, OF> {
    type Objective = OF;

    fn objective(&self) -> &OF {
        &self.objective
    }

    fn objective_mut(&mut self) -> &mut OF {
        &mut self.objective
    }

    fn set_share_objectives(&mut self, share_objectives: bool) {
        self.share_objectives = share_objectives;
    }

    fn share_objectives(&self) -> bool {
        self.share_objectives
    }
}

impl<CS, CSC, EM, F, I, IF, OF, OT, S> ExecutionProcessor<EM, I, OT, S>
    for CrashExploreFuzzer<CS, CSC, F, IF, OF>
where
    CS: Scheduler<I, S>,
    EM: EventFirer<I, S>,
    F: Feedback<EM, I, OT, S>,
    I: Input,
    OF: Feedback<EM, I, OT, S>,
    OT: ObserversTuple<I, S> + Serialize,
    S: HasCorpus<I>
        + MaybeHasClientPerfMonitor
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
    ) -> Result<ExecuteInputResult, Error> {
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

    /// Post process a testcase depending the testcase execution results
    /// returns corpus id if it put something into corpus (not solution)
    fn process_execution(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        input: &I,
        exec_res: &ExecuteInputResult,
        observers: &OT,
    ) -> Result<Option<CorpusId>, Error> {
        match exec_res {
            ExecuteInputResult::None => Ok(None),
            ExecuteInputResult::Corpus => {
                // Not a solution
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

    fn serialize_and_dispatch(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        input: &I,
        exec_res: &ExecuteInputResult,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        // Now send off the event
        let observers_buf = match exec_res {
            ExecuteInputResult::Corpus => {
                if manager.should_send() {
                    // TODO set None for fast targets
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
        exec_res: &ExecuteInputResult,
        observers_buf: Option<Vec<u8>>,
        exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        // Now send off the event

        match exec_res {
            ExecuteInputResult::Corpus => {
                if manager.should_send() {
                    manager.fire(
                        state,
                        Event::NewTestcase {
                            input: input.clone(),
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
                            input: self.share_objectives.then_some(input.clone()),
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

    fn evaluate_execution(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        input: &I,
        observers: &OT,
        exit_kind: &ExitKind,
        send_events: bool,
    ) -> Result<(ExecuteInputResult, Option<CorpusId>), Error> {
        let exec_res = self.check_results(state, manager, input, observers, exit_kind)?;
        let corpus_id = self.process_execution(state, manager, input, &exec_res, observers)?;
        if send_events {
            self.serialize_and_dispatch(state, manager, input, &exec_res, observers, exit_kind)?;
        }
        if exec_res != ExecuteInputResult::None {
            *state.last_found_time_mut() = current_time();
        }
        Ok((exec_res, corpus_id))
    }
}

impl<CS, CSC, E, EM, F, I, IF, OF, S> EvaluatorObservers<E, EM, I, S>
    for CrashExploreFuzzer<CS, CSC, F, IF, OF>
where
    CS: Scheduler<I, S>,
    E: HasObservers + Executor<EM, I, S, Self>,
    E::Observers: MatchName + ObserversTuple<I, S> + Serialize,
    EM: EventFirer<I, S>,
    F: Feedback<EM, I, E::Observers, S>,
    OF: Feedback<EM, I, E::Observers, S>,
    S: HasCorpus<I>
        + HasSolutions<I>
        + MaybeHasClientPerfMonitor
        + HasCurrentTestcase<I>
        + HasExecutions
        + HasLastFoundTime,
    I: Input,
{
    /// Process one input, adding to the respective corpora if needed and firing the right events
    #[inline]
    fn evaluate_input_with_observers(
        &mut self,
        state: &mut S,
        executor: &mut E,
        manager: &mut EM,
        input: &I,
        send_events: bool,
    ) -> Result<(ExecuteInputResult, Option<CorpusId>), Error> {
        let exit_kind = self.execute_input(state, executor, manager, input)?;
        let observers = executor.observers();

        self.scheduler.on_evaluation(state, input, &*observers)?;

        self.evaluate_execution(state, manager, input, &*observers, &exit_kind, send_events)
    }
}

trait InputFilter<I> {
    fn should_execute(&mut self, input: &I) -> bool;
}

/// A pseudo-filter that will execute each input.
#[derive(Debug)]
pub struct NopInputFilter;
impl<I> InputFilter<I> for NopInputFilter {
    #[inline]
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
    fn should_execute(&mut self, input: &I) -> bool {
        !self.bloom.insert(input)
    }
}

impl<CS, CSC, E, EM, F, I, IF, OF, S> Evaluator<E, EM, I, S>
    for CrashExploreFuzzer<CS, CSC, F, IF, OF>
where
    CS: Scheduler<I, S>,
    E: HasObservers + Executor<EM, I, S, Self>,
    E::Observers: MatchName + ObserversTuple<I, S> + Serialize,
    EM: EventFirer<I, S>,
    F: Feedback<EM, I, E::Observers, S>,
    OF: Feedback<EM, I, E::Observers, S>,
    S: HasCorpus<I>
        + HasSolutions<I>
        + MaybeHasClientPerfMonitor
        + HasCurrentTestcase<I>
        + HasLastFoundTime
        + HasExecutions,
    I: Input,
    IF: InputFilter<I>,
{
    fn evaluate_filtered(
        &mut self,
        state: &mut S,
        executor: &mut E,
        manager: &mut EM,
        input: &I,
    ) -> Result<(ExecuteInputResult, Option<CorpusId>), Error> {
        if self.input_filter.should_execute(input) {
            self.evaluate_input(state, executor, manager, input)
        } else {
            Ok((ExecuteInputResult::None, None))
        }
    }

    /// Process one input, adding to the respective corpora if needed and firing the right events
    #[inline]
    fn evaluate_input(
        &mut self,
        state: &mut S,
        executor: &mut E,
        manager: &mut EM,
        input: &I,
    ) -> Result<(ExecuteInputResult, Option<CorpusId>), Error> {
        self.evaluate_input_with_observers(state, executor, manager, input, true)
    }

    /// Adds an input, even if it's not considered `interesting` by any of the executors
    fn add_input(
        &mut self,
        state: &mut S,
        executor: &mut E,
        manager: &mut EM,
        input: I,
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
            // we don't care about solution id
            let id = state.solutions_mut().add(testcase)?;

            manager.fire(
                state,
                Event::Objective {
                    input: self.share_objectives.then_some(input.clone()),
                    objective_size: state.solutions().count(),
                    time: current_time(),
                },
            )?;

            // if it is a solution then early return
            return Ok(id);
        }

        // not a solution

        // several is_interesting implementations collect some data about the run, later used in
        // append_metadata; we *must* invoke is_interesting here to collect it
        #[cfg(not(feature = "introspection"))]
        let _is_corpus =
            self.feedback_mut()
                .is_interesting(state, manager, &input, &*observers, &exit_kind)?;

        #[cfg(feature = "introspection")]
        let _is_corpus = self.feedback_mut().is_interesting_introspection(
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
            Some(postcard::to_allocvec(&*observers)?)
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

    fn add_disabled_input(&mut self, state: &mut S, input: I) -> Result<CorpusId, Error> {
        let mut testcase = Testcase::from(input.clone());
        testcase.set_disabled(true);
        // Add the disabled input to the main corpus
        let id = state.corpus_mut().add_disabled(testcase)?;
        Ok(id)
    }
}

impl<CS, CSC, E, EM, F, I, IF, OF, S> EventProcessor<E, EM, I, S>
    for CrashExploreFuzzer<CS, CSC, F, IF, OF>
where
    CS: Scheduler<I, S>,
    E: HasObservers + Executor<EM, I, S, Self>,
    E::Observers: DeserializeOwned + Serialize + ObserversTuple<I, S>,
    EM: EventReceiver<I, S> + EventFirer<I, S>,
    F: Feedback<EM, I, E::Observers, S>,
    I: Input,
    OF: Feedback<EM, I, E::Observers, S>,
    S: HasCorpus<I>
        + HasSolutions<I>
        + HasExecutions
        + HasLastFoundTime
        + MaybeHasClientPerfMonitor
        + HasCurrentCorpusId
        + HasImported,
{
    fn process_events(
        &mut self,
        state: &mut S,
        executor: &mut E,
        manager: &mut EM,
    ) -> Result<(), Error> {
        // todo make this into a trait
        // Execute the manager
        while let Some((event, with_observers)) = manager.try_receive(state)? {
            // at this point event is either newtestcase or objectives
            let res = if with_observers {
                match event {
                    Event::NewTestcase {
                        ref input,
                        ref observers_buf,
                        exit_kind,
                        ..
                    } => {
                        let observers: E::Observers =
                            postcard::from_bytes(observers_buf.as_ref().unwrap())?;
                        let res = self.evaluate_execution(
                            state, manager, input, &observers, &exit_kind, false,
                        )?;
                        res.1
                    }
                    _ => None,
                }
            } else {
                match event {
                    Event::NewTestcase { ref input, .. } => {
                        let res = self.evaluate_input_with_observers(
                            state, executor, manager, input, false,
                        )?;
                        res.1
                    }
                    Event::Objective {
                        input: Some(ref unwrapped_input),
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

                // for centralize
                manager.on_interesting(state, event)?;
            } else {
                log::debug!("Received input was discarded");
            }
        }
        Ok(())
    }
}

impl<CS, CSC, E, EM, F, I, IF, OF, S, ST> Fuzzer<E, EM, I, S, ST>
    for CrashExploreFuzzer<CS, CSC, F, IF, OF>
where
    CS: Scheduler<I, S>,
    E: HasObservers + Executor<EM, I, S, Self>,
    E::Observers: DeserializeOwned + Serialize + ObserversTuple<I, S>,
    EM: EventFirer<I, S>,
    I: Input,
    F: Feedback<EM, I, E::Observers, S>,
    OF: Feedback<EM, I, E::Observers, S>,
    EM: ProgressReporter<S> + SendExiting + EventReceiver<I, S>,
    S: HasExecutions
        + HasMetadata
        + HasCorpus<I>
        + HasSolutions<I>
        + HasLastReportTime
        + HasLastFoundTime
        + HasImported
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
        state.introspection_stats_mut().start_timer();

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
        state.introspection_stats_mut().mark_scheduler_time();

        // Mark the elapsed time for the scheduler
        #[cfg(feature = "introspection")]
        state.introspection_stats_mut().reset_stage_index();

        // Execute all stages
        stages.perform_all(self, executor, state, manager)?;

        // Init timer for manager
        #[cfg(feature = "introspection")]
        state.introspection_stats_mut().start_timer();

        self.process_events(state, executor, manager)?;

        // Mark the elapsed time for the manager
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

impl<CS, CSC, F, IF, OF> CrashExploreFuzzer<CS, CSC, F, IF, OF> {
    /// Create a new [`StdFuzzer`] with standard behavior and the provided duplicate input execution filter.
    pub fn with_input_filter(
        scheduler: CS,
        crash_scheduler: CSC,
        feedback: F,
        objective: OF,
        input_filter: IF,
    ) -> Self {
        Self {
            scheduler,
            crash_scheduler,
            feedback,
            objective,
            input_filter,
            share_objectives: false,
        }
    }
}

impl<CS, CSC, F, OF> CrashExploreFuzzer<CS, CSC, F, NopInputFilter, OF> {
    /// Create a new [`StdFuzzer`] with standard behavior and no duplicate input execution filtering.
    pub fn new(scheduler: CS, crash_scheduler: CSC, feedback: F, objective: OF) -> Self {
        Self::with_input_filter(
            scheduler,
            crash_scheduler,
            feedback,
            objective,
            NopInputFilter,
        )
    }
}

#[cfg(feature = "std")] // hashing requires std
impl<CS, CSC, F, OF> CrashExploreFuzzer<CS, CSC, F, BloomInputFilter, OF> {
    /// Create a new [`StdFuzzer`], which, with a certain certainty, executes each input only once.
    ///
    /// This is achieved by hashing each input and using a bloom filter to differentiate inputs.
    ///
    /// Use this implementation if hashing each input is very fast compared to executing potential duplicate inputs.
    pub fn with_bloom_input_filter(
        scheduler: CS,
        crash_scheduler: CSC,
        feedback: F,
        objective: OF,
        items_count: usize,
        fp_p: f64,
    ) -> Self {
        let input_filter = BloomInputFilter::new(items_count, fp_p);
        Self::with_input_filter(
            scheduler,
            crash_scheduler,
            feedback,
            objective,
            input_filter,
        )
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

impl<CS, CSC, E, EM, F, I, IF, OF, S> ExecutesInput<E, EM, I, S>
    for CrashExploreFuzzer<CS, CSC, F, IF, OF>
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
