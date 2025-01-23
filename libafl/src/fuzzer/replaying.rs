//! Fuzzer instance that increases stability by executing the same input multiple times.

use alloc::{borrow::Cow, string::ToString, vec::Vec};
use core::{fmt::Debug, hash::Hash, marker::PhantomData};

use hashbrown::HashMap;
use libafl_bolts::{
    current_time, generic_hash_std,
    tuples::{Handle, MatchName, MatchNameRef},
};
use serde::Serialize;

#[cfg(feature = "std")]
use crate::fuzzer::BloomInputFilter;
#[cfg(feature = "introspection")]
use crate::monitors::PerfFeature;
use crate::{
    corpus::{Corpus, CorpusId, HasCurrentCorpusId, HasTestcase, Testcase},
    events::{
        CanSerializeObserver, Event, EventConfig, EventFirer, EventProcessor, ProgressReporter,
    },
    executors::{Executor, ExitKind, HasObservers},
    feedbacks::Feedback,
    fuzzer::{
        Evaluator, EvaluatorObservers, ExecuteInputResult, ExecutesInput, ExecutionProcessor,
        Fuzzer, HasFeedback, HasObjective, HasScheduler, InputFilter, NopInputFilter,
        STATS_TIMEOUT_DEFAULT,
    },
    inputs::Input,
    mark_feature_time,
    monitors::{AggregatorOps, UserStats, UserStatsValue},
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

/// A fuzzer instance for unstable targets that increases stability by executing the same input multiple times.
///
/// The input will be executed as often as necessary until the most frequent result appears
/// - at least `min_count_diff` times more often than any other result
/// - at least `min_factor_diff` times more often than any other result
/// - at most `max_trys` times
#[derive(Debug)]
pub struct ReplayingFuzzer<CS, F, O, IF, OF> {
    min_count_diff: usize,
    min_factor_diff: f64,
    max_trys: usize,
    handle: Handle<O>,
    scheduler: CS,
    feedback: F,
    objective: OF,
    input_filter: IF,
}

impl<CS, F, O, I, IF, OF, S> HasScheduler<I, S> for ReplayingFuzzer<CS, F, O, IF, OF>
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

impl<CS, F, O, IF, OF> HasFeedback for ReplayingFuzzer<CS, F, O, IF, OF> {
    type Feedback = F;

    fn feedback(&self) -> &Self::Feedback {
        &self.feedback
    }

    fn feedback_mut(&mut self) -> &mut Self::Feedback {
        &mut self.feedback
    }
}

impl<CS, F, O, IF, OF> HasObjective for ReplayingFuzzer<CS, F, O, IF, OF> {
    type Objective = OF;

    fn objective(&self) -> &OF {
        &self.objective
    }

    fn objective_mut(&mut self) -> &mut OF {
        &mut self.objective
    }
}

impl<CS, EM, F, O, I, IF, OF, OT, S> ExecutionProcessor<EM, I, OT, S>
    for ReplayingFuzzer<CS, F, O, IF, OF>
where
    CS: Scheduler<I, S>,
    EM: EventFirer<I, S> + CanSerializeObserver<OT>,
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

    /// Evaluate if a set of observation channels has an interesting state
    fn process_execution(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        input: &I,
        exec_res: &ExecuteInputResult,
        observers: &OT,
    ) -> Result<Option<CorpusId>, Error> {
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

    fn serialize_and_dispatch(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        input: I,
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
                        manager.serialize_observers(observers)?
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
        input: I,
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

    fn evaluate_execution(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        input: I,
        observers: &OT,
        exit_kind: &ExitKind,
        send_events: bool,
    ) -> Result<(ExecuteInputResult, Option<CorpusId>), Error> {
        let exec_res = self.check_results(state, manager, &input, observers, exit_kind)?;
        let corpus_id = self.process_execution(state, manager, &input, &exec_res, observers)?;
        if send_events {
            self.serialize_and_dispatch(state, manager, input, &exec_res, observers, exit_kind)?;
        }
        if exec_res != ExecuteInputResult::None {
            *state.last_found_time_mut() = current_time();
        }
        Ok((exec_res, corpus_id))
    }
}

impl<CS, E, EM, F, O, I, IF, OF, S> EvaluatorObservers<E, EM, I, S>
    for ReplayingFuzzer<CS, F, O, IF, OF>
where
    CS: Scheduler<I, S>,
    E: HasObservers + Executor<EM, I, S, Self>,
    E::Observers: MatchName + ObserversTuple<I, S> + Serialize,
    EM: EventFirer<I, S> + CanSerializeObserver<E::Observers>,
    F: Feedback<EM, I, E::Observers, S>,
    OF: Feedback<EM, I, E::Observers, S>,
    S: HasCorpus<I>
        + HasSolutions<I>
        + MaybeHasClientPerfMonitor
        + HasCurrentTestcase<I>
        + HasExecutions
        + HasLastFoundTime,
    I: Input,
    O: Hash,
{
    /// Process one input, adding to the respective corpora if needed and firing the right events
    #[inline]
    fn evaluate_input_with_observers(
        &mut self,
        state: &mut S,
        executor: &mut E,
        manager: &mut EM,
        input: I,
        send_events: bool,
    ) -> Result<(ExecuteInputResult, Option<CorpusId>), Error> {
        let exit_kind = self.execute_input(state, executor, manager, &input)?;
        let observers = executor.observers();

        self.scheduler.on_evaluation(state, &input, &*observers)?;

        self.evaluate_execution(state, manager, input, &*observers, &exit_kind, send_events)
    }
}

impl<CS, E, EM, F, O, I, IF, OF, S> Evaluator<E, EM, I, S> for ReplayingFuzzer<CS, F, O, IF, OF>
where
    CS: Scheduler<I, S>,
    E: HasObservers + Executor<EM, I, S, Self>,
    E::Observers: MatchName + ObserversTuple<I, S> + Serialize,
    EM: EventFirer<I, S> + CanSerializeObserver<E::Observers>,
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
    O: Hash,
{
    fn evaluate_filtered(
        &mut self,
        state: &mut S,
        executor: &mut E,
        manager: &mut EM,
        input: I,
    ) -> Result<(ExecuteInputResult, Option<CorpusId>), Error> {
        if self.input_filter.should_execute(&input) {
            self.evaluate_input(state, executor, manager, input)
        } else {
            Ok((ExecuteInputResult::None, None))
        }
    }

    /// Process one input, adding to the respective corpora if needed and firing the right events
    #[inline]
    fn evaluate_input_events(
        &mut self,
        state: &mut S,
        executor: &mut E,
        manager: &mut EM,
        input: I,
        send_events: bool,
    ) -> Result<(ExecuteInputResult, Option<CorpusId>), Error> {
        self.evaluate_input_with_observers(state, executor, manager, input, send_events)
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

    fn add_disabled_input(&mut self, state: &mut S, input: I) -> Result<CorpusId, Error> {
        let mut testcase = Testcase::from(input.clone());
        testcase.set_disabled(true);
        // Add the disabled input to the main corpus
        let id = state.corpus_mut().add_disabled(testcase)?;
        Ok(id)
    }
}

impl<CS, E, EM, F, O, I, IF, OF, S, ST> Fuzzer<E, EM, I, S, ST>
    for ReplayingFuzzer<CS, F, O, IF, OF>
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

impl<CS, F, O, IF, OF> ReplayingFuzzer<CS, F, O, IF, OF> {
    /// Create a new [`ReplayingFuzzer`] with standard behavior and the provided duplicate input execution filter.
    #[expect(clippy::too_many_arguments)]
    pub fn with_input_filter(
        min_count_diff: usize,
        min_factor_diff: f64,
        max_trys: usize,
        handle: Handle<O>,
        scheduler: CS,
        feedback: F,
        objective: OF,
        input_filter: IF,
    ) -> Self {
        Self {
            min_count_diff,
            min_factor_diff,
            max_trys,
            handle,
            scheduler,
            feedback,
            objective,
            input_filter,
        }
    }
}

impl<CS, F, O, OF> ReplayingFuzzer<CS, F, O, NopInputFilter, OF> {
    /// Create a new [`ReplayingFuzzer`] with standard behavior and no duplicate input execution filtering.
    pub fn new(
        min_count_diff: usize,
        min_factor_diff: f64,
        max_trys: usize,
        handle: Handle<O>,
        scheduler: CS,
        feedback: F,
        objective: OF,
    ) -> Self {
        Self::with_input_filter(
            min_count_diff,
            min_factor_diff,
            max_trys,
            handle,
            scheduler,
            feedback,
            objective,
            NopInputFilter,
        )
    }
}

#[cfg(feature = "std")] // hashing requires std
impl<CS, F, O, OF> ReplayingFuzzer<CS, F, O, BloomInputFilter, OF> {
    /// Create a new [`ReplayingFuzzer`], which, with a certain certainty, executes each input only once.
    ///
    /// This is achieved by hashing each input and using a bloom filter to differentiate inputs.
    ///
    /// Use this implementation if hashing each input is very fast compared to executing potential duplicate inputs.
    #[expect(clippy::too_many_arguments)]
    pub fn with_bloom_input_filter(
        min_count_diff: usize,
        min_factor_diff: f64,
        max_trys: usize,
        handle: Handle<O>,
        scheduler: CS,
        feedback: F,
        objective: OF,
        items_count: usize,
        fp_p: f64,
    ) -> Self {
        let input_filter = BloomInputFilter::new(items_count, fp_p);
        Self::with_input_filter(
            min_count_diff,
            min_factor_diff,
            max_trys,
            handle,
            scheduler,
            feedback,
            objective,
            input_filter,
        )
    }
}

impl<CS, E, EM, F, O, I, IF, OF, S> ExecutesInput<E, EM, I, S> for ReplayingFuzzer<CS, F, O, IF, OF>
where
    CS: Scheduler<I, S>,
    E: Executor<EM, I, S, Self> + HasObservers,
    E::Observers: ObserversTuple<I, S>,
    S: HasExecutions + HasCorpus<I> + MaybeHasClientPerfMonitor,
    O: Hash,
    EM: EventFirer<I, S>,
{
    /// Runs the input and triggers observers and feedback
    fn execute_input(
        &mut self,
        state: &mut S,
        executor: &mut E,
        event_mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, Error> {
        let mut results = HashMap::new();
        let mut inconsistent = 0;
        let (exit_kind, total_replayed) = loop {
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

            let observers = executor.observers();

            mark_feature_time!(state, PerfFeature::PostExecObservers);

            let observer = observers.get(&self.handle).expect("observer not found");
            let hash = generic_hash_std(observer);
            *results.entry((hash, exit_kind)).or_insert(0_usize) += 1;

            let total_replayed = results.values().sum::<usize>();

            let ((max_hash, max_exit_kind), max_count) =
                results.iter().max_by(|(_, a), (_, b)| a.cmp(b)).unwrap();

            let consistent_enough = results
                .values()
                .filter(|e| **e != *max_count)
                .all(|&count| {
                    let min_value_count = count + self.min_count_diff;
                    let min_value_factor =
                        f64::from(u32::try_from(*max_count).unwrap()) * self.min_factor_diff;
                    min_value_count <= *max_count
                        && min_value_factor <= f64::from(u32::try_from(*max_count).unwrap())
                });

            let latest_execution_is_dominant = hash == *max_hash && exit_kind == *max_exit_kind;

            if consistent_enough && latest_execution_is_dominant {
                break (exit_kind, total_replayed);
            } else if total_replayed >= self.max_trys {
                log::warn!(
                    "Replaying {} times did not lead to dominant result, using the latest observer value and most common exit_kind. Details: {results:?}",
                    total_replayed
                );
                inconsistent = 1;
                break (*max_exit_kind, total_replayed);
            }
        };

        event_mgr.fire(
            state,
            Event::UpdateUserStats {
                name: Cow::Borrowed("consistency-caused-replay-per-input"),
                value: UserStats::new(
                    UserStatsValue::Float(u32::try_from(total_replayed).unwrap().into()),
                    AggregatorOps::Avg,
                ),
                phantom: PhantomData,
            },
        )?;
        event_mgr.fire(
            state,
            Event::UpdateUserStats {
                name: Cow::Borrowed("uncaptured-inconsistent-rate"),
                value: UserStats::new(
                    UserStatsValue::Float(u32::try_from(inconsistent).unwrap().into()),
                    AggregatorOps::Avg,
                ),
                phantom: PhantomData,
            },
        )?;

        Ok(exit_kind)
    }
}

#[cfg(test)]
mod tests {
    use alloc::rc::Rc;
    use core::cell::RefCell;

    use libafl_bolts::{
        rands::StdRand,
        tuples::{tuple_list, Handled},
    };

    use crate::{
        corpus::InMemoryCorpus,
        events::NopEventManager,
        executors::{ExitKind, InProcessExecutor},
        fuzzer::ExecutesInput,
        inputs::ValueInput,
        observers::StdMapObserver,
        replaying::ReplayingFuzzer,
        schedulers::StdScheduler,
        state::StdState,
    };

    #[test]
    fn test_replaying() {
        let map = Rc::new(RefCell::new(vec![0_usize]));
        let return_value = Rc::new(RefCell::new(vec![0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
        let mut map_borrow = map.borrow_mut();
        let observer = unsafe {
            StdMapObserver::from_mut_ptr("observer", map_borrow.as_mut_ptr(), map_borrow.len())
        };
        drop(map_borrow);
        let mut fuzzer = ReplayingFuzzer::new(
            2,
            1.0,
            10,
            observer.handle(),
            StdScheduler::new(),
            tuple_list!(),
            tuple_list!(),
        );

        let mut state = StdState::new(
            StdRand::new(),
            InMemoryCorpus::new(),
            InMemoryCorpus::new(),
            &mut tuple_list!(),
            &mut tuple_list!(),
        )
        .unwrap();
        let mut event_mgr = NopEventManager::new();
        let execution_count = Rc::new(RefCell::new(0));
        let mut harness = |_i: &ValueInput<usize>| {
            let map_value = return_value.borrow_mut().remove(0);
            map.borrow_mut()[0] = map_value;
            *execution_count.borrow_mut() += 1;

            ExitKind::Ok
        };
        let mut executor = InProcessExecutor::new(
            &mut harness,
            tuple_list!(observer),
            &mut fuzzer,
            &mut state,
            &mut event_mgr,
        )
        .unwrap();

        let input: ValueInput<usize> = 42_usize.into();
        fuzzer
            .execute_input(&mut state, &mut executor, &mut event_mgr, &input)
            .unwrap();

        assert_eq!(*execution_count.borrow(), 4);
    }
}
