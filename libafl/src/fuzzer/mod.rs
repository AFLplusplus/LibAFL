//! The `Fuzzer` is the main struct for a fuzz campaign.

use alloc::{string::ToString, vec::Vec};
#[cfg(feature = "std")]
use core::hash::Hash;
use core::{fmt::Debug, time::Duration};

#[cfg(feature = "std")]
use fastbloom::BloomFilter;
use libafl_bolts::{current_time, tuples::MatchName};
use serde::{Serialize, de::DeserializeOwned};

#[cfg(feature = "introspection")]
use crate::monitors::stats::PerfFeature;
use crate::{
    Error, HasMetadata,
    corpus::{Corpus, CorpusId, HasCurrentCorpusId, HasTestcase, Testcase},
    events::{
        CanSerializeObserver, Event, EventConfig, EventFirer, EventReceiver, ProgressReporter,
        RecordSerializationTime, SendExiting,
    },
    executors::{Executor, ExitKind, HasObservers},
    feedbacks::Feedback,
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

/// Evaluates if an input is interesting using the feedback
pub trait ExecutionProcessor<EM, I, OT, S> {
    /// Check the outcome of the execution, find if it is worth for corpus or objectives
    fn check_results(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        input: &I,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<ExecuteInputResult, Error>;

    /// Process `ExecuteInputResult`. Add to corpus, solution or ignore
    fn process_execution(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        input: &I,
        exec_res: &ExecuteInputResult,
        observers: &OT,
    ) -> Result<Option<CorpusId>, Error>;

    /// serialize and send event via manager
    fn serialize_and_dispatch(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        input: &I,
        exec_res: &ExecuteInputResult,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<(), Error>;

    /// send event via manager
    fn dispatch_event(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        input: &I,
        exec_res: &ExecuteInputResult,
        obs_buf: Option<Vec<u8>>,
        exit_kind: &ExitKind,
    ) -> Result<(), Error>;

    /// Evaluate if a set of observation channels has an interesting state
    fn evaluate_execution(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        input: &I,
        observers: &OT,
        exit_kind: &ExitKind,
        send_events: bool,
    ) -> Result<(ExecuteInputResult, Option<CorpusId>), Error>;
}

/// Evaluates an input modifying the state of the fuzzer
pub trait EvaluatorObservers<E, EM, I, S> {
    /// Runs the input and triggers observers and feedback.
    /// if it is interesting, returns an (option) the index of the new
    /// [`Testcase`] in the [`Corpus`]
    fn evaluate_input_with_observers(
        &mut self,
        state: &mut S,
        executor: &mut E,
        manager: &mut EM,
        input: &I,
        send_events: bool,
    ) -> Result<(ExecuteInputResult, Option<CorpusId>), Error>;
}

/// Receives and event from event manager and then evaluates it
pub trait EventProcessor<E, EM, I, S> {
    /// Asks event manager to see if there's any event to evaluate
    /// If there is any, then evaluates it.
    /// After, run the post processing routines, for example, re-sending the events to the other  
    fn process_events(
        &mut self,
        state: &mut S,
        executor: &mut E,
        manager: &mut EM,
    ) -> Result<(), Error>;
}

/// Evaluate an input modifying the state of the fuzzer
pub trait Evaluator<E, EM, I, S> {
    /// Runs the input if it was (likely) not previously run and triggers observers and feedback and adds the input to the previously executed list
    /// if it is interesting, returns an (option) the index of the new [`Testcase`] in the corpus
    fn evaluate_filtered(
        &mut self,
        state: &mut S,
        executor: &mut E,
        manager: &mut EM,
        input: &I,
    ) -> Result<(ExecuteInputResult, Option<CorpusId>), Error>;

    /// Runs the input and triggers observers and feedback,
    /// returns if is interesting an (option) the index of the new [`Testcase`] in the corpus
    fn evaluate_input(
        &mut self,
        state: &mut S,
        executor: &mut E,
        manager: &mut EM,
        input: &I,
    ) -> Result<(ExecuteInputResult, Option<CorpusId>), Error>;

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
    ) -> Result<CorpusId, Error>;

    /// Adds the input to the corpus as a disabled input.
    /// Used during initial corpus loading.
    /// Disabled testcases are only used for splicing
    /// Returns the `index` of the new testcase in the corpus.
    /// Usually, you want to use [`Evaluator::evaluate_input`], unless you know what you are doing.
    fn add_disabled_input(&mut self, state: &mut S, input: I) -> Result<CorpusId, Error>;
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

impl<CS, EM, F, I, IF, OF, OT, S> ExecutionProcessor<EM, I, OT, S> for StdFuzzer<CS, F, IF, OF>
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
                            #[cfg(feature = "share_objectives")]
                            input: input.clone(),

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

impl<CS, E, EM, F, I, IF, OF, S> EvaluatorObservers<E, EM, I, S> for StdFuzzer<CS, F, IF, OF>
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

impl<CS, E, EM, F, I, IF, OF, S> Evaluator<E, EM, I, S> for StdFuzzer<CS, F, IF, OF>
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

impl<CS, E, EM, F, I, IF, OF, S> EventProcessor<E, EM, I, S> for StdFuzzer<CS, F, IF, OF>
where
    CS: Scheduler<I, S>,
    E: HasObservers + Executor<EM, I, S, Self>,
    E::Observers: DeserializeOwned + Serialize + ObserversTuple<I, S>,
    EM: EventReceiver<I, S>
        + RecordSerializationTime
        + CanSerializeObserver<E::Observers>
        + EventFirer<I, S>,
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
                        let start = current_time();
                        let observers: E::Observers =
                            postcard::from_bytes(observers_buf.as_ref().unwrap())?;
                        {
                            let dur = current_time() - start;
                            manager.set_deserialization_time(dur);
                        }
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
                    #[cfg(feature = "share_objectives")]
                    Event::Objective { ref input, .. } => {
                        let res = self.evaluate_input_with_observers(
                            state, executor, manager, input, false,
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

impl<CS, E, EM, F, I, IF, OF, S, ST> Fuzzer<E, EM, I, S, ST> for StdFuzzer<CS, F, IF, OF>
where
    CS: Scheduler<I, S>,
    E: HasObservers + Executor<EM, I, S, Self>,
    E::Observers: DeserializeOwned + Serialize + ObserversTuple<I, S>,
    EM: CanSerializeObserver<E::Observers> + EventFirer<I, S> + RecordSerializationTime,
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
    EM: ProgressReporter<S>,
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
        assert!(
            fuzzer
                .evaluate_input(&mut state, &mut executor, &mut manager, &input)
                .is_ok()
        );
        assert_eq!(1, *execution_count.borrow()); // evaluate_input does not add it to the filter

        assert!(
            fuzzer
                .evaluate_filtered(&mut state, &mut executor, &mut manager, &input)
                .is_ok()
        );
        assert_eq!(2, *execution_count.borrow()); // at to the filter

        assert!(
            fuzzer
                .evaluate_filtered(&mut state, &mut executor, &mut manager, &input)
                .is_ok()
        );
        assert_eq!(2, *execution_count.borrow()); // the harness is not called

        assert!(
            fuzzer
                .evaluate_input(&mut state, &mut executor, &mut manager, &input)
                .is_ok()
        );
        assert_eq!(3, *execution_count.borrow()); // evaluate_input ignores filters
    }
}
