//| The [`MutationalStage`] is the default stage used during fuzzing.
//! For the current input, it will perform a range of random mutations, and then run them in the executor.

use alloc::rc::Rc;
use core::{
    cell::{Cell, RefCell},
    fmt::Debug,
};

use libafl_bolts::rands::Rand;
use serde::Serialize;

use super::{PushStage, PushStageHelper, PushStageSharedState};
#[cfg(feature = "introspection")]
use crate::monitors::stats::PerfFeature;
use crate::{
    Error, ExecutionProcessor, HasMetadata, HasScheduler,
    corpus::{Corpus, CorpusId},
    events::{EventFirer, ProgressReporter},
    executors::ExitKind,
    fuzzer::STATS_TIMEOUT_DEFAULT,
    inputs::Input,
    mark_feature_time,
    mutators::Mutator,
    nonzero,
    observers::ObserversTuple,
    schedulers::Scheduler,
    start_timer,
    state::{HasCorpus, HasExecutions, HasLastReportTime, HasRand, MaybeHasClientPerfMonitor},
};

/// The default maximum number of mutations to perform per input.
pub const DEFAULT_MUTATIONAL_MAX_ITERATIONS: usize = 128;

/// A Mutational push stage is the stage in a fuzzing run that mutates inputs.
///
/// Mutational push stages will usually have a range of mutations that are
/// being applied to the input one by one, between executions.
/// The push version, in contrast to the normal stage, will return each testcase, instead of executing it.
///
/// Default value, how many iterations each stage gets, as an upper bound.
/// It may randomly continue earlier.
///
/// The default mutational push stage
#[derive(Debug, Clone)]
pub struct StdMutationalPushStage<EM, M, I, OT, S, Z>
where
    S: HasCorpus<I>,
    I: Clone + Debug,
{
    current_corpus_id: Option<CorpusId>,
    testcases_to_do: usize,
    testcases_done: usize,

    mutator: M,

    psh: PushStageHelper<EM, I, OT, S, Z>,
}

impl<EM, M, I, OT, S, Z> StdMutationalPushStage<EM, M, I, OT, S, Z>
where
    S: HasCorpus<I> + HasRand,
    I: Clone + Debug,
{
    /// Gets the number of iterations as a random number
    #[expect(clippy::unused_self, clippy::unnecessary_wraps)] // TODO: we should put this function into a trait later
    fn iterations(&self, state: &mut S, _corpus_id: CorpusId) -> Result<usize, Error> {
        Ok(1 + state
            .rand_mut()
            .below(nonzero!(DEFAULT_MUTATIONAL_MAX_ITERATIONS)))
    }

    /// Sets the current corpus index
    pub fn set_current_corpus_id(&mut self, current_corpus_id: CorpusId) {
        self.current_corpus_id = Some(current_corpus_id);
    }
}

impl<EM, M, I, OT, S, Z> PushStage<EM, I, OT, S, Z> for StdMutationalPushStage<EM, M, I, OT, S, Z>
where
    EM: EventFirer<I, S>,
    Z: HasScheduler<I, S> + ExecutionProcessor<EM, I, OT, S>,
    S: HasCorpus<I> + HasRand + MaybeHasClientPerfMonitor,
    M: Mutator<I, S>,
    OT: ObserversTuple<I, S> + Serialize,
    I: Input + Clone,
{
    #[inline]
    fn push_stage_helper(&self) -> &PushStageHelper<EM, I, OT, S, Z> {
        &self.psh
    }

    #[inline]
    fn push_stage_helper_mut(&mut self) -> &mut PushStageHelper<EM, I, OT, S, Z> {
        &mut self.psh
    }

    /// Creates a new default mutational stage
    fn init(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        _event_mgr: &mut EM,
        _observers: &mut OT,
    ) -> Result<(), Error> {
        // Find a testcase to work on, unless someone already set it
        self.current_corpus_id = Some(if let Some(corpus_id) = self.current_corpus_id {
            corpus_id
        } else {
            fuzzer.scheduler_mut().next(state)?
        });

        self.testcases_to_do = self.iterations(state, self.current_corpus_id.unwrap())?;
        self.testcases_done = 0;
        Ok(())
    }

    fn pre_exec(
        &mut self,
        _fuzzer: &mut Z,
        state: &mut S,
        _event_mgr: &mut EM,
        _observers: &mut OT,
    ) -> Option<Result<I, Error>> {
        if self.testcases_done >= self.testcases_to_do {
            // finished with this cicle.
            return None;
        }

        start_timer!(state);

        let input = state
            .corpus_mut()
            .cloned_input_for_id(self.current_corpus_id.unwrap());
        let mut input = match input {
            Err(e) => return Some(Err(e)),
            Ok(input) => input,
        };

        mark_feature_time!(state, PerfFeature::GetInputFromCorpus);

        start_timer!(state);
        self.mutator.mutate(state, &mut input).unwrap();
        mark_feature_time!(state, PerfFeature::Mutate);

        self.push_stage_helper_mut()
            .current_input
            .replace(input.clone()); // TODO: Get rid of this

        Some(Ok(input))
    }

    fn post_exec(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        event_mgr: &mut EM,
        observers: &mut OT,
        last_input: I,
        exit_kind: ExitKind,
    ) -> Result<(), Error> {
        // todo: is_interesting, etc.

        fuzzer.evaluate_execution(state, event_mgr, &last_input, observers, &exit_kind, true)?;

        start_timer!(state);
        self.mutator.post_exec(state, self.current_corpus_id)?;
        mark_feature_time!(state, PerfFeature::MutatePostExec);
        self.testcases_done += 1;

        Ok(())
    }

    #[inline]
    fn deinit(
        &mut self,
        _fuzzer: &mut Z,
        _state: &mut S,
        _event_mgr: &mut EM,
        _observers: &mut OT,
    ) -> Result<(), Error> {
        self.current_corpus_id = None;
        Ok(())
    }
}

impl<EM, M, I, OT, S, Z> Iterator for StdMutationalPushStage<EM, M, I, OT, S, Z>
where
    EM: ProgressReporter<S> + EventFirer<I, S>,
    S: HasCorpus<I>
        + HasMetadata
        + HasExecutions
        + HasLastReportTime
        + HasRand
        + MaybeHasClientPerfMonitor,
    OT: ObserversTuple<I, S> + Serialize,
    M: Mutator<I, S>,
    I: Clone + Debug + Input,
    Z: HasScheduler<I, S> + ExecutionProcessor<EM, I, OT, S>,
{
    type Item = Result<I, Error>;

    fn next(&mut self) -> Option<Result<I, Error>> {
        self.next_std()
    }
}

impl<EM, M, I, OT, S, Z> StdMutationalPushStage<EM, M, I, OT, S, Z>
where
    EM: ProgressReporter<S> + EventFirer<I, S>,
    S: HasCorpus<I>
        + HasMetadata
        + HasExecutions
        + HasLastReportTime
        + HasRand
        + MaybeHasClientPerfMonitor,
    OT: ObserversTuple<I, S> + Serialize,
    M: Mutator<I, S>,
    I: Clone + Debug + Input,
    Z: HasScheduler<I, S> + ExecutionProcessor<EM, I, OT, S>,
{
    /// Creates a new default mutational stage
    #[must_use]
    #[expect(clippy::type_complexity)]
    pub fn new(
        mutator: M,
        shared_state: Rc<RefCell<Option<PushStageSharedState<EM, I, OT, S, Z>>>>,
        exit_kind: Rc<Cell<Option<ExitKind>>>,
    ) -> Self {
        Self {
            mutator,
            psh: PushStageHelper::new(shared_state, exit_kind),
            current_corpus_id: None, // todo
            testcases_to_do: 0,
            testcases_done: 0,
        }
    }

    /// This is the implementation for `next` for this stage
    pub fn next_std(&mut self) -> Option<Result<I, Error>> {
        let mut shared_state = {
            let shared_state_ref = &mut (*self.push_stage_helper_mut().shared_state).borrow_mut();
            shared_state_ref.take().unwrap()
        };

        let step_success = if self.push_stage_helper().initialized {
            // We already ran once

            let last_input = self.push_stage_helper_mut().current_input.take().unwrap();

            self.post_exec(
                &mut shared_state.fuzzer,
                &mut shared_state.state,
                &mut shared_state.event_mgr,
                &mut shared_state.observers,
                last_input,
                self.push_stage_helper().exit_kind().unwrap(),
            )
        } else {
            self.init(
                &mut shared_state.fuzzer,
                &mut shared_state.state,
                &mut shared_state.event_mgr,
                &mut shared_state.observers,
            )
        };
        if let Err(err) = step_success {
            self.push_stage_helper_mut().end_of_iter(shared_state, true);
            return Some(Err(err));
        }

        //for i in 0..num {
        let ret = self.pre_exec(
            &mut shared_state.fuzzer,
            &mut shared_state.state,
            &mut shared_state.event_mgr,
            &mut shared_state.observers,
        );
        if ret.is_none() {
            // We're done.
            drop(self.push_stage_helper_mut().current_input.take());
            self.push_stage_helper_mut().initialized = false;

            if let Err(err) = self.deinit(
                &mut shared_state.fuzzer,
                &mut shared_state.state,
                &mut shared_state.event_mgr,
                &mut shared_state.observers,
            ) {
                self.push_stage_helper_mut().end_of_iter(shared_state, true);
                return Some(Err(err));
            }

            if let Err(err) = shared_state
                .event_mgr
                .maybe_report_progress(&mut shared_state.state, STATS_TIMEOUT_DEFAULT)
            {
                self.push_stage_helper_mut().end_of_iter(shared_state, true);
                return Some(Err(err));
            }
        } else {
            self.push_stage_helper_mut().initialized = matches!(ret, Some(Ok(_)));
            self.push_stage_helper_mut().reset_exit_kind();
        }
        self.push_stage_helper_mut()
            .end_of_iter(shared_state, false);
        ret
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use alloc::rc::Rc;
    use core::cell::{Cell, RefCell};

    use libafl_bolts::rands::StdRand;

    use super::{DEFAULT_MUTATIONAL_MAX_ITERATIONS, PushStageSharedState, StdMutationalPushStage};
    use crate::{
        Error,
        corpus::{Corpus, InMemoryCorpus, Testcase},
        events::NopEventManager,
        executors::ExitKind,
        feedbacks::{ConstFeedback, CrashFeedback},
        fuzzer::StdFuzzer,
        inputs::NopInput,
        mutators::{MutationResult, NopMutator},
        schedulers::QueueScheduler,
        state::{HasCorpus, HasSolutions, StdState},
    };

    #[test]
    fn test_iterator_processes_executions() -> Result<(), Error> {
        let mut feedback = ConstFeedback::True;
        let mut objective = CrashFeedback::new();
        let mut state = StdState::new(
            StdRand::with_seed(0),
            InMemoryCorpus::new(),
            InMemoryCorpus::new(),
            &mut feedback,
            &mut objective,
        )?;
        state.corpus_mut().add(Testcase::new(NopInput::new()))?;

        let fuzzer = StdFuzzer::new(QueueScheduler::new(), feedback, objective);
        let shared = Rc::new(RefCell::new(Some(PushStageSharedState::new(
            fuzzer,
            state,
            (),
            NopEventManager::new(),
        ))));
        let exit_kind = Rc::new(Cell::new(None));
        let mut stage = StdMutationalPushStage::new(
            NopMutator::new(MutationResult::Mutated),
            Rc::clone(&shared),
            Rc::clone(&exit_kind),
        );

        let (mut corpus_count, mut solution_count) = (1, 0);
        for result in [ExitKind::Ok, ExitKind::Crash] {
            let mut runs = 0;
            for input in stage.by_ref().take(DEFAULT_MUTATIONAL_MAX_ITERATIONS + 1) {
                input?;
                exit_kind.set(Some(result));
                runs += 1;
            }
            if result == ExitKind::Ok {
                corpus_count += runs;
            } else {
                solution_count += runs;
            }

            let shared = shared.borrow();
            let state = &shared.as_ref().unwrap().state;
            assert_eq!(state.corpus().count(), corpus_count);
            assert_eq!(state.solutions().count(), solution_count);
            assert!((1..=DEFAULT_MUTATIONAL_MAX_ITERATIONS).contains(&runs));
        }

        Ok(())
    }
}
