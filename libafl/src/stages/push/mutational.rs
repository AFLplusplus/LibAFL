//| The [`MutationalStage`] is the default stage used during fuzzing.
//! For the current input, it will perform a range of random mutations, and then run them in the executor.

use alloc::rc::Rc;
use core::cell::{Cell, RefCell};

use crate::{
    bolts::rands::Rand,
    corpus::{Corpus, CorpusScheduler},
    events::{EventFirer, EventRestarter, HasEventManagerId, ProgressReporter},
    executors::ExitKind,
    inputs::Input,
    mark_feature_time,
    mutators::Mutator,
    observers::ObserversTuple,
    start_timer,
    state::{HasClientPerfMonitor, HasCorpus, HasExecutions, HasRand},
    Error, EvaluatorObservers, ExecutionProcessor, HasCorpusScheduler,
};

#[cfg(feature = "introspection")]
use crate::monitors::PerfFeature;

use super::{PushStage, PushStageHelper, PushStageSharedState};

pub static DEFAULT_MUTATIONAL_MAX_ITERATIONS: u64 = 128;
/// A Mutational push stage is the stage in a fuzzing run that mutates inputs.
/// Mutational push stages will usually have a range of mutations that are
/// being applied to the input one by one, between executions.
/// The push version, in contrast to the normal stage, will return each testcase, instead of executing it.
///
/// Default value, how many iterations each stage gets, as an upper bound
/// It may randomly continue earlier.
///
/// The default mutational push stage
#[derive(Clone, Debug)]
pub struct StdMutationalPushStage<C, CS, EM, I, M, OT, R, S, Z>
where
    C: Corpus<I>,
    CS: CorpusScheduler<I, S>,
    EM: EventFirer<I> + EventRestarter<S> + HasEventManagerId,
    I: Input,
    M: Mutator<I, S>,
    OT: ObserversTuple<I, S>,
    R: Rand,
    S: HasClientPerfMonitor + HasCorpus<C, I> + HasRand<R>,
    Z: ExecutionProcessor<I, OT, S> + EvaluatorObservers<I, OT, S> + HasCorpusScheduler<CS, I, S>,
{
    current_corpus_idx: Option<usize>,
    testcases_to_do: usize,
    testcases_done: usize,

    stage_idx: i32,

    mutator: M,

    psh: PushStageHelper<C, CS, EM, I, OT, R, S, Z>,
}

impl<C, CS, EM, I, M, OT, R, S, Z> StdMutationalPushStage<C, CS, EM, I, M, OT, R, S, Z>
where
    C: Corpus<I>,
    CS: CorpusScheduler<I, S>,
    EM: EventFirer<I> + EventRestarter<S> + HasEventManagerId,
    I: Input,
    M: Mutator<I, S>,
    OT: ObserversTuple<I, S>,
    R: Rand,
    S: HasClientPerfMonitor + HasCorpus<C, I> + HasRand<R>,
    Z: ExecutionProcessor<I, OT, S> + EvaluatorObservers<I, OT, S> + HasCorpusScheduler<CS, I, S>,
{
    /// Gets the number of iterations as a random number
    #[allow(clippy::unused_self, clippy::unnecessary_wraps)] // TODO: we should put this function into a trait later
    fn iterations(&self, state: &mut S, _corpus_idx: usize) -> Result<usize, Error> {
        Ok(1 + state.rand_mut().below(DEFAULT_MUTATIONAL_MAX_ITERATIONS) as usize)
    }

    pub fn set_current_corpus_idx(&mut self, current_corpus_idx: usize) {
        self.current_corpus_idx = Some(current_corpus_idx);
    }
}

impl<C, CS, EM, I, M, OT, R, S, Z> PushStage<C, CS, EM, I, OT, R, S, Z>
    for StdMutationalPushStage<C, CS, EM, I, M, OT, R, S, Z>
where
    C: Corpus<I>,
    CS: CorpusScheduler<I, S>,
    EM: EventFirer<I> + EventRestarter<S> + HasEventManagerId + ProgressReporter<I>,
    I: Input,
    M: Mutator<I, S>,
    OT: ObserversTuple<I, S>,
    R: Rand,
    S: HasClientPerfMonitor + HasCorpus<C, I> + HasRand<R> + HasExecutions,
    Z: ExecutionProcessor<I, OT, S> + EvaluatorObservers<I, OT, S> + HasCorpusScheduler<CS, I, S>,
{
    /// Creates a new default mutational stage
    fn init(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        _event_mgr: &mut EM,
        _observers: &mut OT,
    ) -> Result<(), Error> {
        // Find a testcase to work on, unless someone already set it
        self.current_corpus_idx = Some(if let Some(corpus_idx) = self.current_corpus_idx {
            corpus_idx
        } else {
            fuzzer.scheduler().next(state)?
        });

        self.testcases_to_do = self.iterations(state, self.current_corpus_idx.unwrap())?;
        self.testcases_done = 0;
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
        self.current_corpus_idx = None;
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
        let mut input = state
            .corpus()
            .get(self.current_corpus_idx.unwrap())
            .unwrap()
            .borrow_mut()
            .load_input()
            .unwrap()
            .clone();
        mark_feature_time!(state, PerfFeature::GetInputFromCorpus);

        start_timer!(state);
        self.mutator
            .mutate(state, &mut input, self.stage_idx as i32)
            .unwrap();
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
        // todo: isintersting, etc.

        fuzzer.process_execution(state, event_mgr, last_input, observers, &exit_kind, true)?;

        start_timer!(state);
        self.mutator
            .post_exec(state, self.stage_idx as i32, Some(self.testcases_done))?;
        mark_feature_time!(state, PerfFeature::MutatePostExec);
        self.testcases_done += 1;

        Ok(())
    }

    #[inline]
    fn push_stage_helper(&self) -> &PushStageHelper<C, CS, EM, I, OT, R, S, Z> {
        &self.psh
    }

    #[inline]
    fn push_stage_helper_mut(&mut self) -> &mut PushStageHelper<C, CS, EM, I, OT, R, S, Z> {
        &mut self.psh
    }
}

impl<C, CS, EM, I, M, OT, R, S, Z> Iterator for StdMutationalPushStage<C, CS, EM, I, M, OT, R, S, Z>
where
    C: Corpus<I>,
    CS: CorpusScheduler<I, S>,
    EM: EventFirer<I> + EventRestarter<S> + HasEventManagerId + ProgressReporter<I>,
    I: Input,
    M: Mutator<I, S>,
    OT: ObserversTuple<I, S>,
    R: Rand,
    S: HasClientPerfMonitor + HasCorpus<C, I> + HasRand<R> + HasExecutions,
    Z: ExecutionProcessor<I, OT, S> + EvaluatorObservers<I, OT, S> + HasCorpusScheduler<CS, I, S>,
{
    type Item = Result<I, Error>;

    fn next(&mut self) -> Option<Result<I, Error>> {
        self.next_std()
    }
}

impl<C, CS, EM, I, M, OT, R, S, Z> StdMutationalPushStage<C, CS, EM, I, M, OT, R, S, Z>
where
    C: Corpus<I>,
    CS: CorpusScheduler<I, S>,
    EM: EventFirer<I> + EventRestarter<S> + HasEventManagerId,
    I: Input,
    M: Mutator<I, S>,
    OT: ObserversTuple<I, S>,
    R: Rand,
    S: HasClientPerfMonitor + HasCorpus<C, I> + HasRand<R>,
    Z: ExecutionProcessor<I, OT, S> + EvaluatorObservers<I, OT, S> + HasCorpusScheduler<CS, I, S>,
{
    /// Creates a new default mutational stage
    #[must_use]
    #[allow(clippy::type_complexity)]
    pub fn new(
        mutator: M,
        shared_state: Rc<RefCell<Option<PushStageSharedState<C, CS, EM, I, OT, R, S, Z>>>>,
        exit_kind: Rc<Cell<Option<ExitKind>>>,
        stage_idx: i32,
    ) -> Self {
        Self {
            mutator,
            psh: PushStageHelper::new(shared_state, exit_kind),
            current_corpus_idx: None, // todo
            testcases_to_do: 0,
            testcases_done: 0,
            stage_idx,
        }
    }
}
