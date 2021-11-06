//| The [`MutationalStage`] is the default stage used during fuzzing.
//! For the current input, it will perform a range of random mutations, and then run them in the executor.

use alloc::rc::Rc;
use core::{
    borrow::BorrowMut,
    cell::{Cell, RefCell},
    marker::PhantomData,
    time::Duration,
};

use crate::{
    bolts::{current_time, rands::Rand},
    corpus::Corpus,
    events::EventManager,
    executors::ExitKind,
    fuzzer::Evaluator,
    inputs::Input,
    mark_feature_time,
    mutators::Mutator,
    observers::ObserversTuple,
    start_timer,
    state::{HasClientPerfStats, HasCorpus, HasRand},
    Error, EvaluatorObservers, ExecutionProcessor, Fuzzer,
};

#[cfg(feature = "introspection")]
use crate::stats::PerfFeature;

/// Send a stats update all 15 (or more) seconds
const STATS_TIMEOUT_DEFAULT: Duration = Duration::from_secs(15);

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
pub struct StdMutationalPushStage<C, E, EM, I, M, OT, R, S, Z>
where
    C: Corpus<I>,
    EM: EventManager<E, I, S, Z>,
    I: Input,
    M: Mutator<I, S>,
    OT: ObserversTuple<I, S>,
    R: Rand,
    S: HasClientPerfStats + HasCorpus<C, I> + HasRand<R>,
    Z: Evaluator<E, EM, I, S>
        + ExecutionProcessor<I, OT, S>
        + EvaluatorObservers<I, OT, S>
        + Fuzzer<E, EM, I, S, ()>,
{
    initialized: bool,
    state: Rc<RefCell<S>>,
    current_iter: Option<usize>,
    current_corpus_idx: usize,
    testcases_to_do: usize,
    testcases_done: usize,

    fuzzer: Rc<RefCell<Z>>,
    event_mgr: Rc<RefCell<EM>>,

    current_input: Option<I>, // Todo: Get rid of copy

    stage_idx: i32,

    mutator: M,
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(C, E, EM, I, R, OT, S, Z)>,
    last_stats_time: Duration,
    observers: Rc<RefCell<OT>>,
    exit_kind: Rc<Cell<Option<ExitKind>>>,
}

impl<C, E, EM, I, M, OT, R, S, Z> StdMutationalPushStage<C, E, EM, I, M, OT, R, S, Z>
where
    C: Corpus<I>,
    EM: EventManager<E, I, S, Z>,
    I: Input,
    M: Mutator<I, S>,
    OT: ObserversTuple<I, S>,
    R: Rand,
    S: HasClientPerfStats + HasCorpus<C, I> + HasRand<R>,
    Z: Evaluator<E, EM, I, S>
        + ExecutionProcessor<I, OT, S>
        + EvaluatorObservers<I, OT, S>
        + Fuzzer<E, EM, I, S, ()>,
{
    /// Gets the number of iterations as a random number
    #[allow(clippy::unused_self, clippy::unnecessary_wraps)] // TODO: we should put this function into a trait later
    fn iterations(&self, state: &mut S, _corpus_idx: usize) -> Result<usize, Error> {
        Ok(1 + state.rand_mut().below(DEFAULT_MUTATIONAL_MAX_ITERATIONS) as usize)
    }

    /// Creates a new default mutational stage
    fn init(&mut self, corpus_idx: usize) -> Result<(), Error> {
        let state: &mut S = &mut (*self.state).borrow_mut();

        self.testcases_to_do = self.iterations(state, corpus_idx)?;
        self.testcases_done = 0;
        Ok(())
    }

    fn pre_exec(&mut self) -> Option<Result<I, Error>> {
        let state: &mut S = &mut (*self.state).borrow_mut();

        if self.testcases_done >= self.testcases_to_do {
            // finished with this cicle.
            return None;
        }

        start_timer!(state);
        let mut input = state
            .corpus()
            .get(self.current_corpus_idx)
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

        self.current_input = Some(input.clone()); // TODO: Get rid of this

        Some(Ok(input))
    }

    fn post_exec(&mut self) -> Result<(), Error> {
        // todo: isintersting, etc.

        let state: &mut S = &mut (*self.state).borrow_mut();

        let fuzzer: &mut Z = &mut (*self.fuzzer).borrow_mut();
        let event_mgr: &mut EM = &mut (*self.event_mgr).borrow_mut();
        let observers_refcell: &RefCell<OT> = self.observers.borrow_mut();
        let observers: &mut OT = &mut observers_refcell.borrow_mut();

        fuzzer.process_execution(
            state,
            event_mgr,
            self.current_input.take().unwrap(),
            observers,
            &self.exit_kind.get().unwrap(),
            true,
        )?;

        start_timer!(state);
        self.mutator
            .post_exec(state, self.stage_idx as i32, Some(self.testcases_done))?;
        mark_feature_time!(state, PerfFeature::MutatePostExec);
        self.testcases_done += 1;

        Ok(())
    }
}

impl<C, E, EM, I, M, OT, R, S, Z> Iterator for StdMutationalPushStage<C, E, EM, I, M, OT, R, S, Z>
where
    C: Corpus<I>,
    EM: EventManager<E, I, S, Z>,
    I: Input,
    M: Mutator<I, S>,
    OT: ObserversTuple<I, S>,
    R: Rand,
    S: HasClientPerfStats + HasCorpus<C, I> + HasRand<R>,
    Z: Evaluator<E, EM, I, S>
        + ExecutionProcessor<I, OT, S>
        + EvaluatorObservers<I, OT, S>
        + Fuzzer<E, EM, I, S, ()>,
{
    type Item = Result<I, Error>;

    fn next(&mut self) -> Option<Result<I, Error>> {
        let step_success = if self.initialized {
            // We already ran once
            self.post_exec()
        } else {
            self.init(self.current_corpus_idx) // TODO: Corpus idx
        };
        if let Err(err) = step_success {
            //let errored = true;
            return Some(Err(err));
        }

        //for i in 0..num {
        let ret = self.pre_exec();
        if ret.is_none() {
            // We're done.
            self.initialized = false;

            let state: &mut S = &mut (*self.state).borrow_mut();
            //let fuzzer: &mut Z = &mut (*self.fuzzer).borrow_mut();
            let event_mgr: &mut EM = &mut (*self.event_mgr).borrow_mut();

            self.last_stats_time = Z::maybe_report_stats(
                state,
                event_mgr,
                self.last_stats_time,
                STATS_TIMEOUT_DEFAULT,
            )
            .unwrap();
            //self.fuzzer.maybe_report_stats();
        } else {
            self.exit_kind.replace(None);
        }
        ret
    }
}

impl<C, E, EM, I, M, OT, R, S, Z> StdMutationalPushStage<C, E, EM, I, M, OT, R, S, Z>
where
    C: Corpus<I>,
    EM: EventManager<E, I, S, Z>,
    I: Input,
    M: Mutator<I, S>,
    OT: ObserversTuple<I, S>,
    R: Rand,
    S: HasClientPerfStats + HasCorpus<C, I> + HasRand<R>,
    Z: Evaluator<E, EM, I, S>
        + ExecutionProcessor<I, OT, S>
        + EvaluatorObservers<I, OT, S>
        + Fuzzer<E, EM, I, S, ()>,
{
    /// Creates a new default mutational stage
    pub fn new(
        mutator: M,
        fuzzer: Rc<RefCell<Z>>,
        state: Rc<RefCell<S>>,
        event_mgr: Rc<RefCell<EM>>,
        observers: Rc<RefCell<OT>>,
        exit_kind: Rc<Cell<Option<ExitKind>>>,
        stage_idx: i32,
    ) -> Self {
        Self {
            mutator,
            phantom: PhantomData,
            initialized: false,
            state,
            current_iter: None,
            current_corpus_idx: 0, // todo
            testcases_to_do: 0,
            testcases_done: 0,
            current_input: None,
            stage_idx,
            fuzzer,
            event_mgr,
            observers,
            exit_kind,
            last_stats_time: current_time(),
        }
    }
}
