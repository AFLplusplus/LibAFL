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
    corpus::{Corpus, CorpusScheduler},
    events::EventManager,
    executors::ExitKind,
    inputs::Input,
    mark_feature_time,
    mutators::Mutator,
    observers::ObserversTuple,
    start_timer,
    state::{HasClientPerfMonitor, HasCorpus, HasRand},
    Error, EvaluatorObservers, ExecutionProcessor, Fuzzer, HasCorpusScheduler,
};

#[cfg(feature = "introspection")]
use crate::monitors::PerfFeature;

/// Send a monitor update all 15 (or more) seconds
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
pub struct StdMutationalPushStage<C, CS, EM, I, M, OT, R, S, Z>
where
    C: Corpus<I>,
    CS: CorpusScheduler<I, S>,
    EM: EventManager<(), I, S, Z>,
    I: Input,
    M: Mutator<I, S>,
    OT: ObserversTuple<I, S>,
    R: Rand,
    S: HasClientPerfMonitor + HasCorpus<C, I> + HasRand<R>,
    Z: ExecutionProcessor<I, OT, S>
        + EvaluatorObservers<I, OT, S>
        + Fuzzer<(), EM, I, S, ()>
        + HasCorpusScheduler<CS, I, S>,
{
    initialized: bool,
    state: Rc<RefCell<S>>,
    current_corpus_idx: Option<usize>,
    testcases_to_do: usize,
    testcases_done: usize,

    fuzzer: Rc<RefCell<Z>>,
    event_mgr: Rc<RefCell<EM>>,

    current_input: Option<I>, // Todo: Get rid of copy

    stage_idx: i32,

    mutator: M,
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(C, CS, (), EM, I, R, OT, S, Z)>,
    last_monitor_time: Duration,
    observers: Rc<RefCell<OT>>,
    exit_kind: Rc<Cell<Option<ExitKind>>>,
}

impl<C, CS, EM, I, M, OT, R, S, Z> StdMutationalPushStage<C, CS, EM, I, M, OT, R, S, Z>
where
    C: Corpus<I>,
    CS: CorpusScheduler<I, S>,
    EM: EventManager<(), I, S, Z>,
    I: Input,
    M: Mutator<I, S>,
    OT: ObserversTuple<I, S>,
    R: Rand,
    S: HasClientPerfMonitor + HasCorpus<C, I> + HasRand<R>,
    Z: ExecutionProcessor<I, OT, S>
        + EvaluatorObservers<I, OT, S>
        + Fuzzer<(), EM, I, S, ()>
        + HasCorpusScheduler<CS, I, S>,
{
    /// Gets the number of iterations as a random number
    #[allow(clippy::unused_self, clippy::unnecessary_wraps)] // TODO: we should put this function into a trait later
    fn iterations(&self, state: &mut S, _corpus_idx: usize) -> Result<usize, Error> {
        Ok(1 + state.rand_mut().below(DEFAULT_MUTATIONAL_MAX_ITERATIONS) as usize)
    }

    pub fn set_current_corpus_idx(&mut self, current_corpus_idx: usize) {
        self.current_corpus_idx = Some(current_corpus_idx);
    }

    /// Creates a new default mutational stage
    fn init(&mut self) -> Result<(), Error> {
        let state: &mut S = &mut (*self.state).borrow_mut();

        // Find a testcase to work on, unless someone already set it
        self.current_corpus_idx = Some(if let Some(corpus_idx) = self.current_corpus_idx {
            corpus_idx
        } else {
            let fuzzer: &mut Z = &mut (*self.fuzzer).borrow_mut();
            fuzzer.scheduler().next(state)?
        });

        self.testcases_to_do = self.iterations(state, self.current_corpus_idx.unwrap())?;
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

impl<C, CS, EM, I, M, OT, R, S, Z> Iterator for StdMutationalPushStage<C, CS, EM, I, M, OT, R, S, Z>
where
    C: Corpus<I>,
    CS: CorpusScheduler<I, S>,
    EM: EventManager<(), I, S, Z>,
    I: Input,
    M: Mutator<I, S>,
    OT: ObserversTuple<I, S>,
    R: Rand,
    S: HasClientPerfMonitor + HasCorpus<C, I> + HasRand<R>,
    Z: ExecutionProcessor<I, OT, S>
        + EvaluatorObservers<I, OT, S>
        + Fuzzer<(), EM, I, S, ()>
        + HasCorpusScheduler<CS, I, S>,
{
    type Item = Result<I, Error>;

    fn next(&mut self) -> Option<Result<I, Error>> {
        let step_success = if self.initialized {
            // We already ran once
            self.post_exec()
        } else {
            self.init()
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
            self.current_corpus_idx = None;

            let state: &mut S = &mut (*self.state).borrow_mut();
            //let fuzzer: &mut Z = &mut (*self.fuzzer).borrow_mut();
            let event_mgr: &mut EM = &mut (*self.event_mgr).borrow_mut();

            self.last_monitor_time = Z::maybe_report_monitor(
                state,
                event_mgr,
                self.last_monitor_time,
                STATS_TIMEOUT_DEFAULT,
            )
            .unwrap();
            //self.fuzzer.maybe_report_monitor();
        } else {
            self.exit_kind.replace(None);
        }
        ret
    }
}

impl<C, CS, EM, I, M, OT, R, S, Z> StdMutationalPushStage<C, CS, EM, I, M, OT, R, S, Z>
where
    C: Corpus<I>,
    CS: CorpusScheduler<I, S>,
    EM: EventManager<(), I, S, Z>,
    I: Input,
    M: Mutator<I, S>,
    OT: ObserversTuple<I, S>,
    R: Rand,
    S: HasClientPerfMonitor + HasCorpus<C, I> + HasRand<R>,
    Z: ExecutionProcessor<I, OT, S>
        + EvaluatorObservers<I, OT, S>
        + Fuzzer<(), EM, I, S, ()>
        + HasCorpusScheduler<CS, I, S>,
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
            current_corpus_idx: None, // todo
            testcases_to_do: 0,
            testcases_done: 0,
            current_input: None,
            stage_idx,
            fuzzer,
            event_mgr,
            observers,
            exit_kind,
            last_monitor_time: current_time(),
        }
    }
}
