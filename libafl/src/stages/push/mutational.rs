//| The [`MutationalStage`] is the default stage used during fuzzing.
//! For the current input, it will perform a range of random mutations, and then run them in the executor.

use alloc::rc::Rc;
use core::{
    cell::{Cell, RefCell},
    fmt::Debug,
    time::Duration,
};

use libafl_bolts::rands::Rand;

use super::{PushStage, PushStageHelper, PushStageSharedState};
use crate::{
    corpus::{Corpus, CorpusId, HasCorpus},
    events::ProgressReporter,
    executors::ExitKind,
    mark_feature_time,
    mutators::Mutator,
    schedulers::Scheduler,
    start_timer,
    state::HasRand,
    Error, ExecutionProcessor, HasScheduler,
};
#[cfg(feature = "introspection")]
use crate::{monitors::PerfFeature, state::HasClientPerfMonitor};

/// Send a monitor update all 15 (or more) seconds
const STATS_TIMEOUT_DEFAULT: Duration = Duration::from_secs(15);

/// The default maximum number of mutations to perform per input.
pub static DEFAULT_MUTATIONAL_MAX_ITERATIONS: usize = 128;
/// A Mutational push stage is the stage in a fuzzing run that mutates inputs.
/// Mutational push stages will usually have a range of mutations that are
/// being applied to the input one by one, between executions.
/// The push version, in contrast to the normal stage, will return each testcase, instead of executing it.
///
/// Default value, how many iterations each stage gets, as an upper bound.
/// It may randomly continue earlier.
///
/// The default mutational push stage
#[derive(Debug)]
pub struct StdMutationalPushStage<EM, OT, S, M, Z>
where
    S: HasCorpus,
{
    current_corpus_id: Option<CorpusId>,
    testcases_to_do: usize,
    testcases_done: usize,

    mutator: M,

    psh: PushStageHelper<EM, <S::Corpus as Corpus>::Input, OT, S, Z>,
}

impl<EM, OT, S, M, Z> StdMutationalPushStage<EM, OT, S, M, Z>
where
    S: HasCorpus + HasRand,
{
    /// Gets the number of iterations as a random number
    #[allow(clippy::unused_self, clippy::unnecessary_wraps)] // TODO: we should put this function into a trait later
    fn iterations(&self, state: &mut S, _corpus_id: CorpusId) -> Result<usize, Error> {
        Ok(1 + state.rand_mut().below(DEFAULT_MUTATIONAL_MAX_ITERATIONS))
    }

    /// Sets the current corpus index
    pub fn set_current_corpus_id(&mut self, current_corpus_id: CorpusId) {
        self.current_corpus_id = Some(current_corpus_id);
    }
}

impl<EM, M, OT, S, Z> PushStage<EM, OT, S, Z> for StdMutationalPushStage<EM, OT, S, M, Z>
where
    S: HasCorpus + HasRand,
    M: Mutator<<S::Corpus as Corpus>::Input, S>,
    <S::Corpus as Corpus>::Input: Clone,
    Z: HasScheduler + ExecutionProcessor<EM, <S::Corpus as Corpus>::Input, OT, S>,
    Z::Scheduler: Scheduler<<S::Corpus as Corpus>::Input, OT, S>,
{
    type Input = <S::Corpus as Corpus>::Input;

    #[inline]
    fn push_stage_helper(&self) -> &PushStageHelper<EM, Self::Input, OT, S, Z> {
        &self.psh
    }

    #[inline]
    fn push_stage_helper_mut(&mut self) -> &mut PushStageHelper<EM, Self::Input, OT, S, Z> {
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
    ) -> Option<Result<Self::Input, Error>> {
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
        last_input: Self::Input,
        exit_kind: ExitKind,
    ) -> Result<(), Error> {
        // todo: is_interesting, etc.

        fuzzer.evaluate_execution(state, event_mgr, last_input, observers, &exit_kind, true)?;

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

impl<EM, OT, S, M, Z> Iterator for StdMutationalPushStage<EM, OT, S, M, Z>
where
    S: HasCorpus + HasRand,
    M: Mutator<<S::Corpus as Corpus>::Input, S>,
    <S::Corpus as Corpus>::Input: Clone,
    Z: HasScheduler + ExecutionProcessor<EM, <S::Corpus as Corpus>::Input, OT, S>,
    Z::Scheduler: Scheduler<<S::Corpus as Corpus>::Input, OT, S>,
    EM: ProgressReporter<S>,
{
    type Item = Result<<Self as PushStage<EM, OT, S, Z>>::Input, Error>;

    fn next(&mut self) -> Option<Result<<Self as PushStage<EM, OT, S, Z>>::Input, Error>> {
        self.next_std()
    }
}

impl<EM, OT, S, M, Z> StdMutationalPushStage<EM, OT, S, M, Z>
where
    S: HasCorpus + HasRand,
    M: Mutator<<S::Corpus as Corpus>::Input, S>,
    <S::Corpus as Corpus>::Input: Clone,
    Z: HasScheduler + ExecutionProcessor<EM, <S::Corpus as Corpus>::Input, OT, S>,
    Z::Scheduler: Scheduler<<S::Corpus as Corpus>::Input, OT, S>,
{
    /// Creates a new default mutational stage
    #[must_use]
    #[allow(clippy::type_complexity)]
    pub fn new(
        mutator: M,
        shared_state: Rc<RefCell<Option<PushStageSharedState<EM, OT, S, Z>>>>,
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
}
