//| The [`MutationalStage`] is the default stage used during fuzzing.
//! For the current input, it will perform a range of random mutations, and then run them in the executor.

use alloc::rc::Rc;
use core::{
    cell::{Cell, RefCell},
    fmt::Debug,
};

use libafl_bolts::rands::Rand;

use super::{PushStage, PushStageHelper, PushStageSharedState};
use crate::{
    corpus::{Corpus, CorpusId},
    events::{EventFirer, EventRestarter, HasEventManagerId, ProgressReporter},
    executors::ExitKind,
    inputs::UsesInput,
    mark_feature_time,
    mutators::Mutator,
    observers::ObserversTuple,
    schedulers::Scheduler,
    start_timer,
    state::{HasCorpus, HasExecutions, HasLastReportTime, HasMetadata, HasRand},
    Error, EvaluatorObservers, ExecutionProcessor, HasScheduler,
};
#[cfg(feature = "introspection")]
use crate::{monitors::PerfFeature, state::HasClientPerfMonitor};

/// The default maximum number of mutations to perform per input.
pub static DEFAULT_MUTATIONAL_MAX_ITERATIONS: u64 = 128;
/// A Mutational push stage is the stage in a fuzzing run that mutates inputs.
/// Mutational push stages will usually have a range of mutations that are
/// being applied to the input one by one, between executions.
/// The push version, in contrast to the normal stage, will return each testcase, instead of executing it.
///
/// Default value, how many iterations each stage gets, as an upper bound.
/// It may randomly continue earlier.
///
/// The default mutational push stage
#[derive(Clone, Debug)]
pub struct StdMutationalPushStage<CS, EM, M, OT, Z>
where
    CS: Scheduler,
    EM: EventFirer<State = CS::State> + EventRestarter + HasEventManagerId,
    M: Mutator<CS::Input, CS::State>,
    OT: ObserversTuple<CS::State>,
    CS::State: HasRand + HasCorpus + Clone + Debug,
    Z: ExecutionProcessor<OT, State = CS::State>
        + EvaluatorObservers<OT>
        + HasScheduler<Scheduler = CS>,
{
    current_corpus_idx: Option<CorpusId>,
    testcases_to_do: usize,
    testcases_done: usize,

    mutator: M,

    psh: PushStageHelper<CS, EM, OT, Z>,
}

impl<CS, EM, M, OT, Z> StdMutationalPushStage<CS, EM, M, OT, Z>
where
    CS: Scheduler,
    EM: EventFirer<State = CS::State> + EventRestarter + HasEventManagerId,
    M: Mutator<CS::Input, CS::State>,
    OT: ObserversTuple<CS::State>,
    CS::State: HasCorpus + HasRand + Clone + Debug,
    Z: ExecutionProcessor<OT, State = CS::State>
        + EvaluatorObservers<OT>
        + HasScheduler<Scheduler = CS>,
{
    /// Gets the number of iterations as a random number
    #[allow(clippy::unused_self, clippy::unnecessary_wraps)] // TODO: we should put this function into a trait later
    fn iterations(&self, state: &mut CS::State, _corpus_idx: CorpusId) -> Result<usize, Error> {
        Ok(1 + state.rand_mut().below(DEFAULT_MUTATIONAL_MAX_ITERATIONS) as usize)
    }

    /// Sets the current corpus index
    pub fn set_current_corpus_idx(&mut self, current_corpus_idx: CorpusId) {
        self.current_corpus_idx = Some(current_corpus_idx);
    }
}

impl<CS, EM, M, OT, Z> PushStage<CS, EM, OT, Z> for StdMutationalPushStage<CS, EM, M, OT, Z>
where
    CS: Scheduler,
    EM: EventFirer<State = CS::State> + EventRestarter + HasEventManagerId + ProgressReporter,
    M: Mutator<CS::Input, CS::State>,
    OT: ObserversTuple<CS::State>,
    CS::State:
        HasCorpus + HasRand + HasExecutions + HasLastReportTime + HasMetadata + Clone + Debug,
    Z: ExecutionProcessor<OT, State = CS::State>
        + EvaluatorObservers<OT>
        + HasScheduler<Scheduler = CS>,
{
    #[inline]
    fn push_stage_helper(&self) -> &PushStageHelper<CS, EM, OT, Z> {
        &self.psh
    }

    #[inline]
    fn push_stage_helper_mut(&mut self) -> &mut PushStageHelper<CS, EM, OT, Z> {
        &mut self.psh
    }

    /// Creates a new default mutational stage
    fn init(
        &mut self,
        fuzzer: &mut Z,
        state: &mut CS::State,
        _event_mgr: &mut EM,
        _observers: &mut OT,
    ) -> Result<(), Error> {
        // Find a testcase to work on, unless someone already set it
        self.current_corpus_idx = Some(if let Some(corpus_idx) = self.current_corpus_idx {
            corpus_idx
        } else {
            fuzzer.scheduler_mut().next(state)?
        });

        self.testcases_to_do = self.iterations(state, self.current_corpus_idx.unwrap())?;
        self.testcases_done = 0;
        Ok(())
    }

    fn pre_exec(
        &mut self,
        _fuzzer: &mut Z,
        state: &mut CS::State,
        _event_mgr: &mut EM,
        _observers: &mut OT,
    ) -> Option<Result<<CS::State as UsesInput>::Input, Error>> {
        if self.testcases_done >= self.testcases_to_do {
            // finished with this cicle.
            return None;
        }

        start_timer!(state);

        let input = state
            .corpus_mut()
            .cloned_input_for_id(self.current_corpus_idx.unwrap());
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
        state: &mut CS::State,
        event_mgr: &mut EM,
        observers: &mut OT,
        last_input: <CS::State as UsesInput>::Input,
        exit_kind: ExitKind,
    ) -> Result<(), Error> {
        // todo: is_interesting, etc.

        fuzzer.process_execution(state, event_mgr, last_input, observers, &exit_kind, true)?;

        start_timer!(state);
        self.mutator.post_exec(state, self.current_corpus_idx)?;
        mark_feature_time!(state, PerfFeature::MutatePostExec);
        self.testcases_done += 1;

        Ok(())
    }

    #[inline]
    fn deinit(
        &mut self,
        _fuzzer: &mut Z,
        _state: &mut CS::State,
        _event_mgr: &mut EM,
        _observers: &mut OT,
    ) -> Result<(), Error> {
        self.current_corpus_idx = None;
        Ok(())
    }
}

impl<CS, EM, M, OT, Z> Iterator for StdMutationalPushStage<CS, EM, M, OT, Z>
where
    CS: Scheduler,
    EM: EventFirer + EventRestarter + HasEventManagerId + ProgressReporter<State = CS::State>,
    M: Mutator<CS::Input, CS::State>,
    OT: ObserversTuple<CS::State>,
    CS::State:
        HasCorpus + HasRand + HasExecutions + HasMetadata + HasLastReportTime + Clone + Debug,
    Z: ExecutionProcessor<OT, State = CS::State>
        + EvaluatorObservers<OT>
        + HasScheduler<Scheduler = CS>,
{
    type Item = Result<<CS::State as UsesInput>::Input, Error>;

    fn next(&mut self) -> Option<Result<<CS::State as UsesInput>::Input, Error>> {
        self.next_std()
    }
}

impl<CS, EM, M, OT, Z> StdMutationalPushStage<CS, EM, M, OT, Z>
where
    CS: Scheduler,
    EM: EventFirer<State = CS::State> + EventRestarter + HasEventManagerId,
    M: Mutator<CS::Input, CS::State>,
    OT: ObserversTuple<CS::State>,
    CS::State: HasCorpus + HasRand + Clone + Debug,
    Z: ExecutionProcessor<OT, State = CS::State>
        + EvaluatorObservers<OT>
        + HasScheduler<Scheduler = CS>,
{
    /// Creates a new default mutational stage
    #[must_use]
    #[allow(clippy::type_complexity)]
    pub fn new(
        mutator: M,
        shared_state: Rc<RefCell<Option<PushStageSharedState<CS, EM, OT, Z>>>>,
        exit_kind: Rc<Cell<Option<ExitKind>>>,
    ) -> Self {
        Self {
            mutator,
            psh: PushStageHelper::new(shared_state, exit_kind),
            current_corpus_idx: None, // todo
            testcases_to_do: 0,
            testcases_done: 0,
        }
    }
}
