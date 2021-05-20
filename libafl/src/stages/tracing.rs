use core::{marker::PhantomData, mem::drop};

use crate::{
    corpus::Corpus,
    executors::{Executor, HasExecHooks, HasExecHooksTuple, HasObservers, HasObserversHooks},
    inputs::Input,
    mark_feature_time,
    observers::ObserversTuple,
    stages::Stage,
    start_timer,
    state::{HasClientPerfStats, HasCorpus, HasExecutions},
    Error,
};

#[cfg(feature = "introspection")]
use crate::stats::PerfFeature;

/// The default mutational stage
#[derive(Clone, Debug)]
pub struct TracingStage<C, EM, I, OT, S, TE, Z>
where
    I: Input,
    C: Corpus<I>,
    TE: Executor<I>
        + HasObservers<OT>
        + HasExecHooks<EM, I, S, Z>
        + HasObserversHooks<EM, I, OT, S, Z>,
    OT: ObserversTuple + HasExecHooksTuple<EM, I, S, Z>,
    S: HasClientPerfStats + HasExecutions + HasCorpus<C, I>,
{
    tracer_executor: TE,
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(C, EM, I, OT, S, TE, Z)>,
}

impl<E, C, EM, I, OT, S, TE, Z> Stage<E, EM, S, Z> for TracingStage<C, EM, I, OT, S, TE, Z>
where
    I: Input,
    C: Corpus<I>,
    TE: Executor<I>
        + HasObservers<OT>
        + HasExecHooks<EM, I, S, Z>
        + HasObserversHooks<EM, I, OT, S, Z>,
    OT: ObserversTuple + HasExecHooksTuple<EM, I, S, Z>,
    S: HasClientPerfStats + HasExecutions + HasCorpus<C, I>,
{
    #[inline]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        _executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error> {
        start_timer!(state);
        let input = state
            .corpus()
            .get(corpus_idx)?
            .borrow_mut()
            .load_input()?
            .clone();
        mark_feature_time!(state, PerfFeature::GetInputFromCorpus);

        start_timer!(state);
        self.tracer_executor
            .pre_exec_observers(fuzzer, state, manager, &input)?;
        mark_feature_time!(state, PerfFeature::PreExecObservers);

        start_timer!(state);
        self.tracer_executor
            .pre_exec(fuzzer, state, manager, &input)?;
        mark_feature_time!(state, PerfFeature::PreExec);

        start_timer!(state);
        let _ = self.tracer_executor.run_target(&input)?;
        mark_feature_time!(state, PerfFeature::TargetExecution);

        start_timer!(state);
        self.tracer_executor
            .post_exec(fuzzer, state, manager, &input)?;
        mark_feature_time!(state, PerfFeature::PostExec);

        *state.executions_mut() += 1;

        start_timer!(state);
        self.tracer_executor
            .post_exec_observers(fuzzer, state, manager, &input)?;
        mark_feature_time!(state, PerfFeature::PostExecObservers);

        Ok(())
    }
}

impl<C, EM, I, OT, S, TE, Z> TracingStage<C, EM, I, OT, S, TE, Z>
where
    I: Input,
    C: Corpus<I>,
    TE: Executor<I>
        + HasObservers<OT>
        + HasExecHooks<EM, I, S, Z>
        + HasObserversHooks<EM, I, OT, S, Z>,
    OT: ObserversTuple + HasExecHooksTuple<EM, I, S, Z>,
    S: HasClientPerfStats + HasExecutions + HasCorpus<C, I>,
{
    /// Creates a new default mutational stage
    pub fn new(tracer_executor: TE) -> Self {
        Self {
            tracer_executor,
            phantom: PhantomData,
        }
    }
}
