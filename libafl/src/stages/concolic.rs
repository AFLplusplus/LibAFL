use crate::{
    corpus::Corpus,
    executors::{Executor, HasObservers},
    inputs::Input,
    observers::{concolic::ConcolicObserver, ObserversTuple},
    state::{HasClientPerfStats, HasCorpus, HasExecutions, HasMetadata},
    Error,
};

use super::{Stage, TracingStage};

/// Wraps a [`TracingStage`] to add concolic observing.
#[derive(Clone, Debug)]
pub struct ConcolicTracingStage<C, EM, I, OT, S, TE, Z>
where
    I: Input,
    C: Corpus<I>,
    TE: Executor<EM, I, S, Z> + HasObservers<I, OT, S>,
    OT: ObserversTuple<I, S>,
    S: HasClientPerfStats + HasExecutions + HasCorpus<C, I>,
{
    inner: TracingStage<C, EM, I, OT, S, TE, Z>,
    observer_name: String,
}

impl<E, C, EM, I, OT, S, TE, Z> Stage<E, EM, S, Z> for ConcolicTracingStage<C, EM, I, OT, S, TE, Z>
where
    I: Input,
    C: Corpus<I>,
    TE: Executor<EM, I, S, Z> + HasObservers<I, OT, S>,
    OT: ObserversTuple<I, S>,
    S: HasClientPerfStats + HasExecutions + HasCorpus<C, I>,
{
    #[inline]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error> {
        self.inner
            .perform(fuzzer, executor, state, manager, corpus_idx)?;
        if let Some(observer) = self
            .inner
            .executor()
            .observers()
            .match_name::<ConcolicObserver>(&self.observer_name)
        {
            let metadata = observer.create_metadata_from_current_map();
            state
                .corpus_mut()
                .get(corpus_idx)
                .unwrap()
                .borrow_mut()
                .metadata_mut()
                .insert(metadata);
        }
        Ok(())
    }
}

impl<C, EM, I, OT, S, TE, Z> ConcolicTracingStage<C, EM, I, OT, S, TE, Z>
where
    I: Input,
    C: Corpus<I>,
    TE: Executor<EM, I, S, Z> + HasObservers<I, OT, S>,
    OT: ObserversTuple<I, S>,
    S: HasClientPerfStats + HasExecutions + HasCorpus<C, I>,
{
    /// Creates a new default tracing stage using the given [`Executor`], observing traces from a [`ConcolicObserver`] with the given name.
    pub fn new(inner: TracingStage<C, EM, I, OT, S, TE, Z>, observer_name: String) -> Self {
        Self {
            inner,
            observer_name,
        }
    }
}
