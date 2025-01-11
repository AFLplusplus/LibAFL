//! A wrapper for any [`Executor`] to make it implement [`HasObservers`] using a given [`ObserversTuple`].

use core::{fmt::Debug, marker::PhantomData};

use libafl_bolts::tuples::RefIndexable;

use crate::{
    corpus::Corpus,
    executors::{Executor, ExitKind, HasObservers},
    observers::ObserversTuple,
    state::HasCorpus,
    Error,
};

/// A wrapper for any [`Executor`] to make it implement [`HasObservers`] using a given [`ObserversTuple`].
#[derive(Debug)]
pub struct WithObservers<E, OT, S> {
    executor: E,
    observers: OT,
    phantom: PhantomData<S>,
}

impl<E, EM, OT, S, Z> Executor<EM, <S::Corpus as Corpus>::Input, S, Z> for WithObservers<E, OT, S>
where
    S: HasCorpus,
    E: Executor<EM, <S::Corpus as Corpus>::Input, S, Z>,
{
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &<S::Corpus as Corpus>::Input,
    ) -> Result<ExitKind, Error> {
        self.executor.run_target(fuzzer, state, mgr, input)
    }
}

impl<E, OT, S> HasObservers for WithObservers<E, OT, S>
where
    S: HasCorpus,
    OT: ObserversTuple<<S::Corpus as Corpus>::Input, S>,
{
    type Observers = OT;
    fn observers(&self) -> RefIndexable<&Self::Observers, Self::Observers> {
        RefIndexable::from(&self.observers)
    }

    fn observers_mut(&mut self) -> RefIndexable<&mut Self::Observers, Self::Observers> {
        RefIndexable::from(&mut self.observers)
    }
}

impl<E, OT, S> WithObservers<E, OT, S> {
    /// Wraps the given [`Executor`] with the given [`ObserversTuple`] to implement [`HasObservers`].
    ///
    /// If the executor already implements [`HasObservers`], then the original implementation will be overshadowed by
    /// the implementation of this wrapper.
    pub fn new(executor: E, observers: OT) -> Self {
        Self {
            executor,
            observers,
            phantom: PhantomData,
        }
    }
}
