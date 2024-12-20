//! A `ShadowExecutor` wraps an executor to have shadow observer that will not be considered by the feedbacks and the manager

use core::{
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
    time::Duration,
};

use libafl_bolts::tuples::RefIndexable;

use super::HasTimeout;
use crate::{
    corpus::Corpus,
    executors::{Executor, ExitKind, HasObservers},
    observers::ObserversTuple,
    state::HasCorpus,
    Error,
};

/// A [`ShadowExecutor`] wraps an executor and a set of shadow observers
pub struct ShadowExecutor<E, S, SOT> {
    /// The wrapped executor
    executor: E,
    /// The shadow observers
    shadow_observers: SOT,
    phantom: PhantomData<S>,
}

impl<E, S, SOT> Debug for ShadowExecutor<E, S, SOT>
where
    E: Debug,
    SOT: Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShadowExecutor")
            .field("executor", &self.executor)
            .field("shadow_observers", &self.shadow_observers)
            .finish()
    }
}

impl<E, S, SOT> ShadowExecutor<E, S, SOT>
where
    E: HasObservers,
    S: HasCorpus,
    SOT: ObserversTuple<<S::Corpus as Corpus>::Input, S>,
{
    /// Create a new `ShadowExecutor`, wrapping the given `executor`.
    pub fn new(executor: E, shadow_observers: SOT) -> Self {
        Self {
            executor,
            shadow_observers,
            phantom: PhantomData,
        }
    }

    /// The shadow observers are not considered by the feedbacks and the manager, mutable
    #[inline]
    pub fn shadow_observers(&self) -> RefIndexable<&SOT, SOT> {
        RefIndexable::from(&self.shadow_observers)
    }

    /// The shadow observers are not considered by the feedbacks and the manager, mutable
    #[inline]
    pub fn shadow_observers_mut(&mut self) -> RefIndexable<&mut SOT, SOT> {
        RefIndexable::from(&mut self.shadow_observers)
    }
}

impl<E, EM, S, SOT, Z> Executor<EM, <S::Corpus as Corpus>::Input, S, Z>
    for ShadowExecutor<E, S, SOT>
where
    E: Executor<EM, <S::Corpus as Corpus>::Input, S, Z> + HasObservers,
    S: HasCorpus,
    SOT: ObserversTuple<<S::Corpus as Corpus>::Input, S>,
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

impl<E, S, SOT> HasTimeout for ShadowExecutor<E, S, SOT>
where
    E: HasTimeout,
{
    #[inline]
    fn set_timeout(&mut self, timeout: Duration) {
        self.executor.set_timeout(timeout);
    }
    #[inline]
    fn timeout(&self) -> Duration {
        self.executor.timeout()
    }
}

impl<E, S, SOT> HasObservers for ShadowExecutor<E, S, SOT>
where
    E: HasObservers,
    S: HasCorpus,
    SOT: ObserversTuple<<S::Corpus as Corpus>::Input, S>,
{
    type Observers = E::Observers;
    #[inline]
    fn observers(&self) -> RefIndexable<&Self::Observers, Self::Observers> {
        self.executor.observers()
    }

    #[inline]
    fn observers_mut(&mut self) -> RefIndexable<&mut Self::Observers, Self::Observers> {
        self.executor.observers_mut()
    }
}
