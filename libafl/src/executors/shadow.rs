//! A `ShadowExecutor` wraps an executor to have shadow observer that will not be considered by the feedbacks and the manager

use core::fmt::{self, Debug, Formatter};

use crate::{
    executors::{Executor, ExitKind, HasObservers},
    observers::ObserversTuple,
    Error,
};

/// A [`ShadowExecutor`] wraps an executor and a set of shadow observers
pub struct ShadowExecutor<E: Debug, SOT: Debug> {
    /// The wrapped executor
    executor: E,
    /// The shadow observers
    shadow_observers: SOT,
}

impl<E: Debug, SOT: Debug> Debug for ShadowExecutor<E, SOT> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShadowExecutor")
            .field("executor", &self.executor)
            .field("shadow_observers", &self.shadow_observers)
            .finish()
    }
}

impl<E: Debug, SOT: Debug> ShadowExecutor<E, SOT>
where
    SOT: ObserversTuple,
{
    /// Create a new `ShadowExecutor`, wrapping the given `executor`.
    pub fn new(executor: E, shadow_observers: SOT) -> Self {
        Self {
            executor,
            shadow_observers,
        }
    }

    /// The shadow observers are not considered by the feedbacks and the manager, mutable
    #[inline]
    pub fn shadow_observers(&self) -> &SOT {
        &self.shadow_observers
    }

    /// The shadow observers are not considered by the feedbacks and the manager, mutable
    #[inline]
    pub fn shadow_observers_mut(&mut self) -> &mut SOT {
        &mut self.shadow_observers
    }
}

impl<E, SOT> Executor for ShadowExecutor<E, SOT>
where
    E: Executor,
    SOT: ObserversTuple,
{
    fn run_target(
        &mut self,
        fuzzer: &mut Self::Fuzzer,
        state: &mut Self::State,
        mgr: &mut Self::EventManager,
        input: &Self::Input,
    ) -> Result<ExitKind, Error> {
        self.executor.run_target(fuzzer, state, mgr, input)
    }
}

impl<E, SOT> HasObservers for ShadowExecutor<E, SOT>
where
    E: HasObservers,
    SOT: ObserversTuple,
{
    #[inline]
    fn observers(&self) -> &Self::Observers {
        self.executor.observers()
    }

    #[inline]
    fn observers_mut(&mut self) -> &mut Self::Observers {
        self.executor.observers_mut()
    }
}
