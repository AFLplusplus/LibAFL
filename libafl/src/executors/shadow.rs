//! A `ShadowExecutor` wraps an executor to have shadow observer that will not be considered by the feedbacks and the manager

use core::{
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
};

use crate::{
    executors::{Executor, ExitKind, HasObservers},
    inputs::Input,
    observers::ObserversTuple,
    Error,
};

/// A [`ShadowExecutor`] wraps an executor and a set of shadow observers
pub struct ShadowExecutor<E: Debug, I: Debug, S, SOT: Debug> {
    /// The wrapped executor
    executor: E,
    /// The shadow observers
    shadow_observers: SOT,
    /// phantom data
    phantom: PhantomData<(I, S)>,
}

impl<E: Debug, I: Debug, S, SOT: Debug> Debug for ShadowExecutor<E, I, S, SOT> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShadowExecutor")
            .field("executor", &self.executor)
            .field("shadow_observers", &self.shadow_observers)
            .finish()
    }
}

impl<E: Debug, I: Debug, S, SOT: Debug> ShadowExecutor<E, I, S, SOT>
where
    SOT: ObserversTuple<I, S>,
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
    pub fn shadow_observers(&self) -> &SOT {
        &self.shadow_observers
    }

    /// The shadow observers are not considered by the feedbacks and the manager, mutable
    #[inline]
    pub fn shadow_observers_mut(&mut self) -> &mut SOT {
        &mut self.shadow_observers
    }
}

impl<E, EM, I, S, SOT, Z> Executor<EM, I, S, Z> for ShadowExecutor<E, I, S, SOT>
where
    E: Executor<EM, I, S, Z>,
    I: Input,
    SOT: ObserversTuple<I, S>,
{
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, Error> {
        self.executor.run_target(fuzzer, state, mgr, input)
    }
}

impl<E, I, OT, S, SOT> HasObservers<I, OT, S> for ShadowExecutor<E, I, S, SOT>
where
    I: Debug,
    S: Debug,
    E: HasObservers<I, OT, S>,
    OT: ObserversTuple<I, S>,
    SOT: ObserversTuple<I, S>,
{
    #[inline]
    fn observers(&self) -> &OT {
        self.executor.observers()
    }

    #[inline]
    fn observers_mut(&mut self) -> &mut OT {
        self.executor.observers_mut()
    }
}
