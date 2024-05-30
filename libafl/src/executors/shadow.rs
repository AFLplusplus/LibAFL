//! A `ShadowExecutor` wraps an executor to have shadow observer that will not be considered by the feedbacks and the manager

use core::fmt::{self, Debug, Formatter};

use libafl_bolts::tuples::RefIndexable;

use crate::{
    executors::{Executor, ExitKind, HasObservers},
    observers::{ObserversTuple, UsesObservers},
    state::UsesState,
    Error,
};

/// A [`ShadowExecutor`] wraps an executor and a set of shadow observers
pub struct ShadowExecutor<E, SOT> {
    /// The wrapped executor
    executor: E,
    /// The shadow observers
    shadow_observers: SOT,
}

impl<E, SOT> Debug for ShadowExecutor<E, SOT>
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

impl<E, SOT> ShadowExecutor<E, SOT>
where
    E: HasObservers,
    SOT: ObserversTuple<<Self as UsesState>::State>,
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
    pub fn shadow_observers(&self) -> RefIndexable<&SOT, SOT> {
        RefIndexable::from(&self.shadow_observers)
    }

    /// The shadow observers are not considered by the feedbacks and the manager, mutable
    #[inline]
    pub fn shadow_observers_mut(&mut self) -> RefIndexable<&mut SOT, SOT> {
        RefIndexable::from(&mut self.shadow_observers)
    }
}

impl<E, EM, SOT, Z> Executor<EM, Z> for ShadowExecutor<E, SOT>
where
    E: Executor<EM, Z> + HasObservers,
    SOT: ObserversTuple<Self::State>,
    EM: UsesState<State = Self::State>,
    Z: UsesState<State = Self::State>,
{
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut Self::State,
        mgr: &mut EM,
        input: &Self::Input,
    ) -> Result<ExitKind, Error> {
        self.executor.run_target(fuzzer, state, mgr, input)
    }
}

impl<E, SOT> UsesState for ShadowExecutor<E, SOT>
where
    E: UsesState,
{
    type State = E::State;
}

impl<E, SOT> UsesObservers for ShadowExecutor<E, SOT>
where
    E: UsesObservers,
{
    type Observers = E::Observers;
}

impl<E, SOT> HasObservers for ShadowExecutor<E, SOT>
where
    E: HasObservers,
    SOT: ObserversTuple<Self::State>,
{
    #[inline]
    fn observers(&self) -> RefIndexable<&Self::Observers, Self::Observers> {
        self.executor.observers()
    }

    #[inline]
    fn observers_mut(&mut self) -> RefIndexable<&mut Self::Observers, Self::Observers> {
        self.executor.observers_mut()
    }
}
