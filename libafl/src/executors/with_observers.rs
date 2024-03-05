//! A wrapper for any [`Executor`] to make it implement [`HasObservers`] using a given [`ObserversTuple`].

use core::fmt::Debug;

use crate::{
    executors::{Executor, ExitKind, HasObservers},
    observers::{ObserversTuple, UsesObservers},
    state::UsesState,
    Error,
};

/// A wrapper for any [`Executor`] to make it implement [`HasObservers`] using a given [`ObserversTuple`].
#[derive(Debug)]
pub struct WithObservers<E, OT> {
    executor: E,
    observers: OT,
}

impl<E, EM, OT, Z> Executor<EM, Z> for WithObservers<E, OT>
where
    E: Executor<EM, Z>,
    EM: UsesState<State = E::State>,
    Z: UsesState<State = E::State>,
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

impl<E, OT> UsesState for WithObservers<E, OT>
where
    E: UsesState,
{
    type State = E::State;
}

impl<E, OT> UsesObservers for WithObservers<E, OT>
where
    E: UsesState,
    OT: ObserversTuple<E::State>,
{
    type Observers = OT;
}

impl<E, OT> HasObservers for WithObservers<E, OT>
where
    E: UsesState,
    OT: ObserversTuple<E::State>,
{
    fn observers(&self) -> &OT {
        &self.observers
    }

    fn observers_mut(&mut self) -> &mut OT {
        &mut self.observers
    }
}

impl<E, OT> WithObservers<E, OT> {
    /// Wraps the given [`Executor`] with the given [`ObserversTuple`] to implement [`HasObservers`].
    ///
    /// If the executor already implements [`HasObservers`], then the original implementation will be overshadowed by
    /// the implementation of this wrapper.
    pub fn new(executor: E, observers: OT) -> Self {
        Self {
            executor,
            observers,
        }
    }
}
