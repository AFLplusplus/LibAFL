//! A wrapper for any [`Executor`] to make it implement [`HasObservers`] using a given [`ObserversTuple`].

use core::fmt::Debug;

use crate::{
    executors::{Executor, ExitKind, HasObservers},
    observers::ObserversTuple,
    state::State,
    Error,
};

/// A wrapper for any [`Executor`] to make it implement [`HasObservers`] using a given [`ObserversTuple`].
#[derive(Debug)]
pub struct WithObservers<E: Debug, OT: Debug> {
    executor: E,
    observers: OT,
}

impl<E, EM, OT, S, Z> Executor<EM, S, Z> for WithObservers<E, OT>
where
    E: Executor<EM, S, Z> + Debug,
    OT: Debug,
    S: State,
    Z: Sized,
{
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &S::Input,
    ) -> Result<ExitKind, Error> {
        self.executor.run_target(fuzzer, state, mgr, input)
    }
}

impl<E, OT> HasObservers for WithObservers<E, OT>
where
    E: HasObservers + Debug,
    OT: ObserversTuple<E::State> + Debug,
{
    type State = E::State;
    type Observers = OT;

    fn observers(&self) -> &OT {
        &self.observers
    }

    fn observers_mut(&mut self) -> &mut OT {
        &mut self.observers
    }
}

impl<E: Debug, OT: Debug> WithObservers<E, OT> {
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
