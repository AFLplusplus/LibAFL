//! A wrapper for any [`Executor`] to make it implement [`HasObservers`] using a given [`ObserversTuple`].

use core::fmt::Debug;

use crate::{
    executors::{Executor, ExitKind, HasObservers},
    observers::ObserversTuple,
    Error,
};

/// A wrapper for any [`Executor`] to make it implement [`HasObservers`] using a given [`ObserversTuple`].
#[derive(Debug)]
pub struct WithObservers<E: Debug, OT: Debug> {
    executor: E,
    observers: OT,
}

impl<E, OT> Executor for WithObservers<E, OT>
where
    E: Executor,
    OT: Debug,
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

impl<E: Debug, OT: Debug> HasObservers for WithObservers<E, OT>
where
    OT: ObserversTuple,
{
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
