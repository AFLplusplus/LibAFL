//! A wrapper for any [`Executor`] to make it implement [`HasObservers`] using a given [`ObserversTuple`].

use core::fmt::Debug;

use crate::{
    executors::{Executor, ExitKind, HasObservers},
    inputs::Input,
    observers::ObserversTuple,
    Error,
};

/// A wrapper for any [`Executor`] to make it implement [`HasObservers`] using a given [`ObserversTuple`].
#[derive(Debug)]
pub struct WithObservers<E: Debug, OT: Debug> {
    executor: E,
    observers: OT,
}

impl<E, EM, I, OT, S, Z> Executor<EM, I, S, Z> for WithObservers<E, OT>
where
    I: Input,
    E: Executor<EM, I, S, Z>,
    OT: Debug,
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

impl<I, E: Debug, OT: Debug, S> HasObservers<I, OT, S> for WithObservers<E, OT>
where
    I: Input,
    OT: ObserversTuple<I, S>,
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
