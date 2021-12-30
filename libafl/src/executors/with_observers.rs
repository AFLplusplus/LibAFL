//! A wrapper for any [`Executor`] to make it implement [`HasObservers`] using a given [`ObserversTuple`].
use crate::{inputs::Input, observers::ObserversTuple, Error};

use super::{Executor, ExitKind, HasObservers};

/// A wrapper for any [`Executor`] to make it implement [`HasObservers`] using a given [`ObserversTuple`].
#[allow(missing_debug_implementations)]
pub struct WithObservers<E, OT> {
    executor: E,
    observers: OT,
}

impl<EM, I, S, Z, E, OT> Executor<EM, I, S, Z> for WithObservers<E, OT>
where
    I: Input,
    E: Executor<EM, I, S, Z>,
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

impl<I, S, E, OT> HasObservers<I, OT, S> for WithObservers<E, OT>
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
