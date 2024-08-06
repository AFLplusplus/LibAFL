//! A wrapper for any [`Executor`] to make it implement [`HasObservers`] using a given [`ObserversTuple`].

use core::{
    fmt::Debug,
    ops::{Deref, DerefMut},
};

use libafl_bolts::tuples::RefIndexable;

use crate::executors::HasObservers;

/// A wrapper for any [`Executor`] to make it implement [`HasObservers`] using a given [`ObserversTuple`].
#[derive(Debug)]
pub struct WithObservers<E, OT> {
    executor: E,
    observers: OT,
}

impl<E, OT> Deref for WithObservers<E, OT> {
    type Target = E;

    fn deref(&self) -> &Self::Target {
        &self.executor
    }
}

impl<E, OT> DerefMut for WithObservers<E, OT> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.executor
    }
}

impl<E, OT> HasObservers for WithObservers<E, OT> {
    type Observers = OT;

    fn observers(&self) -> RefIndexable<&Self::Observers, Self::Observers> {
        RefIndexable::from(&self.observers)
    }

    fn observers_mut(&mut self) -> RefIndexable<&mut Self::Observers, Self::Observers> {
        RefIndexable::from(&mut self.observers)
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
