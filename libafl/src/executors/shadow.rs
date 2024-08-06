//! A `ShadowExecutor` wraps an executor to have shadow observer that will not be considered by the feedbacks and the manager

use core::{
    fmt::Debug,
    ops::{Deref, DerefMut},
};

use libafl_bolts::tuples::RefIndexable;

/// A [`ShadowExecutor`] wraps an executor and a set of shadow observers
#[derive(Debug)]
pub struct ShadowExecutor<E, SOT> {
    /// The wrapped executor
    executor: E,
    /// The shadow observers
    shadow_observers: SOT,
}

impl<E, SOT> ShadowExecutor<E, SOT> {
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

impl<E, SOT> Deref for ShadowExecutor<E, SOT> {
    type Target = E;

    fn deref(&self) -> &Self::Target {
        &self.executor
    }
}

impl<E, SOT> DerefMut for ShadowExecutor<E, SOT> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.executor
    }
}
