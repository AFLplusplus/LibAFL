//! A `CombinedExecutor` wraps a primary executor and a secondary one
//! In comparison to the [`crate::executors::DiffExecutor`] it does not run the secondary executor in `run_target`.

use core::{
    fmt::Debug,
    ops::{Deref, DerefMut},
};

/// A [`CombinedExecutor`] wraps a primary executor, forwarding its methods, and a secondary one
#[derive(Debug)]
pub struct CombinedExecutor<A, B> {
    primary: A,
    secondary: B,
}

impl<A, B> CombinedExecutor<A, B> {
    /// Create a new `CombinedExecutor`, wrapping the given `executor`s.
    pub fn new(primary: A, secondary: B) -> Self {
        Self { primary, secondary }
    }

    /// Retrieve the primary `Executor` that is wrapped by this `CombinedExecutor`.
    pub fn primary(&self) -> &A {
        &self.primary
    }

    /// Retrieve the secondary `Executor` that is wrapped by this `CombinedExecutor`.
    pub fn secondary(&self) -> &B {
        &self.secondary
    }

    /// Retrieve, mutably, the primary `Executor` that is wrapped by this `CombinedExecutor`.
    pub fn primary_mut(&mut self) -> &mut A {
        &mut self.primary
    }

    /// Retrieve, mutably, the secondary `Executor` that is wrapped by this `CombinedExecutor`.
    pub fn secondary_mut(&mut self) -> &mut B {
        &mut self.secondary
    }
}

impl<A, B> Deref for CombinedExecutor<A, B> {
    type Target = A;

    fn deref(&self) -> &Self::Target {
        self.primary()
    }
}

impl<A, B> DerefMut for CombinedExecutor<A, B> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.primary_mut()
    }
}
