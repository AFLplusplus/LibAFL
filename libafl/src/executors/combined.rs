//! A `CombinedExecutor` wraps a primary executor and a secondary one
//! In comparison to the [`crate::executors::DiffExecutor`] it does not run the secondary executor in `run_target`.

use core::fmt::Debug;

use libafl_bolts::tuples::RefIndexable;

use crate::{
    executors::{Executor, ExitKind, HasObservers},
    state::HasExecutions,
    Error,
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
    pub fn primary(&mut self) -> &mut A {
        &mut self.primary
    }

    /// Retrieve the secondary `Executor` that is wrapped by this `CombinedExecutor`.
    pub fn secondary(&mut self) -> &mut B {
        &mut self.secondary
    }
}

impl<A, B, EM, I, S, Z> Executor<EM, I, S, Z> for CombinedExecutor<A, B>
where
    A: Executor<EM, I, S, Z>,
    B: Executor<EM, I, S, Z>,
    S: HasExecutions,
{
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut Self::State,
        mgr: &mut EM,
        input: &Self::Input,
    ) -> Result<ExitKind, Error> {
        *state.executions_mut() += 1;

        self.primary.run_target(fuzzer, state, mgr, input)
    }
}

impl<'a, A, B> HasObservers<'a> for CombinedExecutor<A, B>
where
    A: HasObservers<'a>,
{
    type Observers = A::Observers;
    type ObserversRef = A::ObserversRef;
    type ObserversRefMut = A::ObserversRefMut;

    #[inline]
    fn observers(&self) -> RefIndexable<Self::ObserversRef, Self::Observers> {
        self.primary.observers()
    }

    #[inline]
    fn observers_mut(&mut self) -> RefIndexable<Self::ObserversRefMut, Self::Observers> {
        self.primary.observers_mut()
    }
}
