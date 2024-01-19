//! A `CombinedExecutor` wraps a primary executor and a secondary one
//! In comparison to the [`crate::executors::DiffExecutor`] it does not run the secondary executor in `run_target`.

use core::fmt::Debug;

use crate::{
    executors::{Executor, ExitKind, HasObservers},
    observers::UsesObservers,
    state::{HasExecutions, UsesState},
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
    pub fn new<EM, Z>(primary: A, secondary: B) -> Self
    where
        A: Executor<EM, Z>,
        B: Executor<EM, Z, State = A::State>,
        EM: UsesState<State = A::State>,
        Z: UsesState<State = A::State>,
    {
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

impl<A, B, EM, Z> Executor<EM, Z> for CombinedExecutor<A, B>
where
    A: Executor<EM, Z>,
    B: Executor<EM, Z, State = A::State>,
    EM: UsesState<State = A::State>,
    EM::State: HasExecutions,
    Z: UsesState<State = A::State>,
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

impl<A, B> UsesState for CombinedExecutor<A, B>
where
    A: UsesState,
{
    type State = A::State;
}

impl<A, B> UsesObservers for CombinedExecutor<A, B>
where
    A: UsesObservers,
{
    type Observers = A::Observers;
}

impl<A, B> HasObservers for CombinedExecutor<A, B>
where
    A: HasObservers,
{
    #[inline]
    fn observers(&self) -> &Self::Observers {
        self.primary.observers()
    }

    #[inline]
    fn observers_mut(&mut self) -> &mut Self::Observers {
        self.primary.observers_mut()
    }
}
