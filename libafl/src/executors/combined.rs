//! A `CombinedExecutor` wraps a primary executor and a secondary one
//! In comparison to the [`crate::executors::DiffExecutor`] it does not run the secondary executor in `run_target`.

use core::{fmt::Debug, marker::PhantomData};

use crate::{
    executors::{Executor, ExitKind, HasExecutorState, HasObservers},
    observers::UsesObservers,
    state::{HasExecutions, UsesState},
    Error,
};

/// A [`CombinedExecutor`] wraps a primary executor, forwarding its methods, and a secondary one
#[derive(Debug)]
pub struct CombinedExecutor<A, B, AES, BES> {
    primary: A,
    secondary: B,
    phantom: PhantomData<(AES, BES)>,
}

impl<A, B, AES, BES> CombinedExecutor<A, B, AES, BES> {
    /// Create a new `CombinedExecutor`, wrapping the given `executor`s.
    pub fn new<EM, Z>(primary: A, secondary: B) -> Self
    where
        A: Executor<EM, Z, AES>,
        B: Executor<EM, Z, BES, State = A::State>,
        EM: UsesState<State = A::State>,
        Z: UsesState<State = A::State>,
        AES: HasExecutorState,
        BES: HasExecutorState,
    {
        Self {
            primary,
            secondary,
            phantom: PhantomData,
        }
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

impl<A, B, EM, Z, AES, BES> Executor<EM, Z, AES> for CombinedExecutor<A, B, AES, BES>
where
    A: Executor<EM, Z, AES>,
    B: Executor<EM, Z, BES, State = A::State>,
    EM: UsesState<State = A::State>,
    EM::State: HasExecutions,
    Z: UsesState<State = A::State>,
    AES: HasExecutorState,
    BES: HasExecutorState,
{
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut Self::State,
        mgr: &mut EM,
        input: &Self::Input,
        executor_state: &mut AES::ExecutorState,
    ) -> Result<ExitKind, Error> {
        *state.executions_mut() += 1;

        self.primary
            .run_target(fuzzer, state, mgr, input, executor_state)
    }
}

impl<A, B, AES, BES> UsesState for CombinedExecutor<A, B, AES, BES>
where
    A: UsesState,
{
    type State = A::State;
}

impl<A, B, AES, BES> UsesObservers for CombinedExecutor<A, B, AES, BES>
where
    A: UsesObservers,
{
    type Observers = A::Observers;
}

impl<A, B, AES, BES> HasObservers for CombinedExecutor<A, B, AES, BES>
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
