//! Executor for differential fuzzing.
//! It wraps two executors that will be run after each other with the same input.
//! In comparison to the [`crate::executors::CombinedExecutor`] it also runs the secondary executor in `run_target`.
//!
use core::fmt::Debug;

use crate::{
    executors::{Executor, ExitKind, HasObservers},
    observers::KnowsObservers,
    state::KnowsState,
    Error,
};

/// A [`DiffExecutor`] wraps a primary executor, forwarding its methods, and a secondary one
#[derive(Debug)]
pub struct DiffExecutor<A, B> {
    primary: A,
    secondary: B,
}

impl<A, B> DiffExecutor<A, B> {
    /// Create a new `DiffExecutor`, wrapping the given `executor`s.
    pub fn new<EM, Z>(primary: A, secondary: B) -> Self
    where
        A: Executor<EM, Z>,
        B: Executor<EM, Z, State = A::State>,
        EM: KnowsState<State = A::State>,
        Z: KnowsState<State = A::State>,
    {
        Self { primary, secondary }
    }

    /// Retrieve the primary `Executor` that is wrapped by this `DiffExecutor`.
    pub fn primary(&mut self) -> &mut A {
        &mut self.primary
    }

    /// Retrieve the secondary `Executor` that is wrapped by this `DiffExecutor`.
    pub fn secondary(&mut self) -> &mut B {
        &mut self.secondary
    }
}

impl<A, B, EM, Z> Executor<EM, Z> for DiffExecutor<A, B>
where
    A: Executor<EM, Z>,
    B: Executor<EM, Z, State = A::State>,
    EM: KnowsState<State = A::State>,
    Z: KnowsState<State = A::State>,
{
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut Self::State,
        mgr: &mut EM,
        input: &Self::Input,
    ) -> Result<ExitKind, Error> {
        let ret1 = self.primary.run_target(fuzzer, state, mgr, input)?;
        self.primary.post_run_reset();
        let ret2 = self.secondary.run_target(fuzzer, state, mgr, input)?;
        self.secondary.post_run_reset();
        if ret1 == ret2 {
            Ok(ret1)
        } else {
            // We found a diff in the exit codes!
            Ok(ExitKind::Diff {
                primary: ret1.into(),
                secondary: ret2.into(),
            })
        }
    }
}

impl<A, B> KnowsState for DiffExecutor<A, B>
where
    A: KnowsState,
{
    type State = A::State;
}

impl<A, B> KnowsObservers for DiffExecutor<A, B>
where
    A: HasObservers,
{
    type Observers = A::Observers;
}

impl<A, B> HasObservers for DiffExecutor<A, B>
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
