//! A `CombinedExecutor` wraps a primary executor and a secondary one
//! In comparison to the [`crate::executors::DiffExecutor`] it does not run the secondary executor in `run_target`.

use core::fmt::Debug;

use crate::{
    executors::{Executor, ExitKind, HasObservers},
    state::State,
    Error,
};

/// A [`CombinedExecutor`] wraps a primary executor, forwarding its methods, and a secondary one
#[derive(Debug)]
pub struct CombinedExecutor<A: Debug, B: Debug> {
    primary: A,
    secondary: B,
}

impl<A: Debug, B: Debug> CombinedExecutor<A, B> {
    /// Create a new `CombinedExecutor`, wrapping the given `executor`s.
    pub fn new<EM, S, Z>(primary: A, secondary: B) -> Self
    where
        A: Executor<EM, S, Z>,
        B: Executor<EM, S, Z>,
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

impl<A, B, EM, S, Z> Executor<EM, S, Z> for CombinedExecutor<A, B>
where
    A: Executor<EM, S, Z>,
    B: Executor<EM, S, Z>,
    S: State,
    Z: Sized,
{
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &S::Input,
    ) -> Result<ExitKind, Error> {
        let ret = self.primary.run_target(fuzzer, state, mgr, input);
        self.primary.post_run_reset();
        self.secondary.post_run_reset();
        ret
    }
}

impl<A, B> HasObservers for CombinedExecutor<A, B>
where
    A: HasObservers,
    B: Debug,
{
    type State = A::State;
    type Observers = A::Observers;

    #[inline]
    fn observers(&self) -> &Self::Observers {
        self.primary.observers()
    }

    #[inline]
    fn observers_mut(&mut self) -> &mut Self::Observers {
        self.primary.observers_mut()
    }
}
