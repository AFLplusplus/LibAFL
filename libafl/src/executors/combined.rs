//! A `CombinedExecutor` wraps a primary executor and a secondary one
//! In comparison to the [`crate::executors::DiffExecutor`] it does not run the secondary executor in `run_target`.

use crate::{
    executors::{Executor, ExitKind, HasObservers},
    inputs::Input,
    observers::ObserversTuple,
    Error,
};
use core::fmt::Debug;

/// A [`CombinedExecutor`] wraps a primary executor, forwarding its methods, and a secondary one
#[derive(Debug)]
pub struct CombinedExecutor<A: Debug, B: Debug> {
    primary: A,
    secondary: B,
}

impl<A: Debug, B: Debug> CombinedExecutor<A, B> {
    /// Create a new `CombinedExecutor`, wrapping the given `executor`s.
    pub fn new<EM, I, S, Z>(primary: A, secondary: B) -> Self
    where
        A: Executor<EM, I, S, Z>,
        B: Executor<EM, I, S, Z>,
        I: Input,
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

impl<A, B, EM, I, S, Z> Executor<EM, I, S, Z> for CombinedExecutor<A, B>
where
    A: Executor<EM, I, S, Z>,
    B: Executor<EM, I, S, Z>,
    I: Input,
{
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, Error> {
        let ret = self.primary.run_target(fuzzer, state, mgr, input);
        self.primary.post_run_reset();
        self.secondary.post_run_reset();
        ret
    }
}

impl<A, B, I, OT, S> HasObservers<I, OT, S> for CombinedExecutor<A, B>
where
    A: HasObservers<I, OT, S>,
    B: Debug,
    OT: ObserversTuple<I, S>,
{
    #[inline]
    fn observers(&self) -> &OT {
        self.primary.observers()
    }

    #[inline]
    fn observers_mut(&mut self) -> &mut OT {
        self.primary.observers_mut()
    }
}
