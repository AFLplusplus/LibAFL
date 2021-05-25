//! A `CombinedExecutor` wraps a primary executor and a secondary one

use core::marker::PhantomData;

use crate::{
    executors::{Executor, ExitKind, HasExecHooksTuple, HasObservers, HasObserversHooks},
    inputs::Input,
    observers::ObserversTuple,
    Error,
};

/// A [`CombinedExecutor`] wraps a primary executor, forwarding its methods, and a secondary one
pub struct CombinedExecutor<A, B, EM, I, S, Z>
where
    A: Executor<EM, I, S, Z>,
    B: Executor<EM, I, S, Z>,
    I: Input,
{
    primary: A,
    secondary: B,
    phantom: PhantomData<(EM, I, S, Z)>,
}

impl<A, B, EM, I, S, Z> CombinedExecutor<A, B, EM, I, S, Z>
where
    A: Executor<EM, I, S, Z>,
    B: Executor<EM, I, S, Z>,
    I: Input,
{
    /// Create a new `CombinedExecutor`, wrapping the given `executor`s.
    pub fn new(primary: A, secondary: B) -> Self {
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

impl<A, B, EM, I, S, Z> Executor<EM, I, S, Z> for CombinedExecutor<A, B, EM, I, S, Z>
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
        self.primary.run_target(fuzzer, state, mgr, input)
    }
}

impl<A, B, EM, I, OT, S, Z> HasObservers<OT> for CombinedExecutor<A, B, EM, I, S, Z>
where
    A: Executor<EM, I, S, Z> + HasObservers<OT>,
    B: Executor<EM, I, S, Z>,
    I: Input,
    OT: ObserversTuple,
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

impl<A, B, EM, I, OT, S, Z> HasObserversHooks<EM, I, OT, S, Z>
    for CombinedExecutor<A, B, EM, I, S, Z>
where
    A: Executor<EM, I, S, Z> + HasObservers<OT>,
    B: Executor<EM, I, S, Z>,
    I: Input,
    OT: ObserversTuple + HasExecHooksTuple<EM, I, S, Z>,
{
}
