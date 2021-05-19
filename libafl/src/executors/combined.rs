//! A `CombinedExecutor` wraps a primary executor and a secondary one

use core::marker::PhantomData;

use crate::{
    executors::{
        Executor, ExitKind, HasExecHooks, HasExecHooksTuple, HasObservers, HasObserversHooks,
    },
    inputs::Input,
    observers::ObserversTuple,
    Error,
};

/// A [`CombinedExecutor`] wraps a primary executor, forwarding its methods, and a secondary one

pub struct CombinedExecutor<A, B, I>
where
    A: Executor<I>,
    B: Executor<I>,
    I: Input,
{
    primary: A,
    secondary: B,
    phantom: PhantomData<I>,
}

impl<A, B, I> CombinedExecutor<A, B, I>
where
    A: Executor<I>,
    B: Executor<I>,
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

impl<A, B, I> Executor<I> for CombinedExecutor<A, B, I>
where
    A: Executor<I>,
    B: Executor<I>,
    I: Input,
{
    fn run_target(&mut self, input: &I) -> Result<ExitKind, Error> {
        self.primary.run_target(input)
    }
}

impl<A, B, I, OT> HasObservers<OT> for CombinedExecutor<A, B, I>
where
    A: Executor<I> + HasObservers<OT>,
    B: Executor<I>,
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

impl<A, B, EM, I, OT, S, Z> HasObserversHooks<EM, I, OT, S, Z> for CombinedExecutor<A, B, I>
where
    A: Executor<I> + HasObservers<OT>,
    B: Executor<I>,
    I: Input,
    OT: ObserversTuple + HasExecHooksTuple<EM, I, S, Z>,
{
}

impl<A, B, EM, I, S, Z> HasExecHooks<EM, I, S, Z> for CombinedExecutor<A, B, I>
where
    A: Executor<I> + HasExecHooks<EM, I, S, Z>,
    B: Executor<I>,
    I: Input,
{
    #[inline]
    fn pre_exec(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &I,
    ) -> Result<(), Error> {
        self.primary.pre_exec(fuzzer, state, mgr, input)
    }

    #[inline]
    fn post_exec(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &I,
    ) -> Result<(), Error> {
        self.primary.post_exec(fuzzer, state, mgr, input)
    }
}
