//! A `ShadowExecutor` wraps an executor to have shadow observer that will not be considered by the feedbacks and the manager

use crate::{
    executors::{Executor, ExitKind, HasExecHooksTuple, HasObservers, HasObserversHooks},
    inputs::Input,
    observers::ObserversTuple,
    Error,
};

pub trait HasShadowObserverHooks<EM, I, S, SOT, Z> {
    /// Run the pre exec hook for all the shadow [`crate::observers::Observer`]`s`
    fn pre_exec_shadow_observers(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &I,
    ) -> Result<(), Error>;

    /// Run the post exec hook for all the shadow [`crate::observers::Observer`]`s`
    fn post_exec_shadow_observers(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &I,
    ) -> Result<(), Error>;
}

/// A [`ShadowExecutor`] wraps an executor and a set of shadow observers
pub struct ShadowExecutor<E, SOT> {
    executor: E,
    shadow_observers: SOT,
    // Enable the execution of the shadow observers hooks with the regular observers hooks
    shadow_hooks: bool,
}

impl<E, SOT> ShadowExecutor<E, SOT>
where
    SOT: ObserversTuple,
{
    /// Create a new `ShadowExecutor`, wrapping the given `executor`.
    pub fn new(executor: E, shadow_observers: SOT) -> Self {
        Self {
            executor,
            shadow_observers,
            shadow_hooks: false,
        }
    }

    /// Create a new `ShadowExecutor`, wrapping the given `executor`.
    pub fn with_shadow_hooks<EM, I, S, Z>(
        executor: E,
        shadow_observers: SOT,
        shadow_hooks: bool,
    ) -> Self {
        Self {
            executor,
            shadow_observers,
            shadow_hooks,
        }
    }

    #[inline]
    pub fn shadow_observers(&self) -> &SOT {
        &self.shadow_observers
    }

    #[inline]
    pub fn shadow_observers_mut(&mut self) -> &mut SOT {
        &mut self.shadow_observers
    }

    pub fn shadow_hooks(&self) -> &bool {
        &self.shadow_hooks
    }

    pub fn shadow_hooks_mut(&mut self) -> &mut bool {
        &mut self.shadow_hooks
    }
}

impl<E, EM, I, S, SOT, Z> HasShadowObserverHooks<EM, I, S, SOT, Z> for ShadowExecutor<E, SOT>
where
    I: Input,
    SOT: ObserversTuple + HasExecHooksTuple<EM, I, S, Z>,
{
    #[inline]
    fn pre_exec_shadow_observers(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &I,
    ) -> Result<(), Error> {
        self.shadow_observers
            .pre_exec_all(fuzzer, state, mgr, input)
    }

    #[inline]
    fn post_exec_shadow_observers(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &I,
    ) -> Result<(), Error> {
        self.shadow_observers
            .post_exec_all(fuzzer, state, mgr, input)
    }
}

impl<E, EM, I, S, SOT, Z> Executor<EM, I, S, Z> for ShadowExecutor<E, SOT>
where
    E: Executor<EM, I, S, Z>,
    I: Input,
    SOT: ObserversTuple,
{
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, Error> {
        self.executor.run_target(fuzzer, state, mgr, input)
    }
}

impl<E, OT, SOT> HasObservers<OT> for ShadowExecutor<E, SOT>
where
    E: HasObservers<OT>,
    OT: ObserversTuple,
    SOT: ObserversTuple,
{
    #[inline]
    fn observers(&self) -> &OT {
        self.executor.observers()
    }

    #[inline]
    fn observers_mut(&mut self) -> &mut OT {
        self.executor.observers_mut()
    }
}

impl<E, EM, I, OT, S, SOT, Z> HasObserversHooks<EM, I, OT, S, Z> for ShadowExecutor<E, SOT>
where
    E: HasObservers<OT>,
    I: Input,
    OT: ObserversTuple + HasExecHooksTuple<EM, I, S, Z>,
    SOT: ObserversTuple + HasExecHooksTuple<EM, I, S, Z>,
{
    /// Run the pre exec hook for all [`crate::observers::Observer`]`s` linked to this [`Executor`].
    #[inline]
    fn pre_exec_observers(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &I,
    ) -> Result<(), Error> {
        if self.shadow_hooks {
            self.shadow_observers
                .pre_exec_all(fuzzer, state, mgr, input)?;
        }
        self.observers_mut().pre_exec_all(fuzzer, state, mgr, input)
    }

    /// Run the post exec hook for all the [`crate::observers::Observer`]`s` linked to this [`Executor`].
    #[inline]
    fn post_exec_observers(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &I,
    ) -> Result<(), Error> {
        if self.shadow_hooks {
            self.shadow_observers
                .post_exec_all(fuzzer, state, mgr, input)?;
        }
        self.observers_mut()
            .post_exec_all(fuzzer, state, mgr, input)
    }
}
