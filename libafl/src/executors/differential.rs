//! Executor for differential fuzzing.
//!
//! It wraps two executors that will be run after each other with the same input.
//! In comparison to the [`crate::executors::CombinedExecutor`] it also runs the secondary executor in `run_target`.
//!
use core::{
    cell::UnsafeCell,
    fmt::Debug,
    ops::{Deref, DerefMut},
    ptr,
};

use libafl_bolts::{
    ownedref::OwnedMutPtr,
    tuples::{MatchName, RefIndexable},
};
use serde::{Deserialize, Serialize};

use super::HasTimeout;
use crate::{
    corpus::Corpus,
    executors::{Executor, ExitKind, HasObservers},
    inputs::UsesInput,
    observers::{DifferentialObserversTuple, ObserversTuple},
    state::{HasCorpus, UsesState},
    Error,
};

/// A [`DiffExecutor`] wraps a primary executor, forwarding its methods, and a secondary one
#[derive(Debug)]
pub struct DiffExecutor<A, B, DOT, OTA, OTB> {
    primary: A,
    secondary: B,
    observers: UnsafeCell<ProxyObserversTuple<OTA, OTB, DOT>>,
}

impl<A, B, DOT, OTA, OTB> DiffExecutor<A, B, DOT, OTA, OTB> {
    /// Create a new `DiffExecutor`, wrapping the given `executor`s.
    pub fn new(primary: A, secondary: B, observers: DOT) -> Self
    where
        A: UsesState + HasObservers<Observers = OTA>,
        B: UsesState<State = <Self as UsesState>::State> + HasObservers<Observers = OTB>,
        DOT: DifferentialObserversTuple<OTA, OTB, A::Input, A::State>,
    {
        Self {
            primary,
            secondary,
            observers: UnsafeCell::new(ProxyObserversTuple {
                primary: OwnedMutPtr::Ptr(ptr::null_mut()),
                secondary: OwnedMutPtr::Ptr(ptr::null_mut()),
                differential: observers,
            }),
        }
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

impl<A, B, DOT, EM, Z> Executor<EM, Z> for DiffExecutor<A, B, DOT, A::Observers, B::Observers>
where
    A: Executor<EM, Z> + HasObservers,
    B: Executor<EM, Z, State = <Self as UsesState>::State> + HasObservers,
    EM: UsesState<State = <Self as UsesState>::State>,
    <A as HasObservers>::Observers:
        ObserversTuple<<<A as UsesState>::State as UsesInput>::Input, <A as UsesState>::State>,
    <B as HasObservers>::Observers:
        ObserversTuple<<<A as UsesState>::State as UsesInput>::Input, <A as UsesState>::State>,
    DOT: DifferentialObserversTuple<A::Observers, B::Observers, A::Input, A::State> + MatchName,
    Z: UsesState<State = <Self as UsesState>::State>,
{
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut Self::State,
        mgr: &mut EM,
        input: &Self::Input,
    ) -> Result<ExitKind, Error> {
        self.observers(); // update in advance
        let observers = self.observers.get_mut();
        observers
            .differential
            .pre_observe_first_all(observers.primary.as_mut())?;
        observers.primary.as_mut().pre_exec_all(state, input)?;
        let ret1 = self.primary.run_target(fuzzer, state, mgr, input)?;
        observers
            .primary
            .as_mut()
            .post_exec_all(state, input, &ret1)?;
        observers
            .differential
            .post_observe_first_all(observers.primary.as_mut())?;
        observers
            .differential
            .pre_observe_second_all(observers.secondary.as_mut())?;
        observers.secondary.as_mut().pre_exec_all(state, input)?;
        let ret2 = self.secondary.run_target(fuzzer, state, mgr, input)?;
        observers
            .secondary
            .as_mut()
            .post_exec_all(state, input, &ret2)?;
        observers
            .differential
            .post_observe_second_all(observers.secondary.as_mut())?;
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

impl<A, B, DOT, OTA, OTB> HasTimeout for DiffExecutor<A, B, DOT, OTA, OTB>
where
    A: HasTimeout,
    B: HasTimeout,
{
    #[inline]
    fn set_timeout(&mut self, timeout: core::time::Duration) {
        self.primary.set_timeout(timeout);
        self.secondary.set_timeout(timeout);
    }

    #[inline]
    fn timeout(&self) -> core::time::Duration {
        assert!(
            self.primary.timeout() == self.secondary.timeout(),
            "Primary and Secondary Executors have different timeouts!"
        );
        self.primary.timeout()
    }
}

/// Proxy the observers of the inner executors
#[derive(Serialize, Deserialize, Debug)]
#[serde(
    bound = "A: serde::Serialize + serde::de::DeserializeOwned, B: serde::Serialize + serde::de::DeserializeOwned, DOT: serde::Serialize + serde::de::DeserializeOwned"
)]
pub struct ProxyObserversTuple<A, B, DOT> {
    primary: OwnedMutPtr<A>,
    secondary: OwnedMutPtr<B>,
    differential: DOT,
}

impl<A, B, DOT, I, S> ObserversTuple<I, S> for ProxyObserversTuple<A, B, DOT>
where
    A: ObserversTuple<I, S>,
    B: ObserversTuple<I, S>,
    DOT: DifferentialObserversTuple<A, B, I, S> + MatchName,
    S: HasCorpus,
    S::Corpus: Corpus<Input = I>,
{
    fn pre_exec_all(&mut self, state: &mut S, input: &I) -> Result<(), Error> {
        self.differential.pre_exec_all(state, input)
    }

    fn post_exec_all(
        &mut self,
        state: &mut S,
        input: &I,
        exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        self.differential.post_exec_all(state, input, exit_kind)
    }

    fn pre_exec_child_all(&mut self, state: &mut S, input: &I) -> Result<(), Error> {
        self.differential.pre_exec_child_all(state, input)
    }

    fn post_exec_child_all(
        &mut self,
        state: &mut S,
        input: &I,
        exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        self.differential
            .post_exec_child_all(state, input, exit_kind)
    }
}

impl<A, B, DOT> Deref for ProxyObserversTuple<A, B, DOT> {
    type Target = DOT;

    fn deref(&self) -> &Self::Target {
        &self.differential
    }
}

impl<A, B, DOT> DerefMut for ProxyObserversTuple<A, B, DOT> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.differential
    }
}

impl<A, B, DOT> MatchName for ProxyObserversTuple<A, B, DOT>
where
    A: MatchName,
    B: MatchName,
    DOT: MatchName,
{
    #[allow(deprecated)]
    fn match_name<T>(&self, name: &str) -> Option<&T> {
        if let Some(t) = self.primary.as_ref().match_name::<T>(name) {
            Some(t)
        } else if let Some(t) = self.secondary.as_ref().match_name::<T>(name) {
            Some(t)
        } else {
            self.differential.match_name::<T>(name)
        }
    }

    #[allow(deprecated)]
    fn match_name_mut<T>(&mut self, name: &str) -> Option<&mut T> {
        if let Some(t) = self.primary.as_mut().match_name_mut::<T>(name) {
            Some(t)
        } else if let Some(t) = self.secondary.as_mut().match_name_mut::<T>(name) {
            Some(t)
        } else {
            self.differential.match_name_mut::<T>(name)
        }
    }
}

impl<A, B, DOT> ProxyObserversTuple<A, B, DOT> {
    fn set(&mut self, primary: &A, secondary: &B) {
        self.primary = OwnedMutPtr::Ptr(ptr::from_ref(primary).cast_mut());
        self.secondary = OwnedMutPtr::Ptr(ptr::from_ref(secondary).cast_mut());
    }
}

impl<A, B, DOT, OTA, OTB> UsesState for DiffExecutor<A, B, DOT, OTA, OTB>
where
    A: UsesState,
{
    type State = A::State;
}

impl<A, B, DOT, OTA, OTB> HasObservers for DiffExecutor<A, B, DOT, OTA, OTB>
where
    A: UsesState + HasObservers<Observers = OTA>,
    B: UsesState<State = <Self as UsesState>::State> + HasObservers<Observers = OTB>,
    DOT: DifferentialObserversTuple<OTA, OTB, A::Input, A::State> + MatchName,
    OTA: ObserversTuple<<Self as UsesInput>::Input, <Self as UsesState>::State>,
    OTB: ObserversTuple<<Self as UsesInput>::Input, <Self as UsesState>::State>,
{
    type Observers = ProxyObserversTuple<OTA, OTB, DOT>;

    #[inline]
    fn observers(&self) -> RefIndexable<&Self::Observers, Self::Observers> {
        unsafe {
            self.observers
                .get()
                .as_mut()
                .unwrap()
                .set(&*self.primary.observers(), &*self.secondary.observers());
            RefIndexable::from(self.observers.get().as_ref().unwrap())
        }
    }

    #[inline]
    fn observers_mut(&mut self) -> RefIndexable<&mut Self::Observers, Self::Observers> {
        unsafe {
            self.observers.get().as_mut().unwrap().set(
                &*self.primary.observers_mut(),
                &*self.secondary.observers_mut(),
            );
            RefIndexable::from(self.observers.get().as_mut().unwrap())
        }
    }
}
