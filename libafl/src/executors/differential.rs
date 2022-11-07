//! Executor for differential fuzzing.
//! It wraps two executors that will be run after each other with the same input.
//! In comparison to the [`crate::executors::CombinedExecutor`] it also runs the secondary executor in `run_target`.
//!
use core::{cell::UnsafeCell, fmt::Debug};

use serde::{Deserialize, Serialize};

use crate::{
    bolts::{ownedref::OwnedPtrMut, tuples::MatchName},
    executors::{Executor, ExitKind, HasObservers},
    inputs::UsesInput,
    observers::{ObserversTuple, UsesObservers},
    state::UsesState,
    Error,
};

/// A [`DiffExecutor`] wraps a primary executor, forwarding its methods, and a secondary one
#[derive(Debug)]
pub struct DiffExecutor<A, B, OTA, OTB> {
    primary: A,
    secondary: B,
    observers: UnsafeCell<ProxyObserversTuple<OTA, OTB>>,
}

impl<A, B, OTA, OTB> DiffExecutor<A, B, OTA, OTB> {
    /// Create a new `DiffExecutor`, wrapping the given `executor`s.
    pub fn new<EM, Z>(primary: A, secondary: B) -> Self
    where
        A: Executor<EM, Z>,
        B: Executor<EM, Z, State = A::State>,
        EM: UsesState<State = A::State>,
        Z: UsesState<State = A::State>,
    {
        Self {
            primary,
            secondary,
            observers: UnsafeCell::new(ProxyObserversTuple {
                primary: OwnedPtrMut::Ptr(core::ptr::null_mut()),
                secondary: OwnedPtrMut::Ptr(core::ptr::null_mut()),
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

impl<A, B, EM, OTA, OTB, Z> Executor<EM, Z> for DiffExecutor<A, B, OTA, OTB>
where
    A: Executor<EM, Z>,
    B: Executor<EM, Z, State = A::State>,
    EM: UsesState<State = A::State>,
    OTA: Debug,
    OTB: Debug,
    Z: UsesState<State = A::State>,
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

/// Proxy the observers of the inner executors
#[derive(Serialize, Deserialize, Debug)]
#[serde(
    bound = "A: serde::Serialize + serde::de::DeserializeOwned, B: serde::Serialize + serde::de::DeserializeOwned"
)]
pub struct ProxyObserversTuple<A, B> {
    primary: OwnedPtrMut<A>,
    secondary: OwnedPtrMut<B>,
}

impl<A, B, S> ObserversTuple<S> for ProxyObserversTuple<A, B>
where
    A: ObserversTuple<S>,
    B: ObserversTuple<S>,
    S: UsesInput,
{
    fn pre_exec_all(&mut self, state: &mut S, input: &S::Input) -> Result<(), Error> {
        self.primary.as_mut().pre_exec_all(state, input)?;
        self.secondary.as_mut().pre_exec_all(state, input)
    }

    fn post_exec_all(
        &mut self,
        state: &mut S,
        input: &S::Input,
        exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        self.primary
            .as_mut()
            .post_exec_all(state, input, exit_kind)?;
        self.secondary
            .as_mut()
            .post_exec_all(state, input, exit_kind)
    }

    fn pre_exec_child_all(&mut self, state: &mut S, input: &S::Input) -> Result<(), Error> {
        self.primary.as_mut().pre_exec_child_all(state, input)?;
        self.secondary.as_mut().pre_exec_child_all(state, input)
    }

    fn post_exec_child_all(
        &mut self,
        state: &mut S,
        input: &S::Input,
        exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        self.primary
            .as_mut()
            .post_exec_child_all(state, input, exit_kind)?;
        self.secondary
            .as_mut()
            .post_exec_child_all(state, input, exit_kind)
    }

    /// Returns true if a `stdout` observer was added to the list
    #[inline]
    fn observes_stdout(&self) -> bool {
        self.primary.as_ref().observes_stdout() || self.secondary.as_ref().observes_stdout()
    }
    /// Returns true if a `stderr` observer was added to the list
    #[inline]
    fn observes_stderr(&self) -> bool {
        self.primary.as_ref().observes_stderr() || self.secondary.as_ref().observes_stderr()
    }

    /// Runs `observe_stdout` for all stdout observers in the list
    fn observe_stdout(&mut self, stdout: &str) {
        self.primary.as_mut().observe_stderr(stdout);
        self.secondary.as_mut().observe_stderr(stdout);
    }

    /// Runs `observe_stderr` for all stderr observers in the list
    fn observe_stderr(&mut self, stderr: &str) {
        self.primary.as_mut().observe_stderr(stderr);
        self.secondary.as_mut().observe_stderr(stderr);
    }
}

impl<A, B> MatchName for ProxyObserversTuple<A, B>
where
    A: MatchName,
    B: MatchName,
{
    fn match_name<T>(&self, name: &str) -> Option<&T> {
        if let Some(t) = self.primary.as_ref().match_name::<T>(name) {
            return Some(t);
        }
        self.secondary.as_ref().match_name::<T>(name)
    }
    fn match_name_mut<T>(&mut self, name: &str) -> Option<&mut T> {
        if let Some(t) = self.primary.as_mut().match_name_mut::<T>(name) {
            return Some(t);
        }
        self.secondary.as_mut().match_name_mut::<T>(name)
    }
}

impl<A, B> ProxyObserversTuple<A, B> {
    fn set(&mut self, primary: &A, secondary: &B) {
        self.primary = OwnedPtrMut::Ptr(primary as *const A as *mut A);
        self.secondary = OwnedPtrMut::Ptr(secondary as *const B as *mut B);
    }
}

impl<A, B, OTA, OTB> UsesObservers for DiffExecutor<A, B, OTA, OTB>
where
    A: HasObservers<Observers = OTA>,
    B: HasObservers<Observers = OTB, State = A::State>,
    OTA: ObserversTuple<A::State>,
    OTB: ObserversTuple<A::State>,
{
    type Observers = ProxyObserversTuple<OTA, OTB>;
}

impl<A, B, OTA, OTB> UsesState for DiffExecutor<A, B, OTA, OTB>
where
    A: UsesState,
    B: UsesState<State = A::State>,
{
    type State = A::State;
}

impl<A, B, OTA, OTB> HasObservers for DiffExecutor<A, B, OTA, OTB>
where
    A: HasObservers<Observers = OTA>,
    B: HasObservers<Observers = OTB, State = A::State>,
    OTA: ObserversTuple<A::State>,
    OTB: ObserversTuple<A::State>,
{
    #[inline]
    fn observers(&self) -> &ProxyObserversTuple<OTA, OTB> {
        unsafe {
            self.observers
                .get()
                .as_mut()
                .unwrap()
                .set(self.primary.observers(), self.secondary.observers());
            self.observers.get().as_ref().unwrap()
        }
    }

    #[inline]
    fn observers_mut(&mut self) -> &mut ProxyObserversTuple<OTA, OTB> {
        unsafe {
            self.observers
                .get()
                .as_mut()
                .unwrap()
                .set(self.primary.observers(), self.secondary.observers());
            self.observers.get().as_mut().unwrap()
        }
    }
}
