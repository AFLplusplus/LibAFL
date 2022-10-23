//! Executor for differential fuzzing.
//! It wraps two exeutors that will be run after each other with the same input.
//! In comparison to the [`crate::executors::CombinedExecutor`] it also runs the secondary executor in `run_target`.
//!
use core::{cell::UnsafeCell, fmt::Debug};

use serde::{Deserialize, Serialize};

use crate::{
    bolts::{ownedref::OwnedPtrMut, tuples::MatchName},
    executors::{Executor, ExitKind, HasObservers},
    inputs::Input,
    observers::ObserversTuple,
    Error,
};

/// A [`DiffExecutor`] wraps a primary executor, forwarding its methods, and a secondary one
#[derive(Debug)]
pub struct DiffExecutor<A, B, OTA, OTB>
where
    A: Debug,
    B: Debug,
    OTA: Debug,
    OTB: Debug,
{
    primary: A,
    secondary: B,
    observers: UnsafeCell<ProxyObserversTuple<OTA, OTB>>,
}

impl<A, B, OTA, OTB> DiffExecutor<A, B, OTA, OTB>
where
    A: Debug,
    B: Debug,
    OTA: Debug,
    OTB: Debug,
{
    /// Create a new `DiffExecutor`, wrapping the given `executor`s.
    pub fn new<EM, I, S, Z>(primary: A, secondary: B) -> Self
    where
        A: Executor<EM, I, S, Z>,
        B: Executor<EM, I, S, Z>,
        I: Input,
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

impl<A, B, EM, I, OTA, OTB, S, Z> Executor<EM, I, S, Z> for DiffExecutor<A, B, OTA, OTB>
where
    A: Executor<EM, I, S, Z>,
    B: Executor<EM, I, S, Z>,
    I: Input,
    OTA: Debug,
    OTB: Debug,
{
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &I,
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

impl<A, B, I, S> ObserversTuple<I, S> for ProxyObserversTuple<A, B>
where
    A: ObserversTuple<I, S>,
    B: ObserversTuple<I, S>,
{
    fn pre_exec_all(&mut self, state: &mut S, input: &I) -> Result<(), Error> {
        self.primary.as_mut().pre_exec_all(state, input)?;
        self.secondary.as_mut().pre_exec_all(state, input)
    }

    fn post_exec_all(
        &mut self,
        state: &mut S,
        input: &I,
        exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        self.primary
            .as_mut()
            .post_exec_all(state, input, exit_kind)?;
        self.secondary
            .as_mut()
            .post_exec_all(state, input, exit_kind)
    }

    fn pre_exec_child_all(&mut self, state: &mut S, input: &I) -> Result<(), Error> {
        self.primary.as_mut().pre_exec_child_all(state, input)?;
        self.secondary.as_mut().pre_exec_child_all(state, input)
    }

    fn post_exec_child_all(
        &mut self,
        state: &mut S,
        input: &I,
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
    fn observes_stdout(&mut self) -> bool {
        self.primary.as_mut().observes_stdout() || self.secondary.as_mut().observes_stdout()
    }
    /// Returns true if a `stderr` observer was added to the list
    #[inline]
    fn observes_stderr(&mut self) -> bool {
        self.primary.as_mut().observes_stderr() || self.secondary.as_mut().observes_stderr()
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

impl<A, B, I, OTA, OTB, S> HasObservers<I, ProxyObserversTuple<OTA, OTB>, S>
    for DiffExecutor<A, B, OTA, OTB>
where
    A: HasObservers<I, OTA, S>,
    B: HasObservers<I, OTB, S>,
    OTA: ObserversTuple<I, S>,
    OTB: ObserversTuple<I, S>,
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
