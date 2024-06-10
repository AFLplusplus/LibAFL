//! Executor for differential fuzzing.
//! It wraps two executors that will be run after each other with the same input.
//! In comparison to the [`crate::executors::CombinedExecutor`] it also runs the secondary executor in `run_target`.

use core::{
    fmt::Debug,
    ops::{Deref, DerefMut},
};

use libafl_bolts::tuples::{MatchName, RefIndexable};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    executors::{Executor, ExitKind, HasObservers},
    observers::{DifferentialObserversTuple, ObserversTuple},
    Error,
};

/// A [`DiffExecutor`] wraps a primary executor, forwarding its methods, and a secondary one
#[derive(Debug)]
pub struct DiffExecutor<A, B, DOT> {
    primary: A,
    secondary: B,
    observers: DOT,
}

impl<A, B, DOT> DiffExecutor<A, B, DOT> {
    /// Create a new `DiffExecutor`, wrapping the given `executor`s.
    pub fn new(primary: A, secondary: B, observers: DOT) -> Self {
        Self {
            primary,
            secondary,
            observers,
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

// for<'a> is a bit gross, but necessary -- the lifetime isn't constrained by anything else!
impl<A, B, DOT, EM, I, S, Z> Executor<EM, I, S, Z> for DiffExecutor<A, B, DOT>
where
    A: Executor<EM, I, S, Z> + for<'a> HasObservers<'a>,
    B: Executor<EM, I, S, Z> + for<'a> HasObservers<'a>,
    for<'a> <A as HasObservers<'a>>::Observers: ObserversTuple<I, S>,
    for<'a> <B as HasObservers<'a>>::Observers: ObserversTuple<I, S>,
    for<'a> DOT: DifferentialObserversTuple<
        <A as HasObservers<'a>>::Observers,
        <B as HasObservers<'a>>::Observers,
    >,
{
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut Self::State,
        mgr: &mut EM,
        input: &Self::Input,
    ) -> Result<ExitKind, Error> {
        {
            let mut primary_obs = self.primary.observers_mut();
            self.observers
                .pre_observe_first_all(primary_obs.deref_mut())?;
            primary_obs.pre_exec_all(state, input)?;
        }
        let ret1 = self.primary.run_target(fuzzer, state, mgr, input)?;
        {
            let mut primary_obs = self.primary.observers_mut();
            primary_obs.post_exec_all(state, input, &ret1)?;
            self.observers
                .post_observe_first_all(primary_obs.deref_mut())?;
        }

        {
            let mut secondary_obs = self.secondary.observers_mut();
            self.observers
                .pre_observe_second_all(secondary_obs.deref_mut())?;
            secondary_obs.pre_exec_all(state, input)?;
        }
        let ret2 = self.secondary.run_target(fuzzer, state, mgr, input)?;
        {
            let mut secondary_obs = self.secondary.observers_mut();
            secondary_obs.post_exec_all(state, input, &ret2)?;
            self.observers
                .post_observe_second_all(secondary_obs.deref_mut())?;
        }
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
#[derive(Debug)]
pub enum ProxyObserversTuple<'a, A, B, DOT>
where
    A: HasObservers<'a>,
    B: HasObservers<'a>,
{
    Wrapped(&'a DiffExecutor<A, B, DOT>),
    WrappedMut(&'a mut DiffExecutor<A, B, DOT>),
    Owned(A::Observers, B::Observers, DOT),
}

impl<'a, A, B, DOT> Serialize for ProxyObserversTuple<'a, A, B, DOT>
where
    A: HasObservers<'a>,
    B: HasObservers<'a>,
    A::Observers: Serialize,
    B::Observers: Serialize,
    DOT: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let serializable = match self {
            ProxyObserversTuple::Wrapped(exec) => (
                exec.primary.observers().deref(),
                exec.secondary.observers().deref(),
                &exec.observers,
            ),
            ProxyObserversTuple::WrappedMut(exec) => (
                exec.primary.observers().deref(),
                exec.secondary.observers().deref(),
                &exec.observers,
            ),
            ProxyObserversTuple::Owned(a, b, dot) => (a, b, dot),
        };
        serializable.serialize(serializer)
    }
}

impl<'a, 'de, A, B, DOT> Deserialize<'de> for ProxyObserversTuple<'a, A, B, DOT>
where
    A: HasObservers<'a>,
    B: HasObservers<'a>,
    A::Observers: Deserialize<'de>,
    B::Observers: Deserialize<'de>,
    DOT: Deserialize<'de>,
{
    fn deserialize<D>(de: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let deser: (A::Observers, B::Observers, DOT) = Deserialize::deserialize(de)?;
        Ok(ProxyObserversTuple::Owned(deser.0, deser.1, deser.2))
    }
}

#[allow(deprecated)]
fn match_name_ref<'a, T, A, B, DOT>(exec: &'a DiffExecutor<A, B, DOT>, name: &str) -> Option<&'a T>
where
    A: HasObservers<'a>,
    B: HasObservers<'a>,
    DOT: MatchName,
{
    if let Some(t) = exec.primary.observers().match_name::<T>(name) {
        Some(t)
    } else if let Some(t) = exec.secondary.observers().match_name::<T>(name) {
        Some(t)
    } else {
        exec.observers.match_name::<T>(name)
    }
}

impl<'a, A, B, DOT> MatchName for ProxyObserversTuple<'a, A, B, DOT>
where
    A: HasObservers<'a>,
    B: HasObservers<'a>,
    DOT: MatchName,
{
    #[allow(deprecated)]
    fn match_name<T>(&self, name: &str) -> Option<&T> {
        match self {
            ProxyObserversTuple::Wrapped(exec) => match_name_ref(exec.as_ref(), name),
            ProxyObserversTuple::WrappedMut(exec) => match_name_ref(exec.as_ref(), name),
            ProxyObserversTuple::Owned(primary, secondary, observers) => {
                if let Some(t) = primary.match_name::<T>(name) {
                    Some(t)
                } else if let Some(t) = secondary.match_name::<T>(name) {
                    Some(t)
                } else {
                    observers.match_name::<T>(name)
                }
            }
        }
    }

    #[allow(deprecated)]
    fn match_name_mut<T>(&mut self, name: &str) -> Option<&mut T> {
        match self {
            ProxyObserversTuple::Wrapped(_) => {
                unimplemented!("This should never happen! We should never hold a mutable ProxyObserversTuple::Wrapped");
            }
            ProxyObserversTuple::WrappedMut(exec) => {
                let exec = exec.as_mut();
                if let Some(t) = exec.primary.observers_mut().match_name_mut::<T>(name) {
                    Some(t)
                } else if let Some(t) = exec.secondary.observers_mut().match_name_mut::<T>(name) {
                    Some(t)
                } else {
                    exec.observers.match_name_mut::<T>(name)
                }
            }
            ProxyObserversTuple::Owned(primary, secondary, observers) => {
                if let Some(t) = primary.match_name_mut::<T>(name) {
                    Some(t)
                } else if let Some(t) = secondary.match_name_mut::<T>(name) {
                    Some(t)
                } else {
                    observers.match_name_mut::<T>(name)
                }
            }
        }
    }
}

impl<'a, A, B, DOT, I, S> ObserversTuple<I, S> for ProxyObserversTuple<'a, A, B, DOT>
where
    A: HasObservers<'a>,
    B: HasObservers<'a>,
    DOT: MatchName + ObserversTuple<A, B>,
    A::Observers: ObserversTuple<I, S>,
    B::Observers: ObserversTuple<I, S>,
{
    fn pre_exec_all(&mut self, state: &mut S, input: &S::Input) -> Result<(), Error> {
        match self {
            ProxyObserversTuple::WrappedMut(exec) => {
                let exec = exec.as_mut();
                exec.observers.pre_exec_all(state, input)
            }
            ProxyObserversTuple::Wrapped(_) => unimplemented!("This should never happen! We should never pre_exec_all on a ProxyObserversTuple::Wrapped"),
            ProxyObserversTuple::Owned(_, _, _) => unimplemented!("This should never happen! We should never pre_exec_all on a ProxyObserversTuple::Owned"),
        }
    }

    fn post_exec_all(
        &mut self,
        state: &mut S,
        input: &S::Input,
        exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        match self {
            ProxyObserversTuple::WrappedMut(exec) => {
                let exec = exec.as_mut();
                exec.observers.post_exec_all(state, input, exit_kind)
            }
            ProxyObserversTuple::Wrapped(_) => unimplemented!("This should never happen! We should never post_exec_all on a ProxyObserversTuple::Wrapped"),
            ProxyObserversTuple::Owned(_, _, _) => unimplemented!("This should never happen! We should never post_exec_all on a ProxyObserversTuple::Owned"),
        }
    }

    fn pre_exec_child_all(&mut self, state: &mut S, input: &S::Input) -> Result<(), Error> {
        match self {
            ProxyObserversTuple::WrappedMut(exec) => {
                let exec = exec.as_mut();
                exec.observers.pre_exec_child_all(state, input)
            }
            ProxyObserversTuple::Wrapped(_) => unimplemented!("This should never happen! We should never pre_exec_child_all on a ProxyObserversTuple::Wrapped"),
            ProxyObserversTuple::Owned(_, _, _) => unimplemented!("This should never happen! We should never pre_exec_child_all on a ProxyObserversTuple::Owned"),
        }
    }

    fn post_exec_child_all(
        &mut self,
        state: &mut S,
        input: &S::Input,
        exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        match self {
            ProxyObserversTuple::WrappedMut(exec) => {
                let exec = exec.as_mut();
                exec.observers.post_exec_child_all(state, input, exit_kind)
            }
            ProxyObserversTuple::Wrapped(_) => unimplemented!("This should never happen! We should never post_exec_child_all on a ProxyObserversTuple::Wrapped"),
            ProxyObserversTuple::Owned(_, _, _) => unimplemented!("This should never happen! We should never post_exec_child_all on a ProxyObserversTuple::Owned"),
        }
    }
}

impl<'a, A, B, DOT> Deref for ProxyObserversTuple<'a, A, B, DOT> {
    type Target = Self;

    fn deref(&self) -> &Self::Target {
        self
    }
}

impl<'a, A, B, DOT> DerefMut for ProxyObserversTuple<'a, A, B, DOT> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self
    }
}

impl<'a, A, B, DOT> HasObservers<'a> for DiffExecutor<A, B, DOT>
where
    A: HasObservers<'a>,
    B: HasObservers<'a>,
    DOT: MatchName,
{
    type Observers = ProxyObserversTuple<'a, A, B, DOT>;
    type ObserversRef = Self::Observers;
    type ObserversRefMut = Self::Observers;

    #[inline]
    fn observers(&'a self) -> RefIndexable<Self::ObserversRef, Self::Observers> {
        let proxy = ProxyObserversTuple::Wrapped(self);
        RefIndexable::from(proxy)
    }

    #[inline]
    fn observers_mut(&'a mut self) -> RefIndexable<Self::ObserversRefMut, Self::Observers> {
        let proxy = ProxyObserversTuple::WrappedMut(self);
        RefIndexable::from(proxy)
    }
}
