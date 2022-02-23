//! Observers give insights about runs of a target, such as coverage, timing, stack depth, and more.

pub mod map;
pub use map::*;

pub mod cmp;
pub use cmp::*;

#[cfg(feature = "std")]
pub mod stdio;
#[cfg(feature = "std")]
pub use stdio::{StdErrObserver, StdOutObserver};

#[cfg(feature = "std")]
pub mod stacktrace;
#[cfg(feature = "std")]
pub use stacktrace::*;

pub mod concolic;

#[cfg(unstable_feature)]
pub mod owned;
#[cfg(unstable_feature)]
pub use owned::*;

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::{fmt::Debug, time::Duration};
use serde::{Deserialize, Serialize};

use crate::{
    bolts::{
        current_time,
        ownedref::OwnedRefMut,
        tuples::{MatchName, Named},
    },
    executors::ExitKind,
    Error,
};

/// Observers observe different information about the target.
/// They can then be used by various sorts of feedback.
pub trait Observer<I, S>: Named + Debug {
    /// The testcase finished execution, calculate any changes.
    /// Reserved for future use.
    #[inline]
    fn flush(&mut self) -> Result<(), Error> {
        Ok(())
    }

    /// Called right before execution starts.
    #[inline]
    fn pre_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        Ok(())
    }

    /// Called right after execution finishes.
    #[inline]
    fn post_exec(
        &mut self,
        _state: &mut S,
        _input: &I,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        Ok(())
    }

    /// Called right before execution starts in the child process, if any.
    #[inline]
    fn pre_exec_child(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        Ok(())
    }

    /// Called right after execution finishes in the child process, if any.
    #[inline]
    fn post_exec_child(
        &mut self,
        _state: &mut S,
        _input: &I,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        Ok(())
    }
}

/// A haskell-style tuple of observers
pub trait ObserversTuple<I, S>: MatchName + Debug {
    /// This is called right before the next execution.
    fn pre_exec_all(&mut self, state: &mut S, input: &I) -> Result<(), Error>;

    /// This is called right after the last execution
    fn post_exec_all(
        &mut self,
        state: &mut S,
        input: &I,
        exit_kind: &ExitKind,
    ) -> Result<(), Error>;

    /// This is called right before the next execution in the child process, if any.
    fn pre_exec_child_all(&mut self, state: &mut S, input: &I) -> Result<(), Error>;

    /// This is called right after the last execution in the child process, if any.
    fn post_exec_child_all(
        &mut self,
        state: &mut S,
        input: &I,
        exit_kind: &ExitKind,
    ) -> Result<(), Error>;
}

impl<I, S> ObserversTuple<I, S> for () {
    fn pre_exec_all(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        Ok(())
    }

    fn post_exec_all(
        &mut self,
        _state: &mut S,
        _input: &I,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        Ok(())
    }

    fn pre_exec_child_all(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        Ok(())
    }

    fn post_exec_child_all(
        &mut self,
        _state: &mut S,
        _input: &I,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        Ok(())
    }
}

impl<Head, Tail, I, S> ObserversTuple<I, S> for (Head, Tail)
where
    Head: Observer<I, S>,
    Tail: ObserversTuple<I, S>,
{
    fn pre_exec_all(&mut self, state: &mut S, input: &I) -> Result<(), Error> {
        self.0.pre_exec(state, input)?;
        self.1.pre_exec_all(state, input)
    }

    fn post_exec_all(
        &mut self,
        state: &mut S,
        input: &I,
        exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        self.0.post_exec(state, input, exit_kind)?;
        self.1.post_exec_all(state, input, exit_kind)
    }

    fn pre_exec_child_all(&mut self, state: &mut S, input: &I) -> Result<(), Error> {
        self.0.pre_exec_child(state, input)?;
        self.1.pre_exec_child_all(state, input)
    }

    fn post_exec_child_all(
        &mut self,
        state: &mut S,
        input: &I,
        exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        self.0.post_exec_child(state, input, exit_kind)?;
        self.1.post_exec_child_all(state, input, exit_kind)
    }
}

/// A trait for obervers with a hash field
pub trait ObserverWithHashField {
    /// get the value of the hash field
    fn hash(&self) -> &Option<u64>;
    /// update the hash field with the given value
    fn update_hash(&mut self, hash: u64);
    /// clears the current value of the hash and sets it to None
    fn clear_hash(&mut self);
}
/// A simple observer, just overlooking the runtime of the target.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TimeObserver {
    name: String,
    start_time: Duration,
    last_runtime: Option<Duration>,
}

impl TimeObserver {
    /// Creates a new [`TimeObserver`] with the given name.
    #[must_use]
    pub fn new(name: &'static str) -> Self {
        Self {
            name: name.to_string(),
            start_time: Duration::from_secs(0),
            last_runtime: None,
        }
    }

    /// Gets the runtime for the last execution of this target.
    #[must_use]
    pub fn last_runtime(&self) -> &Option<Duration> {
        &self.last_runtime
    }
}

impl<I, S> Observer<I, S> for TimeObserver {
    fn pre_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        self.last_runtime = None;
        self.start_time = current_time();
        Ok(())
    }

    fn post_exec(
        &mut self,
        _state: &mut S,
        _input: &I,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        self.last_runtime = current_time().checked_sub(self.start_time);
        Ok(())
    }
}

impl Named for TimeObserver {
    fn name(&self) -> &str {
        &self.name
    }
}

/// A simple observer with a list of things.
#[derive(Serialize, Deserialize, Debug)]
#[serde(bound = "T: serde::de::DeserializeOwned")]
pub struct ListObserver<'a, T>
where
    T: Debug + Serialize + serde::de::DeserializeOwned,
{
    name: String,
    /// The list
    list: OwnedRefMut<'a, Vec<T>>,
}

impl<'a, T> ListObserver<'a, T>
where
    T: Debug + Serialize + serde::de::DeserializeOwned,
{
    /// Creates a new [`ListObserver`] with the given name.
    #[must_use]
    pub fn new(name: &'static str, list: &'a mut Vec<T>) -> Self {
        Self {
            name: name.to_string(),
            list: OwnedRefMut::Ref(list),
        }
    }

    /// Get a list ref
    #[must_use]
    pub fn list(&self) -> &Vec<T> {
        self.list.as_ref()
    }

    /// Get a list mut
    #[must_use]
    pub fn list_mut(&mut self) -> &mut Vec<T> {
        self.list.as_mut()
    }
}

impl<'a, I, S, T> Observer<I, S> for ListObserver<'a, T>
where
    T: Debug + Serialize + serde::de::DeserializeOwned,
{
    fn pre_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        self.list.as_mut().clear();
        Ok(())
    }
}

impl<'a, T> Named for ListObserver<'a, T>
where
    T: Debug + Serialize + serde::de::DeserializeOwned,
{
    fn name(&self) -> &str {
        &self.name
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {

    use crate::{
        bolts::tuples::{tuple_list, tuple_list_type, Named},
        observers::{StdMapObserver, TimeObserver},
    };

    static mut MAP: [u32; 4] = [0; 4];

    #[test]
    fn test_observer_serde() {
        let obv = tuple_list!(
            TimeObserver::new("time"),
            StdMapObserver::new("map", unsafe { &mut MAP })
        );
        let vec = postcard::to_allocvec(&obv).unwrap();
        println!("{:?}", vec);
        let obv2: tuple_list_type!(TimeObserver, StdMapObserver<u32>) =
            postcard::from_bytes(&vec).unwrap();
        assert_eq!(obv.0.name(), obv2.0.name());
    }
}
