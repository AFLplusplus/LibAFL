//! Observers give insights about runs of a target, such as coverage, timing, stack depth, and more.

pub mod map;
pub use map::*;

pub mod cmp;
pub use cmp::*;

#[cfg(feature = "std")]
pub mod stdio;
#[cfg(feature = "std")]
pub use stdio::{StdErrObserver, StdOutObserver};

#[cfg(feature = "regex")]
pub mod stacktrace;
#[cfg(feature = "regex")]
pub use stacktrace::*;

pub mod concolic;

pub mod value;

/// List observer
pub mod list;
use alloc::string::{String, ToString};
use core::{fmt::Debug, time::Duration};
#[cfg(feature = "std")]
use std::time::Instant;

#[cfg(feature = "no_std")]
use libafl_bolts::current_time;
use libafl_bolts::{tuples::MatchName, Named};
pub use list::*;
use serde::{Deserialize, Serialize};
pub use value::*;

use crate::{executors::ExitKind, inputs::UsesInput, state::UsesState, Error};

/// Something that uses observer like mapfeedbacks
pub trait UsesObserver<S>
where
    S: UsesInput,
{
    /// The observer type used
    type Observer: Observer<S>;
}

/// Observers observe different information about the target.
/// They can then be used by various sorts of feedback.
pub trait Observer<S>: Named
where
    S: UsesInput,
{
    /// The testcase finished execution, calculate any changes.
    /// Reserved for future use.
    #[inline]
    fn flush(&mut self) -> Result<(), Error> {
        Ok(())
    }

    /// Called right before execution starts.
    #[inline]
    fn pre_exec(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        Ok(())
    }

    /// Called right after execution finishes.
    #[inline]
    fn post_exec(
        &mut self,
        _state: &mut S,
        _input: &S::Input,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        Ok(())
    }

    /// Called right before execution starts in the child process, if any.
    #[inline]
    fn pre_exec_child(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        Ok(())
    }

    /// Called right after execution finishes in the child process, if any.
    #[inline]
    fn post_exec_child(
        &mut self,
        _state: &mut S,
        _input: &S::Input,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        Ok(())
    }

    /// If this observer observes `stdout`
    #[inline]
    fn observes_stdout(&self) -> bool {
        false
    }
    /// If this observer observes `stderr`
    #[inline]
    fn observes_stderr(&self) -> bool {
        false
    }

    /// React to new `stdout`
    /// To use this, always return `true` from `observes_stdout`
    #[inline]
    #[allow(unused_variables)]
    fn observe_stdout(&mut self, stdout: &[u8]) {}

    /// React to new `stderr`
    /// To use this, always return `true` from `observes_stderr`
    #[inline]
    #[allow(unused_variables)]
    fn observe_stderr(&mut self, stderr: &[u8]) {}
}

/// Defines the observer type shared across traits of the type.
/// Needed for consistency across HasCorpus/HasSolutions and friends.
pub trait UsesObservers: UsesState {
    /// The observers type
    type Observers: ObserversTuple<Self::State>;
}

/// A haskell-style tuple of observers
pub trait ObserversTuple<S>: MatchName
where
    S: UsesInput,
{
    /// This is called right before the next execution.
    fn pre_exec_all(&mut self, state: &mut S, input: &S::Input) -> Result<(), Error>;

    /// This is called right after the last execution
    fn post_exec_all(
        &mut self,
        state: &mut S,
        input: &S::Input,
        exit_kind: &ExitKind,
    ) -> Result<(), Error>;

    /// This is called right before the next execution in the child process, if any.
    fn pre_exec_child_all(&mut self, state: &mut S, input: &S::Input) -> Result<(), Error>;

    /// This is called right after the last execution in the child process, if any.
    fn post_exec_child_all(
        &mut self,
        state: &mut S,
        input: &S::Input,
        exit_kind: &ExitKind,
    ) -> Result<(), Error>;

    /// Returns true if a `stdout` observer was added to the list
    fn observes_stdout(&self) -> bool;
    /// Returns true if a `stderr` observer was added to the list
    fn observes_stderr(&self) -> bool;

    /// Runs `observe_stdout` for all stdout observers in the list
    fn observe_stdout(&mut self, stdout: &[u8]);
    /// Runs `observe_stderr` for all stderr observers in the list
    fn observe_stderr(&mut self, stderr: &[u8]);
}

impl<S> ObserversTuple<S> for ()
where
    S: UsesInput,
{
    fn pre_exec_all(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        Ok(())
    }

    fn post_exec_all(
        &mut self,
        _state: &mut S,
        _input: &S::Input,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        Ok(())
    }

    fn pre_exec_child_all(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        Ok(())
    }

    fn post_exec_child_all(
        &mut self,
        _state: &mut S,
        _input: &S::Input,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        Ok(())
    }

    /// Returns true if a `stdout` observer was added to the list
    #[inline]
    fn observes_stdout(&self) -> bool {
        false
    }

    /// Returns true if a `stderr` observer was added to the list
    #[inline]
    fn observes_stderr(&self) -> bool {
        false
    }

    /// Runs `observe_stdout` for all stdout observers in the list
    #[inline]
    #[allow(unused_variables)]
    fn observe_stdout(&mut self, stdout: &[u8]) {}

    /// Runs `observe_stderr` for all stderr observers in the list
    #[inline]
    #[allow(unused_variables)]
    fn observe_stderr(&mut self, stderr: &[u8]) {}
}

impl<Head, Tail, S> ObserversTuple<S> for (Head, Tail)
where
    Head: Observer<S>,
    Tail: ObserversTuple<S>,
    S: UsesInput,
{
    fn pre_exec_all(&mut self, state: &mut S, input: &S::Input) -> Result<(), Error> {
        self.0.pre_exec(state, input)?;
        self.1.pre_exec_all(state, input)
    }

    fn post_exec_all(
        &mut self,
        state: &mut S,
        input: &S::Input,
        exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        self.0.post_exec(state, input, exit_kind)?;
        self.1.post_exec_all(state, input, exit_kind)
    }

    fn pre_exec_child_all(&mut self, state: &mut S, input: &S::Input) -> Result<(), Error> {
        self.0.pre_exec_child(state, input)?;
        self.1.pre_exec_child_all(state, input)
    }

    fn post_exec_child_all(
        &mut self,
        state: &mut S,
        input: &S::Input,
        exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        self.0.post_exec_child(state, input, exit_kind)?;
        self.1.post_exec_child_all(state, input, exit_kind)
    }

    /// Returns true if a `stdout` observer was added to the list
    #[inline]
    fn observes_stdout(&self) -> bool {
        self.0.observes_stdout() || self.1.observes_stdout()
    }

    /// Returns true if a `stderr` observer was added to the list
    #[inline]
    fn observes_stderr(&self) -> bool {
        self.0.observes_stderr() || self.1.observes_stderr()
    }

    /// Runs `observe_stdout` for all stdout observers in the list
    #[inline]
    fn observe_stdout(&mut self, stdout: &[u8]) {
        self.0.observe_stdout(stdout);
        self.1.observe_stdout(stdout);
    }

    /// Runs `observe_stderr` for all stderr observers in the list
    #[inline]
    fn observe_stderr(&mut self, stderr: &[u8]) {
        self.0.observe_stderr(stderr);
        self.1.observe_stderr(stderr);
    }
}

/// A trait for [`Observer`]`s` with a hash field
pub trait ObserverWithHashField {
    /// get the value of the hash field
    fn hash(&self) -> Option<u64>;
}

/// A trait for [`Observer`]`s` which observe over differential execution.
///
/// Differential observers have the following flow during a single execution:
///  - `Observer::pre_exec` for the differential observer is invoked.
///  - `DifferentialObserver::pre_observe_first` for the differential observer is invoked.
///  - `Observer::pre_exec` for each of the observers for the first executor is invoked.
///  - The first executor is invoked.
///  - `Observer::post_exec` for each of the observers for the first executor is invoked.
///  - `DifferentialObserver::post_observe_first` for the differential observer is invoked.
///  - `DifferentialObserver::pre_observe_second` for the differential observer is invoked.
///  - `Observer::pre_exec` for each of the observers for the second executor is invoked.
///  - The second executor is invoked.
///  - `Observer::post_exec` for each of the observers for the second executor is invoked.
///  - `DifferentialObserver::post_observe_second` for the differential observer is invoked.
///  - `Observer::post_exec` for the differential observer is invoked.
///
/// You should perform any preparation for the diff execution in `Observer::pre_exec` and respective
/// cleanup in `Observer::post_exec`. For individual executions, use
/// `DifferentialObserver::{pre,post}_observe_{first,second}` as necessary for first and second,
/// respectively.
#[allow(unused_variables)]
pub trait DifferentialObserver<OTA, OTB, S>: Observer<S>
where
    OTA: ObserversTuple<S>,
    OTB: ObserversTuple<S>,
    S: UsesInput,
{
    /// Perform an operation with the first set of observers before they are `pre_exec`'d.
    fn pre_observe_first(&mut self, observers: &mut OTA) -> Result<(), Error> {
        Ok(())
    }

    /// Perform an operation with the first set of observers after they are `post_exec`'d.
    fn post_observe_first(&mut self, observers: &mut OTA) -> Result<(), Error> {
        Ok(())
    }

    /// Perform an operation with the second set of observers before they are `pre_exec`'d.
    fn pre_observe_second(&mut self, observers: &mut OTB) -> Result<(), Error> {
        Ok(())
    }

    /// Perform an operation with the second set of observers after they are `post_exec`'d.
    fn post_observe_second(&mut self, observers: &mut OTB) -> Result<(), Error> {
        Ok(())
    }
}

/// Differential observers tuple, for when you're using multiple differential observers.
pub trait DifferentialObserversTuple<OTA, OTB, S>: ObserversTuple<S>
where
    OTA: ObserversTuple<S>,
    OTB: ObserversTuple<S>,
    S: UsesInput,
{
    /// Perform an operation with the first set of observers before they are `pre_exec`'d on all the
    /// differential observers in this tuple.
    fn pre_observe_first_all(&mut self, observers: &mut OTA) -> Result<(), Error>;

    /// Perform an operation with the first set of observers after they are `post_exec`'d on all the
    /// differential observers in this tuple.
    fn post_observe_first_all(&mut self, observers: &mut OTA) -> Result<(), Error>;

    /// Perform an operation with the second set of observers before they are `pre_exec`'d on all
    /// the differential observers in this tuple.
    fn pre_observe_second_all(&mut self, observers: &mut OTB) -> Result<(), Error>;

    /// Perform an operation with the second set of observers after they are `post_exec`'d on all
    /// the differential observers in this tuple.
    fn post_observe_second_all(&mut self, observers: &mut OTB) -> Result<(), Error>;
}

impl<OTA, OTB, S> DifferentialObserversTuple<OTA, OTB, S> for ()
where
    OTA: ObserversTuple<S>,
    OTB: ObserversTuple<S>,
    S: UsesInput,
{
    fn pre_observe_first_all(&mut self, _: &mut OTA) -> Result<(), Error> {
        Ok(())
    }

    fn post_observe_first_all(&mut self, _: &mut OTA) -> Result<(), Error> {
        Ok(())
    }

    fn pre_observe_second_all(&mut self, _: &mut OTB) -> Result<(), Error> {
        Ok(())
    }

    fn post_observe_second_all(&mut self, _: &mut OTB) -> Result<(), Error> {
        Ok(())
    }
}

impl<Head, Tail, OTA, OTB, S> DifferentialObserversTuple<OTA, OTB, S> for (Head, Tail)
where
    Head: DifferentialObserver<OTA, OTB, S>,
    Tail: DifferentialObserversTuple<OTA, OTB, S>,
    OTA: ObserversTuple<S>,
    OTB: ObserversTuple<S>,
    S: UsesInput,
{
    fn pre_observe_first_all(&mut self, observers: &mut OTA) -> Result<(), Error> {
        self.0.pre_observe_first(observers)?;
        self.1.pre_observe_first_all(observers)
    }

    fn post_observe_first_all(&mut self, observers: &mut OTA) -> Result<(), Error> {
        self.0.post_observe_first(observers)?;
        self.1.post_observe_first_all(observers)
    }

    fn pre_observe_second_all(&mut self, observers: &mut OTB) -> Result<(), Error> {
        self.0.pre_observe_second(observers)?;
        self.1.pre_observe_second_all(observers)
    }

    fn post_observe_second_all(&mut self, observers: &mut OTB) -> Result<(), Error> {
        self.0.post_observe_second(observers)?;
        self.1.post_observe_second_all(observers)
    }
}

/// A simple observer, just overlooking the runtime of the target.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TimeObserver {
    name: String,

    #[cfg(feature = "std")]
    #[serde(with = "instant_serializer")]
    start_time: Instant,

    #[cfg(feature = "no_std")]
    start_time: Duration,

    last_runtime: Option<Duration>,
}

#[cfg(feature = "std")]
mod instant_serializer {
    use core::time::Duration;
    use std::time::Instant;

    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn serialize<S>(instant: &Instant, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let duration = instant.elapsed();
        duration.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Instant, D::Error>
    where
        D: Deserializer<'de>,
    {
        let duration = Duration::deserialize(deserializer)?;
        let instant = Instant::now().checked_sub(duration).unwrap();
        Ok(instant)
    }
}

impl TimeObserver {
    /// Creates a new [`TimeObserver`] with the given name.
    #[must_use]
    pub fn new(name: &'static str) -> Self {
        Self {
            name: name.to_string(),

            #[cfg(feature = "std")]
            start_time: Instant::now(),

            #[cfg(feature = "no_std")]
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

impl<S> Observer<S> for TimeObserver
where
    S: UsesInput,
{
    #[cfg(feature = "std")]
    fn pre_exec(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        self.last_runtime = None;
        self.start_time = Instant::now();
        Ok(())
    }

    #[cfg(feature = "no_std")]
    fn pre_exec(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        self.last_runtime = None;
        self.start_time = current_time();
        Ok(())
    }

    #[cfg(feature = "std")]
    fn post_exec(
        &mut self,
        _state: &mut S,
        _input: &S::Input,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        self.last_runtime = Some(self.start_time.elapsed());
        Ok(())
    }

    #[cfg(feature = "no_std")]
    fn post_exec(
        &mut self,
        _state: &mut S,
        _input: &S::Input,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        self.last_runtime = current_time().checked_sub(self.start_time);
    }
}

impl Named for TimeObserver {
    fn name(&self) -> &str {
        &self.name
    }
}

impl<OTA, OTB, S> DifferentialObserver<OTA, OTB, S> for TimeObserver
where
    OTA: ObserversTuple<S>,
    OTB: ObserversTuple<S>,
    S: UsesInput,
{
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {

    use core::ptr::addr_of_mut;

    use libafl_bolts::{
        ownedref::OwnedMutSlice,
        tuples::{tuple_list, tuple_list_type},
        Named,
    };

    use crate::observers::{StdMapObserver, TimeObserver};

    static mut MAP: [u32; 4] = [0; 4];

    #[test]
    fn test_observer_serde() {
        let obv = tuple_list!(TimeObserver::new("time"), unsafe {
            StdMapObserver::from_ownedref(
                "map",
                OwnedMutSlice::from_raw_parts_mut(addr_of_mut!(MAP) as *mut u32, MAP.len()),
            )
        });
        let vec = postcard::to_allocvec(&obv).unwrap();
        log::info!("{vec:?}");
        let obv2: tuple_list_type!(TimeObserver, StdMapObserver<u32, false>) =
            postcard::from_bytes(&vec).unwrap();
        assert_eq!(obv.0.name(), obv2.0.name());
    }
}
