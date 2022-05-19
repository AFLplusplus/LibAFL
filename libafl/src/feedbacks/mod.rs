//! The feedbacks reduce observer state after each run to a single `is_interesting`-value.
//! If a testcase is interesting, it may be added to a Corpus.

pub mod map;
pub use map::*;

pub mod differential;
pub use differential::DiffFeedback;
#[cfg(feature = "std")]
pub mod concolic;
#[cfg(feature = "std")]
pub use concolic::ConcolicFeedback;

#[cfg(feature = "std")]
pub mod new_hash_feedback;
#[cfg(feature = "std")]
pub use new_hash_feedback::NewHashFeedback;
#[cfg(feature = "std")]
pub use new_hash_feedback::NewHashFeedbackMetadata;

#[cfg(feature = "nautilus")]
pub mod nautilus;
#[cfg(feature = "nautilus")]
pub use nautilus::*;

use alloc::string::{String, ToString};
use serde::{Deserialize, Serialize};

use crate::{
    bolts::tuples::Named,
    corpus::Testcase,
    events::EventFirer,
    executors::ExitKind,
    inputs::Input,
    observers::{ListObserver, ObserversTuple, TimeObserver},
    state::HasClientPerfMonitor,
    Error,
};

use core::{
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
    time::Duration,
};

/// Feedbacks evaluate the observers.
/// Basically, they reduce the information provided by an observer to a value,
/// indicating the "interestingness" of the last run.
pub trait Feedback<I, S>: Named + Debug
where
    I: Input,
    S: HasClientPerfMonitor,
{
    /// Initializes the feedback state.
    /// This method is called after that the `State` is created.
    fn init_state(&mut self, _state: &mut S) -> Result<(), Error> {
        Ok(())
    }

    /// `is_interesting ` return if an input is worth the addition to the corpus
    #[allow(clippy::wrong_self_convention)]
    fn is_interesting<EM, OT>(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        input: &I,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<I>,
        OT: ObserversTuple<I, S>;

    /// Returns if the result of a run is interesting and the value input should be stored in a corpus.
    /// It also keeps track of introspection stats.
    #[cfg(feature = "introspection")]
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::wrong_self_convention)]
    fn is_interesting_introspection<EM, OT>(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        input: &I,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<I>,
        OT: ObserversTuple<I, S>,
    {
        // Start a timer for this feedback
        let start_time = crate::bolts::cpu::read_time_counter();

        // Execute this feedback
        let ret = self.is_interesting(state, manager, input, observers, exit_kind);

        // Get the elapsed time for checking this feedback
        let elapsed = crate::bolts::cpu::read_time_counter() - start_time;

        // Add this stat to the feedback metrics
        state
            .introspection_monitor_mut()
            .update_feedback(self.name(), elapsed);

        ret
    }

    /// Append to the testcase the generated metadata in case of a new corpus item
    #[inline]
    fn append_metadata(
        &mut self,
        _state: &mut S,
        _testcase: &mut Testcase<I>,
    ) -> Result<(), Error> {
        Ok(())
    }

    /// Discard the stored metadata in case that the testcase is not added to the corpus
    #[inline]
    fn discard_metadata(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        Ok(())
    }
}

/// Has an associated observer name (mostly used to retrieve the observer with `MatchName` from an `ObserverTuple`)
pub trait HasObserverName {
    /// The name associated with the observer
    fn observer_name(&self) -> &str;
}

/// A combined feedback consisting of multiple [`Feedback`]s
#[derive(Debug)]
pub struct CombinedFeedback<A, B, FL, I, S>
where
    A: Feedback<I, S>,
    B: Feedback<I, S>,
    FL: FeedbackLogic<A, B, I, S>,
    I: Input,
    S: HasClientPerfMonitor,
{
    /// First [`Feedback`]
    pub first: A,
    /// Second [`Feedback`]
    pub second: B,
    name: String,
    phantom: PhantomData<(I, S, FL)>,
}

impl<A, B, FL, I, S> Named for CombinedFeedback<A, B, FL, I, S>
where
    A: Feedback<I, S>,
    B: Feedback<I, S>,
    FL: FeedbackLogic<A, B, I, S>,
    I: Input,
    S: HasClientPerfMonitor,
{
    fn name(&self) -> &str {
        self.name.as_ref()
    }
}

impl<A, B, FL, I, S> CombinedFeedback<A, B, FL, I, S>
where
    A: Feedback<I, S>,
    B: Feedback<I, S>,
    FL: FeedbackLogic<A, B, I, S>,
    I: Input,
    S: HasClientPerfMonitor,
{
    /// Create a new combined feedback
    pub fn new(first: A, second: B) -> Self {
        let name = format!("{} ({},{})", FL::name(), first.name(), second.name());
        Self {
            first,
            second,
            name,
            phantom: PhantomData,
        }
    }
}

impl<A, B, FL, I, S> Feedback<I, S> for CombinedFeedback<A, B, FL, I, S>
where
    A: Feedback<I, S>,
    B: Feedback<I, S>,
    FL: FeedbackLogic<A, B, I, S>,
    I: Input,
    S: HasClientPerfMonitor + Debug,
{
    fn init_state(&mut self, state: &mut S) -> Result<(), Error> {
        self.first.init_state(state)?;
        self.second.init_state(state)?;
        Ok(())
    }

    #[allow(clippy::wrong_self_convention)]
    fn is_interesting<EM, OT>(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        input: &I,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<I>,
        OT: ObserversTuple<I, S>,
    {
        FL::is_pair_interesting(
            &mut self.first,
            &mut self.second,
            state,
            manager,
            input,
            observers,
            exit_kind,
        )
    }

    #[cfg(feature = "introspection")]
    #[allow(clippy::wrong_self_convention)]
    fn is_interesting_introspection<EM, OT>(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        input: &I,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<I>,
        OT: ObserversTuple<I, S>,
    {
        FL::is_pair_interesting_introspection(
            &mut self.first,
            &mut self.second,
            state,
            manager,
            input,
            observers,
            exit_kind,
        )
    }

    #[inline]
    fn append_metadata(&mut self, state: &mut S, testcase: &mut Testcase<I>) -> Result<(), Error> {
        self.first.append_metadata(state, testcase)?;
        self.second.append_metadata(state, testcase)
    }

    #[inline]
    fn discard_metadata(&mut self, state: &mut S, input: &I) -> Result<(), Error> {
        self.first.discard_metadata(state, input)?;
        self.second.discard_metadata(state, input)
    }
}

/// Logical combination of two feedbacks
pub trait FeedbackLogic<A, B, I, S>: 'static + Debug
where
    A: Feedback<I, S>,
    B: Feedback<I, S>,
    I: Input,
    S: HasClientPerfMonitor,
{
    /// The name of this combination
    fn name() -> &'static str;

    /// If the feedback pair is interesting
    fn is_pair_interesting<EM, OT>(
        first: &mut A,
        second: &mut B,
        state: &mut S,
        manager: &mut EM,
        input: &I,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<I>,
        OT: ObserversTuple<I, S>;

    /// If this pair is interesting (with introspection features enabled)
    #[cfg(feature = "introspection")]
    #[allow(clippy::too_many_arguments)]
    fn is_pair_interesting_introspection<EM, OT>(
        first: &mut A,
        second: &mut B,
        state: &mut S,
        manager: &mut EM,
        input: &I,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<I>,
        OT: ObserversTuple<I, S>;
}

/// Eager `OR` combination of two feedbacks
#[derive(Debug, Clone)]
pub struct LogicEagerOr {}

/// Fast `OR` combination of two feedbacks
#[derive(Debug, Clone)]
pub struct LogicFastOr {}

/// Eager `AND` combination of two feedbacks
#[derive(Debug, Clone)]
pub struct LogicEagerAnd {}

/// Fast `AND` combination of two feedbacks
#[derive(Debug, Clone)]
pub struct LogicFastAnd {}

impl<A, B, I, S> FeedbackLogic<A, B, I, S> for LogicEagerOr
where
    A: Feedback<I, S>,
    B: Feedback<I, S>,
    I: Input,
    S: HasClientPerfMonitor,
{
    fn name() -> &'static str {
        "Eager OR"
    }

    fn is_pair_interesting<EM, OT>(
        first: &mut A,
        second: &mut B,
        state: &mut S,
        manager: &mut EM,
        input: &I,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<I>,
        OT: ObserversTuple<I, S>,
    {
        let a = first.is_interesting(state, manager, input, observers, exit_kind)?;
        let b = second.is_interesting(state, manager, input, observers, exit_kind)?;
        Ok(a || b)
    }

    #[cfg(feature = "introspection")]
    fn is_pair_interesting_introspection<EM, OT>(
        first: &mut A,
        second: &mut B,
        state: &mut S,
        manager: &mut EM,
        input: &I,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<I>,
        OT: ObserversTuple<I, S>,
    {
        // Execute this feedback
        let a = first.is_interesting_introspection(state, manager, input, observers, exit_kind)?;

        let b = second.is_interesting_introspection(state, manager, input, observers, exit_kind)?;
        Ok(a || b)
    }
}

impl<A, B, I, S> FeedbackLogic<A, B, I, S> for LogicFastOr
where
    A: Feedback<I, S>,
    B: Feedback<I, S>,
    I: Input,
    S: HasClientPerfMonitor,
{
    fn name() -> &'static str {
        "Fast OR"
    }

    fn is_pair_interesting<EM, OT>(
        first: &mut A,
        second: &mut B,
        state: &mut S,
        manager: &mut EM,
        input: &I,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<I>,
        OT: ObserversTuple<I, S>,
    {
        let a = first.is_interesting(state, manager, input, observers, exit_kind)?;
        if a {
            return Ok(true);
        }

        second.is_interesting(state, manager, input, observers, exit_kind)
    }

    #[cfg(feature = "introspection")]
    fn is_pair_interesting_introspection<EM, OT>(
        first: &mut A,
        second: &mut B,
        state: &mut S,
        manager: &mut EM,
        input: &I,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<I>,
        OT: ObserversTuple<I, S>,
    {
        // Execute this feedback
        let a = first.is_interesting_introspection(state, manager, input, observers, exit_kind)?;

        if a {
            return Ok(true);
        }

        second.is_interesting_introspection(state, manager, input, observers, exit_kind)
    }
}

impl<A, B, I, S> FeedbackLogic<A, B, I, S> for LogicEagerAnd
where
    A: Feedback<I, S>,
    B: Feedback<I, S>,
    I: Input,
    S: HasClientPerfMonitor,
{
    fn name() -> &'static str {
        "Eager AND"
    }

    fn is_pair_interesting<EM, OT>(
        first: &mut A,
        second: &mut B,
        state: &mut S,
        manager: &mut EM,
        input: &I,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<I>,
        OT: ObserversTuple<I, S>,
    {
        let a = first.is_interesting(state, manager, input, observers, exit_kind)?;
        let b = second.is_interesting(state, manager, input, observers, exit_kind)?;
        Ok(a && b)
    }

    #[cfg(feature = "introspection")]
    fn is_pair_interesting_introspection<EM, OT>(
        first: &mut A,
        second: &mut B,
        state: &mut S,
        manager: &mut EM,
        input: &I,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<I>,
        OT: ObserversTuple<I, S>,
    {
        // Execute this feedback
        let a = first.is_interesting_introspection(state, manager, input, observers, exit_kind)?;

        let b = second.is_interesting_introspection(state, manager, input, observers, exit_kind)?;
        Ok(a && b)
    }
}

impl<A, B, I, S> FeedbackLogic<A, B, I, S> for LogicFastAnd
where
    A: Feedback<I, S>,
    B: Feedback<I, S>,
    I: Input,
    S: HasClientPerfMonitor,
{
    fn name() -> &'static str {
        "Fast AND"
    }

    fn is_pair_interesting<EM, OT>(
        first: &mut A,
        second: &mut B,
        state: &mut S,
        manager: &mut EM,
        input: &I,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<I>,
        OT: ObserversTuple<I, S>,
    {
        let a = first.is_interesting(state, manager, input, observers, exit_kind)?;
        if !a {
            return Ok(false);
        }

        second.is_interesting(state, manager, input, observers, exit_kind)
    }

    #[cfg(feature = "introspection")]
    fn is_pair_interesting_introspection<EM, OT>(
        first: &mut A,
        second: &mut B,
        state: &mut S,
        manager: &mut EM,
        input: &I,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<I>,
        OT: ObserversTuple<I, S>,
    {
        // Execute this feedback
        let a = first.is_interesting_introspection(state, manager, input, observers, exit_kind)?;

        if !a {
            return Ok(false);
        }

        second.is_interesting_introspection(state, manager, input, observers, exit_kind)
    }
}

/// Combine two feedbacks with an eager AND operation,
/// will call all feedbacks functions even if not necessary to conclude the result
pub type EagerAndFeedback<A, B, I, S> = CombinedFeedback<A, B, LogicEagerAnd, I, S>;

/// Combine two feedbacks with an fast AND operation,
/// might skip calling feedbacks functions if not necessary to conclude the result
pub type FastAndFeedback<A, B, I, S> = CombinedFeedback<A, B, LogicFastAnd, I, S>;

/// Combine two feedbacks with an eager OR operation,
/// will call all feedbacks functions even if not necessary to conclude the result
pub type EagerOrFeedback<A, B, I, S> = CombinedFeedback<A, B, LogicEagerOr, I, S>;

/// Combine two feedbacks with an fast OR operation,
/// might skip calling feedbacks functions if not necessary to conclude the result.
/// This means any feedback that is not first might be skipped, use caution when using with
/// `TimeFeedback`
pub type FastOrFeedback<A, B, I, S> = CombinedFeedback<A, B, LogicFastOr, I, S>;

/// Compose feedbacks with an `NOT` operation
#[derive(Clone)]
pub struct NotFeedback<A, I, S>
where
    A: Feedback<I, S>,
    I: Input,
    S: HasClientPerfMonitor,
{
    /// The feedback to invert
    pub first: A,
    /// The name
    name: String,
    phantom: PhantomData<(I, S)>,
}

impl<A, I, S> Debug for NotFeedback<A, I, S>
where
    A: Feedback<I, S>,
    I: Input,
    S: HasClientPerfMonitor,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("NotFeedback")
            .field("name", &self.name)
            .field("first", &self.first)
            .finish()
    }
}

impl<A, I, S> Feedback<I, S> for NotFeedback<A, I, S>
where
    A: Feedback<I, S>,
    I: Input,
    S: HasClientPerfMonitor,
{
    fn init_state(&mut self, state: &mut S) -> Result<(), Error> {
        self.first.init_state(state)
    }

    #[allow(clippy::wrong_self_convention)]
    fn is_interesting<EM, OT>(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        input: &I,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<I>,
        OT: ObserversTuple<I, S>,
    {
        Ok(!self
            .first
            .is_interesting(state, manager, input, observers, exit_kind)?)
    }

    #[inline]
    fn append_metadata(&mut self, state: &mut S, testcase: &mut Testcase<I>) -> Result<(), Error> {
        self.first.append_metadata(state, testcase)
    }

    #[inline]
    fn discard_metadata(&mut self, state: &mut S, input: &I) -> Result<(), Error> {
        self.first.discard_metadata(state, input)
    }
}

impl<A, I, S> Named for NotFeedback<A, I, S>
where
    A: Feedback<I, S>,
    I: Input,
    S: HasClientPerfMonitor,
{
    #[inline]
    fn name(&self) -> &str {
        &self.name
    }
}

impl<A, I, S> NotFeedback<A, I, S>
where
    A: Feedback<I, S>,
    I: Input,
    S: HasClientPerfMonitor,
{
    /// Creates a new [`NotFeedback`].
    pub fn new(first: A) -> Self {
        let name = format!("Not({})", first.name());
        Self {
            first,
            name,
            phantom: PhantomData,
        }
    }
}

/// Variadic macro to create a chain of [`AndFeedback`](EagerAndFeedback)
#[macro_export]
macro_rules! feedback_and {
    ( $last:expr ) => { $last };

    ( $head:expr, $($tail:expr), +) => {
        // recursive call
        $crate::feedbacks::EagerAndFeedback::new($head , feedback_and!($($tail),+))
    };
}
///
/// Variadic macro to create a chain of (fast) [`AndFeedback`](FastAndFeedback)
#[macro_export]
macro_rules! feedback_and_fast {
    ( $last:expr ) => { $last };

    ( $head:expr, $($tail:expr), +) => {
        // recursive call
        $crate::feedbacks::FastAndFeedback::new($head , feedback_and_fast!($($tail),+))
    };
}

/// Variadic macro to create a chain of [`OrFeedback`](EagerOrFeedback)
#[macro_export]
macro_rules! feedback_or {
    ( $last:expr ) => { $last };

    ( $head:expr, $($tail:expr), +) => {
        // recursive call
        $crate::feedbacks::EagerOrFeedback::new($head , feedback_or!($($tail),+))
    };
}

/// Combines multiple feedbacks with an `OR` operation, not executing feedbacks after the first positive result
#[macro_export]
macro_rules! feedback_or_fast {
    ( $last:expr ) => { $last };

    ( $head:expr, $($tail:expr), +) => {
        // recursive call
        $crate::feedbacks::FastOrFeedback::new($head , feedback_or_fast!($($tail),+))
    };
}

/// Variadic macro to create a [`NotFeedback`]
#[macro_export]
macro_rules! feedback_not {
    ( $last:expr ) => {
        $crate::feedbacks::NotFeedback::new($last)
    };
}

/// Hack to use () as empty Feedback
impl<I, S> Feedback<I, S> for ()
where
    I: Input,
    S: HasClientPerfMonitor,
{
    #[allow(clippy::wrong_self_convention)]
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &I,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<I>,
        OT: ObserversTuple<I, S>,
    {
        Ok(false)
    }
}

impl Named for () {
    #[inline]
    fn name(&self) -> &str {
        "Empty"
    }
}

/// A [`CrashFeedback`] reports as interesting if the target crashed.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CrashFeedback {}

impl<I, S> Feedback<I, S> for CrashFeedback
where
    I: Input,
    S: HasClientPerfMonitor,
{
    #[allow(clippy::wrong_self_convention)]
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &I,
        _observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<I>,
        OT: ObserversTuple<I, S>,
    {
        if let ExitKind::Crash = exit_kind {
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

impl Named for CrashFeedback {
    #[inline]
    fn name(&self) -> &str {
        "CrashFeedback"
    }
}

impl CrashFeedback {
    /// Creates a new [`CrashFeedback`]
    #[must_use]
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for CrashFeedback {
    fn default() -> Self {
        Self::new()
    }
}

/// A [`TimeoutFeedback`] reduces the timeout value of a run.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TimeoutFeedback {}

impl<I, S> Feedback<I, S> for TimeoutFeedback
where
    I: Input,
    S: HasClientPerfMonitor,
{
    #[allow(clippy::wrong_self_convention)]
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &I,
        _observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<I>,
        OT: ObserversTuple<I, S>,
    {
        if let ExitKind::Timeout = exit_kind {
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

impl Named for TimeoutFeedback {
    #[inline]
    fn name(&self) -> &str {
        "TimeoutFeedback"
    }
}

impl TimeoutFeedback {
    /// Returns a new [`TimeoutFeedback`].
    #[must_use]
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for TimeoutFeedback {
    fn default() -> Self {
        Self::new()
    }
}

/// Nop feedback that annotates execution time in the new testcase, if any
/// for this Feedback, the testcase is never interesting (use with an OR).
/// It decides, if the given [`TimeObserver`] value of a run is interesting.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TimeFeedback {
    exec_time: Option<Duration>,
    name: String,
}

impl<I, S> Feedback<I, S> for TimeFeedback
where
    I: Input,
    S: HasClientPerfMonitor,
{
    #[allow(clippy::wrong_self_convention)]
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &I,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<I>,
        OT: ObserversTuple<I, S>,
    {
        // TODO Replace with match_name_type when stable
        let observer = observers.match_name::<TimeObserver>(self.name()).unwrap();
        self.exec_time = *observer.last_runtime();
        Ok(false)
    }

    /// Append to the testcase the generated metadata in case of a new corpus item
    #[inline]
    fn append_metadata(&mut self, _state: &mut S, testcase: &mut Testcase<I>) -> Result<(), Error> {
        *testcase.exec_time_mut() = self.exec_time;
        self.exec_time = None;
        Ok(())
    }

    /// Discard the stored metadata in case that the testcase is not added to the corpus
    #[inline]
    fn discard_metadata(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        self.exec_time = None;
        Ok(())
    }
}

impl Named for TimeFeedback {
    #[inline]
    fn name(&self) -> &str {
        self.name.as_str()
    }
}

impl TimeFeedback {
    /// Creates a new [`TimeFeedback`], deciding if the value of a [`TimeObserver`] with the given `name` of a run is interesting.
    #[must_use]
    pub fn new(name: &'static str) -> Self {
        Self {
            exec_time: None,
            name: name.to_string(),
        }
    }

    /// Creates a new [`TimeFeedback`], deciding if the given [`TimeObserver`] value of a run is interesting.
    #[must_use]
    pub fn new_with_observer(observer: &TimeObserver) -> Self {
        Self {
            exec_time: None,
            name: observer.name().to_string(),
        }
    }
}

/// Consider interesting a testcase if the list in `ListObserver` is not empty.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ListFeedback<T>
where
    T: Debug + Serialize + serde::de::DeserializeOwned,
{
    name: String,
    phantom: PhantomData<T>,
}

impl<I, S, T> Feedback<I, S> for ListFeedback<T>
where
    I: Input,
    S: HasClientPerfMonitor,
    T: Debug + Serialize + serde::de::DeserializeOwned,
{
    #[allow(clippy::wrong_self_convention)]
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &I,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<I>,
        OT: ObserversTuple<I, S>,
    {
        // TODO Replace with match_name_type when stable
        let observer = observers
            .match_name::<ListObserver<T>>(self.name())
            .unwrap();
        // TODO register the list content in a testcase metadata
        Ok(!observer.list().is_empty())
    }
}

impl<T> Named for ListFeedback<T>
where
    T: Debug + Serialize + serde::de::DeserializeOwned,
{
    #[inline]
    fn name(&self) -> &str {
        self.name.as_str()
    }
}

impl<T> ListFeedback<T>
where
    T: Debug + Serialize + serde::de::DeserializeOwned,
{
    /// Creates a new [`ListFeedback`], deciding if the value of a [`ListObserver`] with the given `name` of a run is interesting.
    #[must_use]
    pub fn new(name: &'static str) -> Self {
        Self {
            name: name.to_string(),
            phantom: PhantomData,
        }
    }

    /// Creates a new [`TimeFeedback`], deciding if the given [`ListObserver`] value of a run is interesting.
    #[must_use]
    pub fn new_with_observer(observer: &ListObserver<T>) -> Self {
        Self {
            name: observer.name().to_string(),
            phantom: PhantomData,
        }
    }
}

/// The [`ConstFeedback`] reports the same value, always.
/// It can be used to enable or disable feedback results through composition.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConstFeedback {
    /// Always returns `true`
    True,
    /// Alsways returns `false`
    False,
}

impl<I, S> Feedback<I, S> for ConstFeedback
where
    I: Input,
    S: HasClientPerfMonitor,
{
    #[inline]
    #[allow(clippy::wrong_self_convention)]
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &I,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<I>,
        OT: ObserversTuple<I, S>,
    {
        Ok(match self {
            ConstFeedback::True => true,
            ConstFeedback::False => false,
        })
    }
}

impl Named for ConstFeedback {
    #[inline]
    fn name(&self) -> &str {
        "ConstFeedback"
    }
}

impl ConstFeedback {
    /// Creates a new [`ConstFeedback`] from the given boolean
    #[must_use]
    pub fn new(val: bool) -> Self {
        Self::from(val)
    }
}

impl From<bool> for ConstFeedback {
    fn from(val: bool) -> Self {
        if val {
            Self::True
        } else {
            Self::False
        }
    }
}

/// `Feedback` Python bindings
#[cfg(feature = "python")]
#[allow(missing_docs)]
pub mod pybind {
    use super::*;
    use crate::feedbacks::map::pybind::*;
    use crate::inputs::HasBytesVec;
    use crate::observers::pybind::PythonObserversTuple;
    use crate::state::pybind::{PythonStdState, PythonStdStateWrapper};
    use crate::{
        bolts::tuples::Named, corpus::Testcase, events::EventFirer, executors::ExitKind,
        inputs::BytesInput, observers::ObserversTuple, Error,
    };
    use pyo3::prelude::*;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::cell::UnsafeCell;

    #[derive(Debug)]
    pub struct PyObjectFeedback {
        inner: PyObject,
        name: UnsafeCell<String>,
    }

    impl Clone for PyObjectFeedback {
        fn clone(&self) -> PyObjectFeedback {
            PyObjectFeedback {
                inner: self.inner.clone(),
                name: UnsafeCell::new(String::new()),
            }
        }
    }

    impl PyObjectFeedback {
        pub fn new(obj: PyObject) -> Self {
            PyObjectFeedback {
                inner: obj,
                name: UnsafeCell::new(String::new()),
            }
        }
    }

    impl Serialize for PyObjectFeedback {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let buf = Python::with_gil(|py| -> PyResult<Vec<u8>> {
                let pickle = PyModule::import(py, "pickle")?;
                let buf: Vec<u8> = pickle.getattr("dumps")?.call1((&self.inner,))?.extract()?;
                Ok(buf)
            })
            .unwrap();
            serializer.serialize_bytes(&buf)
        }
    }

    struct PyObjectFeedbackVisitor;

    impl<'de> serde::de::Visitor<'de> for PyObjectFeedbackVisitor {
        type Value = PyObjectFeedback;

        fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
            formatter.write_str("Expecting some bytes to deserialize from the Python side")
        }

        fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            let obj = Python::with_gil(|py| -> PyResult<PyObject> {
                let pickle = PyModule::import(py, "pickle")?;
                let obj = pickle.getattr("loads")?.call1((v,))?.to_object(py);
                Ok(obj)
            })
            .unwrap();
            Ok(PyObjectFeedback::new(obj))
        }
    }

    impl<'de> Deserialize<'de> for PyObjectFeedback {
        fn deserialize<D>(deserializer: D) -> Result<PyObjectFeedback, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_byte_buf(PyObjectFeedbackVisitor)
        }
    }

    impl Named for PyObjectFeedback {
        fn name(&self) -> &str {
            let s = Python::with_gil(|py| -> PyResult<String> {
                let s: String = self.inner.call_method0(py, "name")?.extract(py)?;
                Ok(s)
            })
            .unwrap();
            unsafe {
                *self.name.get() = s;
                &*self.name.get()
            }
        }
    }

    impl Feedback<BytesInput, PythonStdState> for PyObjectFeedback {
        fn init_state(&mut self, state: &mut PythonStdState) -> Result<(), Error> {
            Python::with_gil(|py| -> PyResult<()> {
                self.inner
                    .call_method1(py, "init_state", (PythonStdStateWrapper::wrap(state),))?;
                Ok(())
            })
            .unwrap();
            Ok(())
        }

        fn is_interesting<EM, OT>(
            &mut self,
            state: &mut PythonStdState,
            _manager: &mut EM,
            input: &BytesInput,
            observers: &OT,
            _exit_kind: &ExitKind,
        ) -> Result<bool, Error>
        where
            EM: EventFirer<BytesInput>,
            OT: ObserversTuple<BytesInput, PythonStdState>,
        {
            // SAFETY: We use this observer in Python ony when the ObserverTuple is PythonObserversTuple
            let dont_look_at_this: &PythonObserversTuple =
                unsafe { std::mem::transmute(observers) };
            // TODO pass the other args
            Ok(Python::with_gil(|py| -> PyResult<bool> {
                let r: bool = self
                    .inner
                    .call_method1(
                        py,
                        "is_interesting",
                        (
                            PythonStdStateWrapper::wrap(state),
                            input.bytes(),
                            dont_look_at_this.clone(),
                        ),
                    )?
                    .extract(py)?;
                Ok(r)
            })
            .unwrap())
        }

        fn append_metadata(
            &mut self,
            state: &mut PythonStdState,
            _testcase: &mut Testcase<BytesInput>,
        ) -> Result<(), Error> {
            // TODO pass the other args
            Python::with_gil(|py| -> PyResult<()> {
                self.inner.call_method1(
                    py,
                    "append_metadata",
                    (PythonStdStateWrapper::wrap(state),),
                )?;
                Ok(())
            })
            .unwrap();
            Ok(())
        }

        fn discard_metadata(
            &mut self,
            state: &mut PythonStdState,
            input: &BytesInput,
        ) -> Result<(), Error> {
            Python::with_gil(|py| -> PyResult<()> {
                self.inner.call_method1(
                    py,
                    "discard_metadata",
                    (PythonStdStateWrapper::wrap(state), input.bytes()),
                )?;
                Ok(())
            })
            .unwrap();
            Ok(())
        }
    }

    #[derive(Clone, Debug)]
    pub enum PythonFeedbackWrapper {
        MaxMapI8(Py<PythonMaxMapFeedbackI8>),
        Python(PyObjectFeedback),
    }

    #[pyclass(unsendable, name = "Feedback")]
    #[derive(Debug)]
    /// Observer Trait binding
    pub struct PythonFeedback {
        pub wrapper: PythonFeedbackWrapper,
        name: UnsafeCell<String>,
    }

    macro_rules! unwrap_me {
        ($wrapper:expr, $result:ty, $name:ident, $body:block) => {
            match &$wrapper {
                PythonFeedbackWrapper::MaxMapI8(py_wrapper) => {
                    Python::with_gil(|py| -> PyResult<$result> {
                        let borrowed = py_wrapper.borrow(py);
                        let $name = &borrowed.inner;
                        Ok($body)
                    })
                    .unwrap()
                }
                PythonFeedbackWrapper::Python(py_wrapper) => {
                    let $name = py_wrapper;
                    $body
                }
            }
        };
    }

    macro_rules! unwrap_me_mut {
        ($wrapper:expr, $result:ty, $name:ident, $body:block) => {
            match &mut $wrapper {
                PythonFeedbackWrapper::MaxMapI8(py_wrapper) => {
                    Python::with_gil(|py| -> PyResult<$result> {
                        let mut borrowed = py_wrapper.borrow_mut(py);
                        let $name = &mut borrowed.inner;
                        Ok($body)
                    })
                    .unwrap()
                }
                PythonFeedbackWrapper::Python(py_wrapper) => {
                    let $name = py_wrapper;
                    $body
                }
            }
        };
    }

    impl Clone for PythonFeedback {
        fn clone(&self) -> PythonFeedback {
            PythonFeedback {
                wrapper: self.wrapper.clone(),
                name: UnsafeCell::new(String::new()),
            }
        }
    }

    #[pymethods]
    impl PythonFeedback {
        #[staticmethod]
        pub fn new_max_map_i8(map_feedback: Py<PythonMaxMapFeedbackI8>) -> Self {
            Self {
                wrapper: PythonFeedbackWrapper::MaxMapI8(map_feedback),
                name: UnsafeCell::new(String::new()),
            }
        }

        #[staticmethod]
        pub fn new_py(obj: PyObject) -> Self {
            Self {
                wrapper: PythonFeedbackWrapper::Python(PyObjectFeedback::new(obj)),
                name: UnsafeCell::new(String::new()),
            }
        }

        fn pippo(&mut self) {
            unwrap_me_mut!(self.wrapper, (), f, {
                println!("{:?}", f.name());
            })
        }
    }

    impl Named for PythonFeedback {
        fn name(&self) -> &str {
            let s = unwrap_me!(self.wrapper, String, f, { f.name().to_string() });
            unsafe {
                *self.name.get() = s;
                &*self.name.get()
            }
        }
    }

    impl Feedback<BytesInput, PythonStdState> for PythonFeedback {
        fn init_state(&mut self, state: &mut PythonStdState) -> Result<(), Error> {
            unwrap_me_mut!(self.wrapper, Result<(), Error>, f, { f.init_state(state) })
        }

        fn is_interesting<EM, OT>(
            &mut self,
            state: &mut PythonStdState,
            manager: &mut EM,
            input: &BytesInput,
            observers: &OT,
            exit_kind: &ExitKind,
        ) -> Result<bool, Error>
        where
            EM: EventFirer<BytesInput>,
            OT: ObserversTuple<BytesInput, PythonStdState>,
        {
            unwrap_me_mut!(self.wrapper, Result<bool, Error>, f, { f.is_interesting(state, manager, input, observers, exit_kind) })
        }

        fn append_metadata(
            &mut self,
            state: &mut PythonStdState,
            testcase: &mut Testcase<BytesInput>,
        ) -> Result<(), Error> {
            unwrap_me_mut!(self.wrapper, Result<(), Error>, f, { f.append_metadata(state, testcase) })
        }

        fn discard_metadata(
            &mut self,
            state: &mut PythonStdState,
            input: &BytesInput,
        ) -> Result<(), Error> {
            unwrap_me_mut!(self.wrapper, Result<(), Error>, f, { f.discard_metadata(state, input) })
        }
    }

    /// Register the classes to the python module
    pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
        m.add_class::<PythonFeedback>()?;
        Ok(())
    }
}
