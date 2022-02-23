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
pub use new_hash_feedback::NewHashFeedbackState;

#[cfg(feature = "nautilus")]
pub mod nautilus;
#[cfg(feature = "nautilus")]
pub use nautilus::*;

use alloc::string::{String, ToString};
use serde::{Deserialize, Serialize};

use crate::{
    bolts::tuples::{MatchName, Named},
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

/// [`FeedbackState`] is the data associated with a [`Feedback`] that must persist as part
/// of the fuzzer State
pub trait FeedbackState: Named + Serialize + serde::de::DeserializeOwned + Debug {
    /// Reset the internal state
    fn reset(&mut self) -> Result<(), Error> {
        Ok(())
    }
}

/// A haskell-style tuple of feedback states
pub trait FeedbackStatesTuple: MatchName + Serialize + serde::de::DeserializeOwned + Debug {
    /// Resets all the feedback states of the tuple
    fn reset_all(&mut self) -> Result<(), Error>;
}

impl FeedbackStatesTuple for () {
    fn reset_all(&mut self) -> Result<(), Error> {
        Ok(())
    }
}

impl<Head, Tail> FeedbackStatesTuple for (Head, Tail)
where
    Head: FeedbackState,
    Tail: FeedbackStatesTuple,
{
    fn reset_all(&mut self) -> Result<(), Error> {
        self.0.reset()?;
        self.1.reset_all()
    }
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
