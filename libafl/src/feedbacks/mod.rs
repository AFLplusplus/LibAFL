//! The feedbacks reduce observer state after each run to a single `is_interesting`-value.
//! If a testcase is interesting, it may be added to a Corpus.

pub mod map;
pub use map::*;

use alloc::string::{String, ToString};
use serde::{Deserialize, Serialize};

use crate::{
    bolts::tuples::{MatchName, Named},
    corpus::Testcase,
    executors::ExitKind,
    inputs::Input,
    observers::{ObserversTuple, TimeObserver},
    state::HasFeedbackStates,
    Error,
};

#[cfg(feature = "introspection")]
use crate::stats::NUM_FEEDBACKS;

use core::{marker::PhantomData, time::Duration};

/// Feedbacks evaluate the observers.
/// Basically, they reduce the information provided by an observer to a value,
/// indicating the "interestingness" of the last run.
pub trait Feedback<FT, I, S>: Named
where
    I: Input,
    S: HasFeedbackStates<FT, I>,
    FT: FeedbackStatesTuple<I>,
{
    /// `is_interesting ` return if an input is worth the addition to the corpus
    fn is_interesting<OT>(
        &mut self,
        state: &mut S,
        input: &I,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        OT: ObserversTuple;

    #[cfg(feature = "introspection")]
    fn is_interesting_with_perf<OT>(
        &mut self,
        state: &mut S,
        input: &I,
        observers: &OT,
        exit_kind: &ExitKind,
        feedback_stats: &mut [u64; NUM_FEEDBACKS],
        feedback_index: usize,
    ) -> Result<bool, Error>
    where
        OT: ObserversTuple,
    {
        // Start a timer for this feedback
        let start_time = crate::cpu::read_time_counter();

        // Execute this feedback
        let ret = self.is_interesting(input, observers, &exit_kind);

        // Get the elapsed time for checking this feedback
        let elapsed = crate::cpu::read_time_counter() - start_time;

        // TODO: A more meaningful way to get perf for each feedback

        // Add this stat to the feedback metrics
        feedback_stats[feedback_index] = elapsed;

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

/// FeedbackState is the data associated with a Feedback that must persist as part
/// of the fuzzer State
pub trait FeedbackState<I>: Named + serde::Serialize + serde::de::DeserializeOwned
where
    I: Input,
{
}

/// A haskell-style tuple of feedback states
pub trait FeedbackStatesTuple<I>:
    MatchName + serde::Serialize + serde::de::DeserializeOwned
where
    I: Input,
{
}

impl<I> FeedbackStatesTuple<I> for () where I: Input {}

impl<Head, Tail, I> FeedbackStatesTuple<I> for (Head, Tail)
where
    Head: FeedbackState<I>,
    Tail: FeedbackStatesTuple<I>,
    I: Input,
{
}

/// Compose [`Feedback`]`s` with an `AND` operation
pub struct AndFeedback<A, B, FT, I, S>
where
    A: Feedback<FT, I, S>,
    B: Feedback<FT, I, S>,
    I: Input,
    S: HasFeedbackStates<FT, I>,
    FT: FeedbackStatesTuple<I>,
{
    /// The first [`Feedback`] to `AND`.
    pub first: A,
    /// The second [`Feedback`] to `AND`.
    pub second: B,
    phantom: PhantomData<(FT, I, S)>,
}

impl<A, B, FT, I, S> Feedback<FT, I, S> for AndFeedback<A, B, FT, I, S>
where
    A: Feedback<FT, I, S>,
    B: Feedback<FT, I, S>,
    I: Input,
    S: HasFeedbackStates<FT, I>,
    FT: FeedbackStatesTuple<I>,
{
    fn is_interesting<OT>(
        &mut self,
        state: &mut S,
        input: &I,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        OT: ObserversTuple,
    {
        let a = self
            .first
            .is_interesting(state, input, observers, exit_kind)?;
        let b = self
            .second
            .is_interesting(state, input, observers, exit_kind)?;
        Ok(a && b)
    }

    #[cfg(feature = "introspection")]
    fn is_interesting_with_perf<OT>(
        &mut self,
        state: &mut S,
        input: &I,
        observers: &OT,
        exit_kind: &ExitKind,
        feedback_stats: &mut [u64; NUM_FEEDBACKS],
        feedback_index: usize,
    ) -> Result<bool, Error>
    where
        OT: ObserversTuple,
    {
        // Execute this feedback
        let a = self.first.is_interesting_with_perf(
            input,
            observers,
            &exit_kind,
            feedback_stats,
            feedback_index,
        )?;
        let b = self.second.is_interesting_with_perf(
            input,
            observers,
            &exit_kind,
            feedback_stats,
            feedback_index + 1,
        )?;
        Ok(a && b)
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

impl<A, B, FT, I, S> Named for AndFeedback<A, B, FT, I, S>
where
    A: Feedback<FT, I, S>,
    B: Feedback<FT, I, S>,
    I: Input,
    S: HasFeedbackStates<FT, I>,
    FT: FeedbackStatesTuple<I>,
{
    #[inline]
    fn name(&self) -> &str {
        //format!("And({}, {})", self.first.name(), self.second.name())
        "AndFeedback"
    }
}

impl<A, B, FT, I, S> AndFeedback<A, B, FT, I, S>
where
    A: Feedback<FT, I, S>,
    B: Feedback<FT, I, S>,
    I: Input,
    S: HasFeedbackStates<FT, I>,
    FT: FeedbackStatesTuple<I>,
{
    /// Creates a new [`AndFeedback`], resulting in the `AND` of two feedbacks.
    pub fn new(first: A, second: B) -> Self {
        Self {
            first,
            second,
            phantom: PhantomData,
        }
    }
}

/// Compose feedbacks with an OR operation
pub struct OrFeedback<A, B, FT, I, S>
where
    A: Feedback<FT, I, S>,
    B: Feedback<FT, I, S>,
    I: Input,
    S: HasFeedbackStates<FT, I>,
    FT: FeedbackStatesTuple<I>,
{
    /// The first [`Feedback`]
    pub first: A,
    /// The second [`Feedback`], `OR`ed with the first.
    pub second: B,
    phantom: PhantomData<(FT, I, S)>,
}

impl<A, B, FT, I, S> Feedback<FT, I, S> for OrFeedback<A, B, FT, I, S>
where
    A: Feedback<FT, I, S>,
    B: Feedback<FT, I, S>,
    I: Input,
    S: HasFeedbackStates<FT, I>,
    FT: FeedbackStatesTuple<I>,
{
    fn is_interesting<OT>(
        &mut self,
        state: &mut S,
        input: &I,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        OT: ObserversTuple,
    {
        let a = self
            .first
            .is_interesting(state, input, observers, exit_kind)?;
        let b = self
            .second
            .is_interesting(state, input, observers, exit_kind)?;
        Ok(a || b)
    }

    #[cfg(feature = "introspection")]
    fn is_interesting_with_perf<OT>(
        &mut self,
        state: &mut S,
        input: &I,
        observers: &OT,
        exit_kind: &ExitKind,
        feedback_stats: &mut [u64; NUM_FEEDBACKS],
        feedback_index: usize,
    ) -> Result<bool, Error>
    where
        OT: ObserversTuple,
    {
        // Execute this feedback
        let a = self.first.is_interesting_with_perf(
            input,
            observers,
            &exit_kind,
            feedback_stats,
            feedback_index,
        )?;
        let b = self.second.is_interesting_with_perf(
            input,
            observers,
            &exit_kind,
            feedback_stats,
            feedback_index + 1,
        )?;
        Ok(a || b)
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

impl<A, B, FT, I, S> Named for OrFeedback<A, B, FT, I, S>
where
    A: Feedback<FT, I, S>,
    B: Feedback<FT, I, S>,
    I: Input,
    S: HasFeedbackStates<FT, I>,
    FT: FeedbackStatesTuple<I>,
{
    #[inline]
    fn name(&self) -> &str {
        //format!("Or({}, {})", self.first.name(), self.second.name())
        "OrFeedback"
    }
}

impl<A, B, FT, I, S> OrFeedback<A, B, FT, I, S>
where
    A: Feedback<FT, I, S>,
    B: Feedback<FT, I, S>,
    I: Input,
    S: HasFeedbackStates<FT, I>,
    FT: FeedbackStatesTuple<I>,
{
    /// Creates a new [`OrFeedback`] for two feedbacks.
    pub fn new(first: A, second: B) -> Self {
        Self {
            first,
            second,
            phantom: PhantomData,
        }
    }
}

/// Compose feedbacks with an OR operation
pub struct NotFeedback<A, FT, I, S>
where
    A: Feedback<FT, I, S>,
    I: Input,
    S: HasFeedbackStates<FT, I>,
    FT: FeedbackStatesTuple<I>,
{
    /// The feedback to invert
    pub first: A,
    phantom: PhantomData<(FT, I, S)>,
}

impl<A, FT, I, S> Feedback<FT, I, S> for NotFeedback<A, FT, I, S>
where
    A: Feedback<FT, I, S>,
    I: Input,
    S: HasFeedbackStates<FT, I>,
    FT: FeedbackStatesTuple<I>,
{
    fn is_interesting<OT>(
        &mut self,
        state: &mut S,
        input: &I,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        OT: ObserversTuple,
    {
        Ok(!self
            .first
            .is_interesting(state, input, observers, exit_kind)?)
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

impl<A, FT, I, S> Named for NotFeedback<A, FT, I, S>
where
    A: Feedback<FT, I, S>,
    I: Input,
    S: HasFeedbackStates<FT, I>,
    FT: FeedbackStatesTuple<I>,
{
    #[inline]
    fn name(&self) -> &str {
        //format!("Not({})", self.first.name())
        "NotFeedback"
    }
}

impl<A, FT, I, S> NotFeedback<A, FT, I, S>
where
    A: Feedback<FT, I, S>,
    I: Input,
    S: HasFeedbackStates<FT, I>,
    FT: FeedbackStatesTuple<I>,
{
    /// Creates a new [`NotFeedback`].
    pub fn new(first: A) -> Self {
        Self {
            first,
            phantom: PhantomData,
        }
    }
}

/// Variadic macro to create a chain of AndFeedback
#[macro_export]
macro_rules! feedback_and {
    ( $last:expr ) => { $last };

    ( $head:expr, $($tail:expr), +) => {
        // recursive call
        $crate::feedbacks::AndFeedback::new($head , feedback_and!($($tail),+))
    };
}

/// Variadic macro to create a chain of OrFeedback
#[macro_export]
macro_rules! feedback_or {
    ( $last:expr ) => { $last };

    ( $head:expr, $($tail:expr), +) => {
        // recursive call
        $crate::feedbacks::OrFeedback::new($head , feedback_or!($($tail),+))
    };
}

/// Variadic macro to create a NotFeedback
#[macro_export]
macro_rules! feedback_not {
    ( $last:expr ) => {
        $crate::feedbacks::NotFeedback::new($last)
    };
}

/// Hack to use () as empty Feedback
impl<FT, I, S> Feedback<FT, I, S> for ()
where
    I: Input,
    S: HasFeedbackStates<FT, I>,
    FT: FeedbackStatesTuple<I>,
{
    fn is_interesting<OT>(
        &mut self,
        _state: &mut S,
        _input: &I,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        OT: ObserversTuple,
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

impl<FT, I, S> Feedback<FT, I, S> for CrashFeedback
where
    I: Input,
    S: HasFeedbackStates<FT, I>,
    FT: FeedbackStatesTuple<I>,
{
    fn is_interesting<OT>(
        &mut self,
        _state: &mut S,
        _input: &I,
        _observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        OT: ObserversTuple,
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

impl<FT, I, S> Feedback<FT, I, S> for TimeoutFeedback
where
    I: Input,
    S: HasFeedbackStates<FT, I>,
    FT: FeedbackStatesTuple<I>,
{
    fn is_interesting<OT>(
        &mut self,
        _state: &mut S,
        _input: &I,
        _observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        OT: ObserversTuple,
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
/// for this Feedback, the testcase is never interesting (use with an OR)
/// It decides, if the given [`TimeObserver`] value of a run is interesting.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TimeFeedback {
    exec_time: Option<Duration>,
    name: String,
}

impl<FT, I, S> Feedback<FT, I, S> for TimeFeedback
where
    I: Input,
    S: HasFeedbackStates<FT, I>,
    FT: FeedbackStatesTuple<I>,
{
    fn is_interesting<OT>(
        &mut self,
        state: &mut S,
        _input: &I,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        OT: ObserversTuple,
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
