//! The feedbacks reduce observer state after each run to a single `is_interesting`-value.
//! If a testcase is interesting, it may be added to a Corpus.

pub mod map;
pub use map::*;

use alloc::string::{String, ToString};
use serde::{Deserialize, Serialize};

use crate::{
    bolts::tuples::Named,
    corpus::Testcase,
    executors::ExitKind,
    inputs::Input,
    observers::{ObserversTuple, TimeObserver},
    Error,
};

use core::{marker::PhantomData, time::Duration};

/// Feedbacks evaluate the observers.
/// Basically, they reduce the information provided by an observer to a value,
/// indicating the "interestingness" of the last run.
pub trait Feedback<I>: Named + serde::Serialize + serde::de::DeserializeOwned
where
    I: Input,
{
    /// `is_interesting ` should return the "Interestingness" from 0 to 255 (percent times 2.55)
    fn is_interesting<OT>(
        &mut self,
        input: &I,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        OT: ObserversTuple;

    /// Append to the testcase the generated metadata in case of a new corpus item
    #[inline]
    fn append_metadata(&mut self, _testcase: &mut Testcase<I>) -> Result<(), Error> {
        Ok(())
    }

    /// Discard the stored metadata in case that the testcase is not added to the corpus
    #[inline]
    fn discard_metadata(&mut self, _input: &I) -> Result<(), Error> {
        Ok(())
    }
}

/// Compose [`Feedback`]`s` with an `AND` operation
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "I: serde::de::DeserializeOwned")]
pub struct AndFeedback<A, B, I>
where
    A: Feedback<I>,
    B: Feedback<I>,
    I: Input,
{
    /// The first [`Feedback`] to `AND`.
    pub first: A,
    /// The second [`Feedback`] to `AND`.
    pub second: B,
    phantom: PhantomData<I>,
}

impl<A, B, I> Feedback<I> for AndFeedback<A, B, I>
where
    A: Feedback<I>,
    B: Feedback<I>,
    I: Input,
{
    fn is_interesting<OT>(
        &mut self,
        input: &I,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        OT: ObserversTuple,
    {
        let a = self.first.is_interesting(input, observers, exit_kind)?;
        let b = self.second.is_interesting(input, observers, exit_kind)?;
        Ok(a && b)
    }

    #[inline]
    fn append_metadata(&mut self, testcase: &mut Testcase<I>) -> Result<(), Error> {
        self.first.append_metadata(testcase)?;
        self.second.append_metadata(testcase)
    }

    #[inline]
    fn discard_metadata(&mut self, input: &I) -> Result<(), Error> {
        self.first.discard_metadata(input)?;
        self.second.discard_metadata(input)
    }
}

impl<A, B, I> Named for AndFeedback<A, B, I>
where
    A: Feedback<I>,
    B: Feedback<I>,
    I: Input,
{
    #[inline]
    fn name(&self) -> &str {
        //format!("And({}, {})", self.first.name(), self.second.name())
        "AndFeedback"
    }
}

impl<A, B, I> AndFeedback<A, B, I>
where
    A: Feedback<I>,
    B: Feedback<I>,
    I: Input,
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
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "I: serde::de::DeserializeOwned")]
pub struct OrFeedback<A, B, I>
where
    A: Feedback<I>,
    B: Feedback<I>,
    I: Input,
{
    /// The first [`Feedback`]
    pub first: A,
    /// The second [`Feedback`], `OR`ed with the first.
    pub second: B,
    phantom: PhantomData<I>,
}

impl<A, B, I> Feedback<I> for OrFeedback<A, B, I>
where
    A: Feedback<I>,
    B: Feedback<I>,
    I: Input,
{
    fn is_interesting<OT>(
        &mut self,
        input: &I,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        OT: ObserversTuple,
    {
        let a = self.first.is_interesting(input, observers, exit_kind)?;
        let b = self.second.is_interesting(input, observers, exit_kind)?;
        Ok(a || b)
    }

    #[inline]
    fn append_metadata(&mut self, testcase: &mut Testcase<I>) -> Result<(), Error> {
        self.first.append_metadata(testcase)?;
        self.second.append_metadata(testcase)
    }

    #[inline]
    fn discard_metadata(&mut self, input: &I) -> Result<(), Error> {
        self.first.discard_metadata(input)?;
        self.second.discard_metadata(input)
    }
}

impl<A, B, I> Named for OrFeedback<A, B, I>
where
    A: Feedback<I>,
    B: Feedback<I>,
    I: Input,
{
    #[inline]
    fn name(&self) -> &str {
        //format!("Or({}, {})", self.first.name(), self.second.name())
        "OrFeedback"
    }
}

impl<A, B, I> OrFeedback<A, B, I>
where
    A: Feedback<I>,
    B: Feedback<I>,
    I: Input,
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
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "I: serde::de::DeserializeOwned")]
pub struct NotFeedback<A, I>
where
    A: Feedback<I>,
    I: Input,
{
    /// The feedback to invert
    pub first: A,
    phantom: PhantomData<I>,
}

impl<A, I> Feedback<I> for NotFeedback<A, I>
where
    A: Feedback<I>,
    I: Input,
{
    fn is_interesting<OT>(
        &mut self,
        input: &I,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        OT: ObserversTuple,
    {
        Ok(!self.first.is_interesting(input, observers, exit_kind)?)
    }

    #[inline]
    fn append_metadata(&mut self, testcase: &mut Testcase<I>) -> Result<(), Error> {
        self.first.append_metadata(testcase)
    }

    #[inline]
    fn discard_metadata(&mut self, input: &I) -> Result<(), Error> {
        self.first.discard_metadata(input)
    }
}

impl<A, I> Named for NotFeedback<A, I>
where
    A: Feedback<I>,
    I: Input,
{
    #[inline]
    fn name(&self) -> &str {
        //format!("Not({})", self.first.name())
        "NotFeedback"
    }
}

impl<A, I> NotFeedback<A, I>
where
    A: Feedback<I>,
    I: Input,
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
impl<I> Feedback<I> for ()
where
    I: Input,
{
    fn is_interesting<OT>(
        &mut self,
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

impl<I> Feedback<I> for CrashFeedback
where
    I: Input,
{
    fn is_interesting<OT>(
        &mut self,
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

impl<I> Feedback<I> for TimeoutFeedback
where
    I: Input,
{
    fn is_interesting<OT>(
        &mut self,
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

impl<I> Feedback<I> for TimeFeedback
where
    I: Input,
{
    fn is_interesting<OT>(
        &mut self,
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
    fn append_metadata(&mut self, testcase: &mut Testcase<I>) -> Result<(), Error> {
        *testcase.exec_time_mut() = self.exec_time;
        self.exec_time = None;
        Ok(())
    }

    /// Discard the stored metadata in case that the testcase is not added to the corpus
    #[inline]
    fn discard_metadata(&mut self, _input: &I) -> Result<(), Error> {
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
    pub fn new(name: &'static str) -> Self {
        Self {
            exec_time: None,
            name: name.to_string(),
        }
    }

    /// Creates a new [`TimeFeedback`], deciding if the given [`TimeObserver`] value of a run is interesting.
    pub fn new_with_observer(observer: &TimeObserver) -> Self {
        Self {
            exec_time: None,
            name: observer.name().to_string(),
        }
    }
}
