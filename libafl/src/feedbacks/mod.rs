//! The feedbacks reduce observer state after each run to a single `is_interesting`-value.
//! If a testcase is interesting, it may be added to a Corpus.

pub mod map;
pub use map::*;

use serde::{Deserialize, Serialize};

use crate::{
    bolts::tuples::Named,
    corpus::Testcase,
    executors::ExitKind,
    inputs::Input,
    observers::{ObserversTuple, TimeObserver},
    Error,
};

use core::time::Duration;

/// Feedbacks evaluate the observers.
/// Basically, they reduce the information provided by an observer to a value,
/// indicating the "interestingness" of the last run.
pub trait Feedback<I>: Named + serde::Serialize + serde::de::DeserializeOwned + 'static
where
    I: Input,
{
    /// `is_interesting ` should return the "Interestingness" from 0 to 255 (percent times 2.55)
    fn is_interesting<OT: ObserversTuple>(
        &mut self,
        input: &I,
        observers: &OT,
        exit_kind: ExitKind,
    ) -> Result<u32, Error>;

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

pub trait FeedbacksTuple<I>: serde::Serialize + serde::de::DeserializeOwned
where
    I: Input,
{
    /// Get the total interestingness value from all feedbacks
    fn is_interesting_all<OT: ObserversTuple>(
        &mut self,
        input: &I,
        observers: &OT,
        exit_kind: ExitKind,
    ) -> Result<u32, Error>;

    /// Write metadata for this testcase
    fn append_metadata_all(&mut self, testcase: &mut Testcase<I>) -> Result<(), Error>;

    /// Discards metadata - the end of this input's execution
    fn discard_metadata_all(&mut self, input: &I) -> Result<(), Error>;
}

impl<I> FeedbacksTuple<I> for ()
where
    I: Input,
{
    #[inline]
    fn is_interesting_all<OT: ObserversTuple>(
        &mut self,
        _: &I,
        _: &OT,
        _: ExitKind,
    ) -> Result<u32, Error> {
        Ok(0)
    }

    #[inline]
    fn append_metadata_all(&mut self, _testcase: &mut Testcase<I>) -> Result<(), Error> {
        Ok(())
    }

    #[inline]
    fn discard_metadata_all(&mut self, _input: &I) -> Result<(), Error> {
        Ok(())
    }
}

impl<Head, Tail, I> FeedbacksTuple<I> for (Head, Tail)
where
    Head: Feedback<I>,
    Tail: FeedbacksTuple<I>,
    I: Input,
{
    fn is_interesting_all<OT: ObserversTuple>(
        &mut self,
        input: &I,
        observers: &OT,
        exit_kind: ExitKind,
    ) -> Result<u32, Error> {
        Ok(self.0.is_interesting(input, observers, exit_kind.clone())?
            + self.1.is_interesting_all(input, observers, exit_kind)?)
    }

    fn append_metadata_all(&mut self, testcase: &mut Testcase<I>) -> Result<(), Error> {
        self.0.append_metadata(testcase)?;
        self.1.append_metadata_all(testcase)
    }

    fn discard_metadata_all(&mut self, input: &I) -> Result<(), Error> {
        self.0.discard_metadata(input)?;
        self.1.discard_metadata_all(input)
    }
}

/// Is a crash feedback
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CrashFeedback {}

impl<I> Feedback<I> for CrashFeedback
where
    I: Input,
{
    fn is_interesting<OT: ObserversTuple>(
        &mut self,
        _input: &I,
        _observers: &OT,
        exit_kind: ExitKind,
    ) -> Result<u32, Error> {
        if exit_kind == ExitKind::Crash {
            Ok(1)
        } else {
            Ok(0)
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
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for CrashFeedback {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TimeoutFeedback {}

impl<I> Feedback<I> for TimeoutFeedback
where
    I: Input,
{
    fn is_interesting<OT: ObserversTuple>(
        &mut self,
        _input: &I,
        _observers: &OT,
        exit_kind: ExitKind,
    ) -> Result<u32, Error> {
        if exit_kind == ExitKind::Timeout {
            Ok(1)
        } else {
            Ok(0)
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
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TimeFeedback {
    exec_time: Option<Duration>,
}

impl<I> Feedback<I> for TimeFeedback
where
    I: Input,
{
    fn is_interesting<OT: ObserversTuple>(
        &mut self,
        _input: &I,
        observers: &OT,
        _exit_kind: ExitKind,
    ) -> Result<u32, Error> {
        let observer = observers.match_first_type::<TimeObserver>().unwrap();
        self.exec_time = *observer.last_runtime();
        Ok(0)
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
        "TimeFeedback"
    }
}

impl TimeFeedback {
    pub fn new() -> Self {
        Self { exec_time: None }
    }
}

impl Default for TimeFeedback {
    fn default() -> Self {
        Self::new()
    }
}
