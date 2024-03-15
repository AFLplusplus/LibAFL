//! The feedbacks reduce observer state after each run to a single `is_interesting`-value.
//! If a testcase is interesting, it may be added to a Corpus.
//!

// TODO: make S of Feedback<S> an associated type when specialisation + AT is stable

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
pub mod transferred;

use alloc::string::{String, ToString};
use core::{
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
};

use libafl_bolts::Named;
#[cfg(feature = "nautilus")]
pub use nautilus::*;
use serde::{Deserialize, Serialize};

use crate::{
    corpus::Testcase,
    events::EventFirer,
    executors::ExitKind,
    observers::{ListObserver, ObserversTuple, TimeObserver},
    state::State,
    Error,
};

/// Feedbacks evaluate the observers.
/// Basically, they reduce the information provided by an observer to a value,
/// indicating the "interestingness" of the last run.
pub trait Feedback<S>: Named
where
    S: State,
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
        input: &S::Input,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>;

    /// Returns if the result of a run is interesting and the value input should be stored in a corpus.
    /// It also keeps track of introspection stats.
    #[cfg(feature = "introspection")]
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::wrong_self_convention)]
    fn is_interesting_introspection<EM, OT>(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        input: &S::Input,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        // Start a timer for this feedback
        let start_time = libafl_bolts::cpu::read_time_counter();

        // Execute this feedback
        let ret = self.is_interesting(state, manager, input, observers, exit_kind);

        // Get the elapsed time for checking this feedback
        let elapsed = libafl_bolts::cpu::read_time_counter() - start_time;

        // Add this stat to the feedback metrics
        state
            .introspection_monitor_mut()
            .update_feedback(self.name(), elapsed);

        ret
    }

    /// Append to the testcase the generated metadata in case of a new corpus item
    #[inline]
    #[allow(unused_variables)]
    fn append_metadata<EM, OT>(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        observers: &OT,
        testcase: &mut Testcase<S::Input>,
    ) -> Result<(), Error>
    where
        OT: ObserversTuple<S>,
        EM: EventFirer<State = S>,
    {
        Ok(())
    }

    /// Discard the stored metadata in case that the testcase is not added to the corpus
    #[inline]
    fn discard_metadata(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
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
pub struct CombinedFeedback<A, B, FL, S>
where
    A: Feedback<S>,
    B: Feedback<S>,
    FL: FeedbackLogic<A, B, S>,
    S: State,
{
    /// First [`Feedback`]
    pub first: A,
    /// Second [`Feedback`]
    pub second: B,
    name: String,
    phantom: PhantomData<(S, FL)>,
}

impl<A, B, FL, S> Named for CombinedFeedback<A, B, FL, S>
where
    A: Feedback<S>,
    B: Feedback<S>,
    FL: FeedbackLogic<A, B, S>,
    S: State,
{
    fn name(&self) -> &str {
        self.name.as_ref()
    }
}

impl<A, B, FL, S> CombinedFeedback<A, B, FL, S>
where
    A: Feedback<S>,
    B: Feedback<S>,
    FL: FeedbackLogic<A, B, S>,
    S: State,
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

impl<A, B, FL, S> Feedback<S> for CombinedFeedback<A, B, FL, S>
where
    A: Feedback<S>,
    B: Feedback<S>,
    FL: FeedbackLogic<A, B, S>,
    S: State,
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
        input: &S::Input,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
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
        input: &S::Input,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
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
    fn append_metadata<EM, OT>(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        observers: &OT,
        testcase: &mut Testcase<S::Input>,
    ) -> Result<(), Error>
    where
        OT: ObserversTuple<S>,
        EM: EventFirer<State = S>,
    {
        self.first
            .append_metadata(state, manager, observers, testcase)?;
        self.second
            .append_metadata(state, manager, observers, testcase)
    }

    #[inline]
    fn discard_metadata(&mut self, state: &mut S, input: &S::Input) -> Result<(), Error> {
        self.first.discard_metadata(state, input)?;
        self.second.discard_metadata(state, input)
    }
}

/// Logical combination of two feedbacks
pub trait FeedbackLogic<A, B, S>: 'static
where
    A: Feedback<S>,
    B: Feedback<S>,
    S: State,
{
    /// The name of this combination
    fn name() -> &'static str;

    /// If the feedback pair is interesting
    fn is_pair_interesting<EM, OT>(
        first: &mut A,
        second: &mut B,
        state: &mut S,
        manager: &mut EM,
        input: &S::Input,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>;

    /// If this pair is interesting (with introspection features enabled)
    #[cfg(feature = "introspection")]
    #[allow(clippy::too_many_arguments)]
    fn is_pair_interesting_introspection<EM, OT>(
        first: &mut A,
        second: &mut B,
        state: &mut S,
        manager: &mut EM,
        input: &S::Input,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>;
}

/// Factory for feedbacks which should be sensitive to an existing context, e.g. observer(s) from a
/// specific execution
pub trait FeedbackFactory<F, S, T>
where
    F: Feedback<S>,
    S: State,
{
    /// Create the feedback from the provided context
    fn create_feedback(&self, ctx: &T) -> F;
}

impl<FE, FU, S, T> FeedbackFactory<FE, S, T> for FU
where
    FU: Fn(&T) -> FE,
    FE: Feedback<S>,
    S: State,
{
    fn create_feedback(&self, ctx: &T) -> FE {
        self(ctx)
    }
}

/// A feedback factory which merely invokes `::default()` for the feedback type provided
#[derive(Default, Debug, Copy, Clone)]
pub struct DefaultFeedbackFactory<F>
where
    F: Default,
{
    phantom: PhantomData<F>,
}

impl<F> DefaultFeedbackFactory<F>
where
    F: Default,
{
    /// Create the feedback factory
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl<F, S, T> FeedbackFactory<F, S, T> for DefaultFeedbackFactory<F>
where
    F: Feedback<S> + Default,
    S: State,
{
    fn create_feedback(&self, _ctx: &T) -> F {
        F::default()
    }
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

impl<A, B, S> FeedbackLogic<A, B, S> for LogicEagerOr
where
    A: Feedback<S>,
    B: Feedback<S>,
    S: State,
{
    fn name() -> &'static str {
        "Eager OR"
    }

    fn is_pair_interesting<EM, OT>(
        first: &mut A,
        second: &mut B,
        state: &mut S,
        manager: &mut EM,
        input: &S::Input,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
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
        input: &S::Input,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        // Execute this feedback
        let a = first.is_interesting_introspection(state, manager, input, observers, exit_kind)?;

        let b = second.is_interesting_introspection(state, manager, input, observers, exit_kind)?;
        Ok(a || b)
    }
}

impl<A, B, S> FeedbackLogic<A, B, S> for LogicFastOr
where
    A: Feedback<S>,
    B: Feedback<S>,
    S: State,
{
    fn name() -> &'static str {
        "Fast OR"
    }

    fn is_pair_interesting<EM, OT>(
        first: &mut A,
        second: &mut B,
        state: &mut S,
        manager: &mut EM,
        input: &S::Input,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
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
        input: &S::Input,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        // Execute this feedback
        let a = first.is_interesting_introspection(state, manager, input, observers, exit_kind)?;

        if a {
            return Ok(true);
        }

        second.is_interesting_introspection(state, manager, input, observers, exit_kind)
    }
}

impl<A, B, S> FeedbackLogic<A, B, S> for LogicEagerAnd
where
    A: Feedback<S>,
    B: Feedback<S>,
    S: State,
{
    fn name() -> &'static str {
        "Eager AND"
    }

    fn is_pair_interesting<EM, OT>(
        first: &mut A,
        second: &mut B,
        state: &mut S,
        manager: &mut EM,
        input: &S::Input,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
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
        input: &S::Input,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        // Execute this feedback
        let a = first.is_interesting_introspection(state, manager, input, observers, exit_kind)?;

        let b = second.is_interesting_introspection(state, manager, input, observers, exit_kind)?;
        Ok(a && b)
    }
}

impl<A, B, S> FeedbackLogic<A, B, S> for LogicFastAnd
where
    A: Feedback<S>,
    B: Feedback<S>,
    S: State,
{
    fn name() -> &'static str {
        "Fast AND"
    }

    fn is_pair_interesting<EM, OT>(
        first: &mut A,
        second: &mut B,
        state: &mut S,
        manager: &mut EM,
        input: &S::Input,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
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
        input: &S::Input,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
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
pub type EagerAndFeedback<A, B, S> = CombinedFeedback<A, B, LogicEagerAnd, S>;

/// Combine two feedbacks with an fast AND operation,
/// might skip calling feedbacks functions if not necessary to conclude the result
pub type FastAndFeedback<A, B, S> = CombinedFeedback<A, B, LogicFastAnd, S>;

/// Combine two feedbacks with an eager OR operation,
/// will call all feedbacks functions even if not necessary to conclude the result
pub type EagerOrFeedback<A, B, S> = CombinedFeedback<A, B, LogicEagerOr, S>;

/// Combine two feedbacks with an fast OR operation,
/// might skip calling feedbacks functions if not necessary to conclude the result.
/// This means any feedback that is not first might be skipped, use caution when using with
/// `TimeFeedback`
pub type FastOrFeedback<A, B, S> = CombinedFeedback<A, B, LogicFastOr, S>;

/// Compose feedbacks with an `NOT` operation
#[derive(Clone)]
pub struct NotFeedback<A, S>
where
    A: Feedback<S>,
    S: State,
{
    /// The feedback to invert
    pub first: A,
    /// The name
    name: String,
    phantom: PhantomData<S>,
}

impl<A, S> Debug for NotFeedback<A, S>
where
    A: Feedback<S> + Debug,
    S: State,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("NotFeedback")
            .field("name", &self.name)
            .field("first", &self.first)
            .finish()
    }
}

impl<A, S> Feedback<S> for NotFeedback<A, S>
where
    A: Feedback<S>,
    S: State,
{
    fn init_state(&mut self, state: &mut S) -> Result<(), Error> {
        self.first.init_state(state)
    }

    #[allow(clippy::wrong_self_convention)]
    fn is_interesting<EM, OT>(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        input: &S::Input,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        Ok(!self
            .first
            .is_interesting(state, manager, input, observers, exit_kind)?)
    }

    #[inline]
    fn append_metadata<EM, OT>(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        observers: &OT,
        testcase: &mut Testcase<S::Input>,
    ) -> Result<(), Error>
    where
        OT: ObserversTuple<S>,
        EM: EventFirer<State = S>,
    {
        self.first
            .append_metadata(state, manager, observers, testcase)
    }

    #[inline]
    fn discard_metadata(&mut self, state: &mut S, input: &S::Input) -> Result<(), Error> {
        self.first.discard_metadata(state, input)
    }
}

impl<A, S> Named for NotFeedback<A, S>
where
    A: Feedback<S>,
    S: State,
{
    #[inline]
    fn name(&self) -> &str {
        &self.name
    }
}

impl<A, S> NotFeedback<A, S>
where
    A: Feedback<S>,
    S: State,
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
impl<S> Feedback<S> for ()
where
    S: State,
{
    #[allow(clippy::wrong_self_convention)]
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &S::Input,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        Ok(false)
    }
}

/// A [`CrashFeedback`] reports as interesting if the target crashed.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CrashFeedback {}

impl<S> Feedback<S> for CrashFeedback
where
    S: State,
{
    #[allow(clippy::wrong_self_convention)]
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &S::Input,
        _observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
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

/// A feedback factory for crash feedbacks
pub type CrashFeedbackFactory = DefaultFeedbackFactory<CrashFeedback>;

/// A [`TimeoutFeedback`] reduces the timeout value of a run.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TimeoutFeedback {}

impl<S> Feedback<S> for TimeoutFeedback
where
    S: State,
{
    #[allow(clippy::wrong_self_convention)]
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &S::Input,
        _observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
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

/// A feedback factory for timeout feedbacks
pub type TimeoutFeedbackFactory = DefaultFeedbackFactory<TimeoutFeedback>;

/// Nop feedback that annotates execution time in the new testcase, if any
/// for this Feedback, the testcase is never interesting (use with an OR).
/// It decides, if the given [`TimeObserver`] value of a run is interesting.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TimeFeedback {
    name: String,
}

impl<S> Feedback<S> for TimeFeedback
where
    S: State,
{
    #[allow(clippy::wrong_self_convention)]
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &S::Input,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        // TODO Replace with match_name_type when stable
        Ok(false)
    }

    /// Append to the testcase the generated metadata in case of a new corpus item
    #[inline]
    fn append_metadata<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        observers: &OT,
        testcase: &mut Testcase<S::Input>,
    ) -> Result<(), Error>
    where
        OT: ObserversTuple<S>,
        EM: EventFirer<State = S>,
    {
        let observer = observers.match_name::<TimeObserver>(self.name()).unwrap();
        *testcase.exec_time_mut() = *observer.last_runtime();
        Ok(())
    }

    /// Discard the stored metadata in case that the testcase is not added to the corpus
    #[inline]
    fn discard_metadata(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
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
            name: name.to_string(),
        }
    }

    /// Creates a new [`TimeFeedback`], deciding if the given [`TimeObserver`] value of a run is interesting.
    #[must_use]
    pub fn with_observer(observer: &TimeObserver) -> Self {
        Self {
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
    last_addr: usize,
    phantom: PhantomData<T>,
}

impl<S, T> Feedback<S> for ListFeedback<T>
where
    S: State,
    T: Debug + Serialize + serde::de::DeserializeOwned,
{
    #[allow(clippy::wrong_self_convention)]
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &S::Input,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
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
            last_addr: 0,
            phantom: PhantomData,
        }
    }

    /// Creates a new [`TimeFeedback`], deciding if the given [`ListObserver`] value of a run is interesting.
    #[must_use]
    pub fn with_observer(observer: &ListObserver<T>) -> Self {
        Self {
            name: observer.name().to_string(),
            last_addr: 0,
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

impl<S> Feedback<S> for ConstFeedback
where
    S: State,
{
    #[inline]
    #[allow(clippy::wrong_self_convention)]
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &S::Input,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
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
#[allow(clippy::unnecessary_fallible_conversions, unused_qualifications)]
#[allow(missing_docs)]
pub mod pybind {
    use core::ptr;
    use std::cell::UnsafeCell;

    use libafl_bolts::Named;
    use pyo3::prelude::*;

    use super::{
        ConstFeedback, CrashFeedback, Debug, EagerAndFeedback, EagerOrFeedback, FastAndFeedback,
        FastOrFeedback, Feedback, NotFeedback, String, ToString,
    };
    use crate::{
        corpus::{testcase::pybind::PythonTestcaseWrapper, Testcase},
        events::{pybind::PythonEventManager, EventFirer},
        executors::{pybind::PythonExitKind, ExitKind},
        feedbacks::map::pybind::{
            PythonMaxMapFeedbackI16, PythonMaxMapFeedbackI32, PythonMaxMapFeedbackI64,
            PythonMaxMapFeedbackI8, PythonMaxMapFeedbackU16, PythonMaxMapFeedbackU32,
            PythonMaxMapFeedbackU64, PythonMaxMapFeedbackU8,
        },
        inputs::{BytesInput, HasBytesVec},
        observers::{pybind::PythonObserversTuple, ObserversTuple},
        state::pybind::{PythonStdState, PythonStdStateWrapper},
        Error,
    };

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
        #[must_use]
        pub fn new(obj: PyObject) -> Self {
            PyObjectFeedback {
                inner: obj,
                name: UnsafeCell::new(String::new()),
            }
        }
    }

    // crate::impl_serde_pyobjectwrapper!(PyObjectObserver, inner);

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

    impl Feedback<PythonStdState> for PyObjectFeedback {
        fn init_state(&mut self, state: &mut PythonStdState) -> Result<(), Error> {
            Python::with_gil(|py| -> PyResult<()> {
                self.inner
                    .call_method1(py, "init_state", (PythonStdStateWrapper::wrap(state),))?;
                Ok(())
            })?;
            Ok(())
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
            EM: EventFirer<State = PythonStdState>,
            OT: ObserversTuple<PythonStdState>,
        {
            // # Safety
            // We use this observer in Python ony when the ObserverTuple is PythonObserversTuple
            let dont_look_at_this: &PythonObserversTuple =
                unsafe { &*(ptr::from_ref(observers) as *const PythonObserversTuple) };
            let dont_look_at_this2: &PythonEventManager =
                unsafe { &*(ptr::from_mut(manager) as *const PythonEventManager) };
            Ok(Python::with_gil(|py| -> PyResult<bool> {
                let r: bool = self
                    .inner
                    .call_method1(
                        py,
                        "is_interesting",
                        (
                            PythonStdStateWrapper::wrap(state),
                            dont_look_at_this2.clone(),
                            input.bytes(),
                            dont_look_at_this.clone(),
                            PythonExitKind::from(*exit_kind),
                        ),
                    )?
                    .extract(py)?;
                Ok(r)
            })?)
        }

        fn append_metadata<EM, OT>(
            &mut self,
            state: &mut PythonStdState,
            _manager: &mut EM,
            observers: &OT,
            testcase: &mut Testcase<BytesInput>,
        ) -> Result<(), Error>
        where
            OT: ObserversTuple<PythonStdState>,
        {
            // # Safety
            // We use this observer in Python ony when the ObserverTuple is PythonObserversTuple
            let dont_look_at_this: &PythonObserversTuple =
                unsafe { &*(ptr::from_ref(observers) as *const PythonObserversTuple) };
            Python::with_gil(|py| -> PyResult<()> {
                self.inner.call_method1(
                    py,
                    "append_metadata",
                    (
                        PythonStdStateWrapper::wrap(state),
                        dont_look_at_this.clone(),
                        PythonTestcaseWrapper::wrap(testcase),
                    ),
                )?;
                Ok(())
            })?;
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
            })?;
            Ok(())
        }
    }

    #[derive(Clone, Debug)]
    #[pyclass(unsendable, name = "CrashFeedback")]
    pub struct PythonCrashFeedback {
        pub inner: CrashFeedback,
    }

    #[pymethods]
    impl PythonCrashFeedback {
        #[new]
        fn new() -> Self {
            Self {
                inner: CrashFeedback::new(),
            }
        }

        #[must_use]
        pub fn as_feedback(slf: Py<Self>) -> PythonFeedback {
            PythonFeedback::new_crash(slf)
        }
    }

    #[derive(Clone, Debug)]
    #[pyclass(unsendable, name = "ConstFeedback")]
    pub struct PythonConstFeedback {
        pub inner: ConstFeedback,
    }

    #[pymethods]
    impl PythonConstFeedback {
        #[new]
        fn new(v: bool) -> Self {
            Self {
                inner: ConstFeedback::new(v),
            }
        }

        #[must_use]
        pub fn as_feedback(slf: Py<Self>) -> PythonFeedback {
            PythonFeedback::new_const(slf)
        }
    }

    #[derive(Debug)]
    #[pyclass(unsendable, name = "NotFeedback")]
    pub struct PythonNotFeedback {
        pub inner: NotFeedback<PythonFeedback, PythonStdState>,
    }

    #[pymethods]
    impl PythonNotFeedback {
        #[new]
        fn new(feedback: PythonFeedback) -> Self {
            Self {
                inner: NotFeedback::new(feedback),
            }
        }

        #[must_use]
        pub fn as_feedback(slf: Py<Self>) -> PythonFeedback {
            PythonFeedback::new_not(slf)
        }
    }

    macro_rules! define_combined {
        ($feed:ident, $pyname:ident, $pystring:tt, $method:ident) => {
            #[derive(Debug)]
            #[pyclass(unsendable, name = $pystring)]
            pub struct $pyname {
                pub inner: $feed<PythonFeedback, PythonFeedback, PythonStdState>,
            }

            #[pymethods]
            impl $pyname {
                #[new]
                fn new(a: PythonFeedback, b: PythonFeedback) -> Self {
                    Self {
                        inner: $feed::new(a, b),
                    }
                }

                #[must_use]
                pub fn as_feedback(slf: Py<Self>) -> PythonFeedback {
                    PythonFeedback::$method(slf)
                }
            }
        };
    }

    define_combined!(
        EagerAndFeedback,
        PythonEagerAndFeedback,
        "EagerAndFeedback",
        new_and
    );
    define_combined!(
        FastAndFeedback,
        PythonFastAndFeedback,
        "FastAndFeedback",
        new_fast_and
    );
    define_combined!(
        EagerOrFeedback,
        PythonEagerOrFeedback,
        "EagerOrFeedback",
        new_or
    );
    define_combined!(
        FastOrFeedback,
        PythonFastOrFeedback,
        "FastOrFeedback",
        new_fast_or
    );

    #[derive(Clone, Debug)]
    pub enum PythonFeedbackWrapper {
        MaxMapI8(Py<PythonMaxMapFeedbackI8>),
        MaxMapI16(Py<PythonMaxMapFeedbackI16>),
        MaxMapI32(Py<PythonMaxMapFeedbackI32>),
        MaxMapI64(Py<PythonMaxMapFeedbackI64>),
        MaxMapU8(Py<PythonMaxMapFeedbackU8>),
        MaxMapU16(Py<PythonMaxMapFeedbackU16>),
        MaxMapU32(Py<PythonMaxMapFeedbackU32>),
        MaxMapU64(Py<PythonMaxMapFeedbackU64>),
        Crash(Py<PythonCrashFeedback>),
        Const(Py<PythonConstFeedback>),
        Not(Py<PythonNotFeedback>),
        And(Py<PythonEagerAndFeedback>),
        FastAnd(Py<PythonFastAndFeedback>),
        Or(Py<PythonEagerOrFeedback>),
        FastOr(Py<PythonFastOrFeedback>),
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
        ($wrapper:expr, $name:ident, $body:block) => {
            libafl_bolts::unwrap_me_body!($wrapper, $name, $body, PythonFeedbackWrapper,
                {
                    MaxMapI8,
                    MaxMapI16,
                    MaxMapI32,
                    MaxMapI64,
                    MaxMapU8,
                    MaxMapU16,
                    MaxMapU32,
                    MaxMapU64,
                    Crash,
                    Const,
                    Not,
                    And,
                    FastAnd,
                    Or,
                    FastOr
                },
                {
                     Python(py_wrapper) => {
                         let $name = py_wrapper;
                         $body
                     }
                }
            )
        };
    }

    macro_rules! unwrap_me_mut {
        ($wrapper:expr, $name:ident, $body:block) => {
            libafl_bolts::unwrap_me_mut_body!($wrapper, $name, $body, PythonFeedbackWrapper,
                {
                    MaxMapI8,
                    MaxMapI16,
                    MaxMapI32,
                    MaxMapI64,
                    MaxMapU8,
                    MaxMapU16,
                    MaxMapU32,
                    MaxMapU64,
                    Crash,
                    Const,
                    Not,
                    And,
                    FastAnd,
                    Or,
                    FastOr
                },
                {
                     Python(py_wrapper) => {
                         let $name = py_wrapper;
                         $body
                     }
                }
            )
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
        #[must_use]
        pub fn new_max_map_i8(map_feedback: Py<PythonMaxMapFeedbackI8>) -> Self {
            Self {
                wrapper: PythonFeedbackWrapper::MaxMapI8(map_feedback),
                name: UnsafeCell::new(String::new()),
            }
        }

        #[staticmethod]
        #[must_use]
        pub fn new_max_map_i16(map_feedback: Py<PythonMaxMapFeedbackI16>) -> Self {
            Self {
                wrapper: PythonFeedbackWrapper::MaxMapI16(map_feedback),
                name: UnsafeCell::new(String::new()),
            }
        }

        #[staticmethod]
        #[must_use]
        pub fn new_max_map_i32(map_feedback: Py<PythonMaxMapFeedbackI32>) -> Self {
            Self {
                wrapper: PythonFeedbackWrapper::MaxMapI32(map_feedback),
                name: UnsafeCell::new(String::new()),
            }
        }

        #[staticmethod]
        #[must_use]
        pub fn new_max_map_i64(map_feedback: Py<PythonMaxMapFeedbackI64>) -> Self {
            Self {
                wrapper: PythonFeedbackWrapper::MaxMapI64(map_feedback),
                name: UnsafeCell::new(String::new()),
            }
        }

        #[staticmethod]
        #[must_use]
        pub fn new_max_map_u8(map_feedback: Py<PythonMaxMapFeedbackU8>) -> Self {
            Self {
                wrapper: PythonFeedbackWrapper::MaxMapU8(map_feedback),
                name: UnsafeCell::new(String::new()),
            }
        }

        #[staticmethod]
        #[must_use]
        pub fn new_max_map_u16(map_feedback: Py<PythonMaxMapFeedbackU16>) -> Self {
            Self {
                wrapper: PythonFeedbackWrapper::MaxMapU16(map_feedback),
                name: UnsafeCell::new(String::new()),
            }
        }

        #[staticmethod]
        #[must_use]
        pub fn new_max_map_u32(map_feedback: Py<PythonMaxMapFeedbackU32>) -> Self {
            Self {
                wrapper: PythonFeedbackWrapper::MaxMapU32(map_feedback),
                name: UnsafeCell::new(String::new()),
            }
        }

        #[staticmethod]
        #[must_use]
        pub fn new_max_map_u64(map_feedback: Py<PythonMaxMapFeedbackU64>) -> Self {
            Self {
                wrapper: PythonFeedbackWrapper::MaxMapU64(map_feedback),
                name: UnsafeCell::new(String::new()),
            }
        }

        #[staticmethod]
        #[must_use]
        pub fn new_crash(feedback: Py<PythonCrashFeedback>) -> Self {
            Self {
                wrapper: PythonFeedbackWrapper::Crash(feedback),
                name: UnsafeCell::new(String::new()),
            }
        }

        #[staticmethod]
        #[must_use]
        pub fn new_const(feedback: Py<PythonConstFeedback>) -> Self {
            Self {
                wrapper: PythonFeedbackWrapper::Const(feedback),
                name: UnsafeCell::new(String::new()),
            }
        }

        #[staticmethod]
        #[must_use]
        pub fn new_not(feedback: Py<PythonNotFeedback>) -> Self {
            Self {
                wrapper: PythonFeedbackWrapper::Not(feedback),
                name: UnsafeCell::new(String::new()),
            }
        }

        #[staticmethod]
        #[must_use]
        pub fn new_and(feedback: Py<PythonEagerAndFeedback>) -> Self {
            Self {
                wrapper: PythonFeedbackWrapper::And(feedback),
                name: UnsafeCell::new(String::new()),
            }
        }

        #[staticmethod]
        #[must_use]
        pub fn new_fast_and(feedback: Py<PythonFastAndFeedback>) -> Self {
            Self {
                wrapper: PythonFeedbackWrapper::FastAnd(feedback),
                name: UnsafeCell::new(String::new()),
            }
        }

        #[staticmethod]
        #[must_use]
        pub fn new_or(feedback: Py<PythonEagerOrFeedback>) -> Self {
            Self {
                wrapper: PythonFeedbackWrapper::Or(feedback),
                name: UnsafeCell::new(String::new()),
            }
        }

        #[staticmethod]
        #[must_use]
        pub fn new_fast_or(feedback: Py<PythonFastOrFeedback>) -> Self {
            Self {
                wrapper: PythonFeedbackWrapper::FastOr(feedback),
                name: UnsafeCell::new(String::new()),
            }
        }

        #[staticmethod]
        #[must_use]
        pub fn new_py(obj: PyObject) -> Self {
            Self {
                wrapper: PythonFeedbackWrapper::Python(PyObjectFeedback::new(obj)),
                name: UnsafeCell::new(String::new()),
            }
        }

        pub fn unwrap_py(&self) -> Option<PyObject> {
            match &self.wrapper {
                PythonFeedbackWrapper::Python(pyo) => Some(pyo.inner.clone()),
                _ => None,
            }
        }
    }

    impl Named for PythonFeedback {
        fn name(&self) -> &str {
            let s = unwrap_me!(self.wrapper, f, { f.name().to_string() });
            unsafe {
                *self.name.get() = s;
                &*self.name.get()
            }
        }
    }

    impl Feedback<PythonStdState> for PythonFeedback {
        fn init_state(&mut self, state: &mut PythonStdState) -> Result<(), Error> {
            unwrap_me_mut!(self.wrapper, f, {
                Feedback::<PythonStdState>::init_state(f, state)
            })
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
            EM: EventFirer<State = PythonStdState>,
            OT: ObserversTuple<PythonStdState>,
        {
            unwrap_me_mut!(self.wrapper, f, {
                f.is_interesting(state, manager, input, observers, exit_kind)
            })
        }

        fn append_metadata<EM, OT>(
            &mut self,
            state: &mut PythonStdState,
            manager: &mut EM,
            observers: &OT,
            testcase: &mut Testcase<BytesInput>,
        ) -> Result<(), Error>
        where
            OT: ObserversTuple<PythonStdState>,
            EM: EventFirer<State = PythonStdState>,
        {
            unwrap_me_mut!(self.wrapper, f, {
                f.append_metadata(state, manager, observers, testcase)
            })
        }

        fn discard_metadata(
            &mut self,
            state: &mut PythonStdState,
            input: &BytesInput,
        ) -> Result<(), Error> {
            unwrap_me_mut!(self.wrapper, f, { f.discard_metadata(state, input) })
        }
    }

    /// Register the classes to the python module
    pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
        m.add_class::<PythonCrashFeedback>()?;
        m.add_class::<PythonConstFeedback>()?;
        m.add_class::<PythonNotFeedback>()?;
        m.add_class::<PythonEagerAndFeedback>()?;
        m.add_class::<PythonFastAndFeedback>()?;
        m.add_class::<PythonEagerOrFeedback>()?;
        m.add_class::<PythonFastOrFeedback>()?;
        m.add_class::<PythonFeedback>()?;
        Ok(())
    }
}
