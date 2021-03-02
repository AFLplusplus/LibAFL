//! The feedbacks reduce observer state after each run to a single `is_interesting`-value.
//! If a testcase is interesting, it may be added to a Corpus.

pub mod map;
pub use map::*;

use serde::{Deserialize, Serialize};

use crate::{
    bolts::tuples::{Named, TupleList},
    corpus::Testcase,
    executors::ExitKind,
    inputs::Input,
    observers::ObserversTuple,
    Error,
};

/// Feedbacks evaluate the observers.
/// Basically, they reduce the information provided by an observer to a value,
/// indicating the "interestingness" of the last run.
pub trait Feedback<I>: Named + serde::Serialize + serde::de::DeserializeOwned + 'static
where
    I: Input,
{
    /// is_interesting should return the "Interestingness" from 0 to 255 (percent times 2.55)
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

    /*
    /// Serialize this feedback's state only, to be restored later using deserialize_state
    /// As opposed to completely serializing the observer, this is only needed when the fuzzer is to be restarted
    /// If no state is needed to be kept, just return an empty vec.
    /// Example:
    /// >> The virgin_bits map in AFL needs to be in sync with the corpus
    #[inline]
    fn serialize_state(&mut self) -> Result<Vec<u8>, Error> {
        Ok(vec![])
    }

    /// Restore the state from a given vec, priviously stored using `serialize_state`
    #[inline]
    fn deserialize_state(&mut self, serialized_state: &[u8]) -> Result<(), Error> {
        let _ = serialized_state;
        Ok(())
    }

    // TODO: Restore_from
    fn restore_from(&mut self, restore_from: Self) -> Result<(), Error> {
        Ok(())
    }
    */
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

    /*
    /// Restores the state from each of the containing feedbacks in a list of the same shape.
    /// Used (prette exclusively) to restore the feedback states after a crash.
    fn restore_state_from_all(&mut self, restore_from: &Self) -> Result<(), Error>;
    */
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

    /*
    fn restore_state_from_all(&mut self, restore_from: &Self) -> Result<(), Error> {
        Ok(())
    }
    */
}

impl<Head, Tail, I> FeedbacksTuple<I> for (Head, Tail)
where
    Head: Feedback<I>,
    Tail: FeedbacksTuple<I> + TupleList,
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
