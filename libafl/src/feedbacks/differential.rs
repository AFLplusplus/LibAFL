//! Diff Feedback, comparing the content of two observers of the same type.
//!

use alloc::string::{String, ToString};
use core::{
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
};

use libafl_bolts::{tuples::MatchName, Named};
use serde::{Deserialize, Serialize};

use crate::{
    events::EventFirer,
    executors::ExitKind,
    feedbacks::Feedback,
    inputs::Input,
    observers::{Observer, ObserversTuple},
    state::{HasMetadata, State},
    Error,
};

/// The result of a differential test between two observers.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum DiffResult {
    /// The two observers report the same outcome.
    Equal,
    /// The two observers report different outcomes.
    Diff,
}

impl DiffResult {
    /// Returns `true` if the two observers report the same outcome.
    #[must_use]
    pub fn is_equal(&self) -> bool {
        match self {
            DiffResult::Equal => true,
            DiffResult::Diff => false,
        }
    }

    /// Returns `true` if the two observers report different outcomes.
    #[must_use]
    pub fn is_diff(&self) -> bool {
        !self.is_equal()
    }
}

/// A [`DiffFeedback`] compares the content of two [`Observer`]s using the given compare function.
#[derive(Serialize, Deserialize)]
pub struct DiffFeedback<F, I, O1, O2, S>
where
    F: FnMut(&O1, &O2) -> DiffResult,
{
    /// This feedback's name
    name: String,
    /// The first observer to compare against
    o1_name: String,
    /// The second observer to compare against
    o2_name: String,
    /// The function used to compare the two observers
    compare_fn: F,
    phantomm: PhantomData<(O1, O2, I, S)>,
}

impl<F, I, O1, O2, S> DiffFeedback<F, I, O1, O2, S>
where
    F: FnMut(&O1, &O2) -> DiffResult,
    O1: Named,
    O2: Named,
{
    /// Create a new [`DiffFeedback`] using two observers and a test function.
    pub fn new(name: &str, o1: &O1, o2: &O2, compare_fn: F) -> Result<Self, Error> {
        let o1_name = o1.name().to_string();
        let o2_name = o2.name().to_string();
        if o1_name == o2_name {
            Err(Error::illegal_argument(format!(
                "DiffFeedback: observer names must be different (both were {o1_name})"
            )))
        } else {
            Ok(Self {
                o1_name,
                o2_name,
                name: name.to_string(),
                compare_fn,
                phantomm: PhantomData,
            })
        }
    }
}

impl<F, I, O1, O2, S> Named for DiffFeedback<F, I, O1, O2, S>
where
    F: FnMut(&O1, &O2) -> DiffResult,
    O1: Named,
    O2: Named,
{
    fn name(&self) -> &str {
        &self.name
    }
}

impl<F, I, O1, O2, S> Debug for DiffFeedback<F, I, O1, O2, S>
where
    F: FnMut(&O1, &O2) -> DiffResult,
    O1: Named,
    O2: Named,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DiffFeedback {{ name: {}, o1: {}, o2: {} }}",
            self.name, self.o1_name, self.o2_name
        )
    }
}

impl<F, I, O1, O2, S> Feedback<S> for DiffFeedback<F, I, O1, O2, S>
where
    F: FnMut(&O1, &O2) -> DiffResult,
    I: Input,
    S: HasMetadata + State<Input = I>,
    O1: Observer<S>,
    O2: Observer<S>,
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
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S> + MatchName,
    {
        fn err(name: &str) -> Error {
            Error::illegal_argument(format!("DiffFeedback: observer {name} not found"))
        }
        let o1: &O1 = observers
            .match_name(&self.o1_name)
            .ok_or_else(|| err(&self.o1_name))?;
        let o2: &O2 = observers
            .match_name(&self.o2_name)
            .ok_or_else(|| err(&self.o2_name))?;

        Ok((self.compare_fn)(o1, o2) == DiffResult::Diff)
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::{String, ToString};
    use core::marker::PhantomData;

    use libafl_bolts::{tuples::tuple_list, Named};

    use crate::{
        events::EventFirer,
        executors::ExitKind,
        feedbacks::{differential::DiffResult, DiffFeedback, Feedback},
        inputs::{BytesInput, UsesInput},
        observers::Observer,
        state::{NopState, State, UsesState},
    };

    #[derive(Debug)]
    struct NopObserver {
        name: String,
        value: bool,
    }
    impl NopObserver {
        fn new(name: &str, value: bool) -> Self {
            Self {
                name: name.to_string(),
                value,
            }
        }
    }
    impl<S> Observer<S> for NopObserver where S: UsesInput {}
    impl PartialEq for NopObserver {
        fn eq(&self, other: &Self) -> bool {
            self.value == other.value
        }
    }
    impl Named for NopObserver {
        fn name(&self) -> &str {
            &self.name
        }
    }

    struct NopEventFirer<S> {
        phantom: PhantomData<S>,
    }
    impl<S> UsesState for NopEventFirer<S>
    where
        S: State,
    {
        type State = S;
    }
    impl<S> EventFirer for NopEventFirer<S>
    where
        S: State,
    {
        fn fire(
            &mut self,
            _state: &mut S,
            _event: crate::events::Event<S::Input>,
        ) -> Result<(), crate::Error> {
            Ok(())
        }
    }

    fn test_diff(should_equal: bool) {
        let mut nop_state = NopState::new();

        let o1 = NopObserver::new("o1", true);
        let o2 = NopObserver::new("o2", should_equal);

        let mut diff_feedback = DiffFeedback::new("diff_feedback", &o1, &o2, |o1, o2| {
            if o1 == o2 {
                DiffResult::Equal
            } else {
                DiffResult::Diff
            }
        })
        .unwrap();
        let observers = tuple_list![o1, o2];
        assert_eq!(
            !should_equal,
            diff_feedback
                .is_interesting(
                    &mut nop_state,
                    &mut NopEventFirer {
                        phantom: PhantomData
                    },
                    &BytesInput::new(vec![0]),
                    &observers,
                    &ExitKind::Ok
                )
                .unwrap()
        );
    }

    #[test]
    fn test_diff_eq() {
        test_diff(true);
    }

    #[test]
    fn test_diff_neq() {
        test_diff(false);
    }
}
