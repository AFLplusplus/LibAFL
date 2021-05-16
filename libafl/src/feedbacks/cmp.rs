use alloc::{
    string::{String, ToString},
};
use core::marker::PhantomData;
use num::Integer;
use serde::{Deserialize, Serialize};

use crate::{
    bolts::tuples::Named,
    executors::ExitKind,
    feedbacks::{Feedback, FeedbackState, FeedbackStatesTuple},
    inputs::Input,
    observers::{CmpObserver, ObserversTuple},
    state::{HasFeedbackStates, HasMetadata},
    utils::AsSlice,
    Error,
};

/// A state metadata holding a list of values logged from comparisons
#[derive(Serialize, Deserialize)]
pub struct CmpValuesMetadata {
    /// A `list` of values.
    pub list: Vec<(u64, u64)>,
}
 
crate::impl_serdeany!(CmpValuesMetadata);

impl AsSlice<(u64, u64)> for CmpValuesMetadata {
    /// Convert to a slice
    #[must_use]
    fn as_slice(&self) -> &[(u64, u64)] {
        self.list.as_slice()
    }
}

impl CmpValuesMetadata {
    /// Creates a new [`struct@CmpValuesMetadata`]
    #[must_use]
    pub fn new(list: Vec<(u64, u64)>) -> Self {
        Self { list }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CmpFeedback<T> {
    name: String,
    phantom: PhantomData<T>
}

impl<I, S, T> Feedback<I, S> for CmpFeedback<T>
where
    I: Input,
{
    fn is_interesting<OT>(
        &mut self,
        _state: &mut S,
        _input: &I,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        OT: ObserversTuple,
    {
        // TODO Replace with match_name_type when stable
        let observer = observers.match_name::<CmpObserver<T>>(self.name()).unwrap();
        // TODO
        Ok(false)
    }
}

impl Named for CmpFeedback {
    #[inline]
    fn name(&self) -> &str {
        self.name.as_str()
    }
}

impl CmpFeedback {
    /// Creates a new [`CmpFeedback`]
    #[must_use]
    pub fn new(name: &'static str) -> Self {
        Self {
            name: name.to_string(),
            phantom: PhantomData
        }
    }

    /// Creates a new [`CmpFeedback`]
    #[must_use]
    pub fn new_with_observer(observer: &CmpObserver<T>) -> Self {
        Self {
            name: observer.name().to_string(),
            phantom: PhantomData
        }
    }
}
