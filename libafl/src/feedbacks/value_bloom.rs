//! The [`ValueBloomFeedback`] checks if a value has already been observed in a [`BloomFilter`] and returns `true` if the value is new, adding it to the bloom filter.
//!

use core::hash::Hash;
use std::{borrow::Cow, string::ToString};

use fastbloom::BloomFilter;
use libafl_bolts::{
    impl_serdeany,
    tuples::{Handle, MatchNameRef},
    Error, Named,
};
use serde::{Deserialize, Serialize};

use super::{Feedback, StateInitializer};
use crate::{
    executors::ExitKind,
    observers::{ObserversTuple, ValueObserver},
    HasNamedMetadata,
};

impl_serdeany!(ValueBloomFeedbackMetadata);

#[derive(Debug, Serialize, Deserialize)]
struct ValueBloomFeedbackMetadata {
    bloom: BloomFilter,
}

/// A Feedback that returns `true` for `is_interesting` for new values it found in a [`ValueObserver`].
/// It keeps track of the previously seen values in a [`BloomFilter`].
#[derive(Debug)]
pub struct ValueBloomFeedback<'a, T> {
    name: Cow<'static, str>,
    observer_hnd: Handle<ValueObserver<'a, T>>,
}

impl<'a, T> ValueBloomFeedback<'a, T> {
    /// Create a new [`ValueBloomFeedback`]
    #[must_use]
    pub fn new(observer_hnd: &Handle<ValueObserver<'a, T>>, name: &str) -> Self {
        Self {
            name: Cow::Owned(name.to_string()),
            observer_hnd: observer_hnd.clone(),
        }
    }
}

impl<T> Named for ValueBloomFeedback<'_, T> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<S: HasNamedMetadata, T> StateInitializer<S> for ValueBloomFeedback<'_, T> {
    fn init_state(&mut self, state: &mut S) -> Result<(), Error> {
        let _ =
            state.named_metadata_or_insert_with::<ValueBloomFeedbackMetadata>(&self.name, || {
                ValueBloomFeedbackMetadata {
                    bloom: BloomFilter::with_false_pos(0.001).expected_items(1024),
                }
            });
        Ok(())
    }
}

impl<EM, I, OT: ObserversTuple<I, S>, S: HasNamedMetadata, T: Hash> Feedback<EM, I, OT, S>
    for ValueBloomFeedback<'_, T>
{
    fn is_interesting(
        &mut self,
        state: &mut S,
        _manager: &mut EM,
        _input: &I,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error> {
        let Some(observer) = observers.get(&self.observer_hnd) else {
            return Err(Error::illegal_state(format!(
                "Observer {:?} not found",
                self.observer_hnd
            )));
        };
        let val = observer.value.as_ref();

        let metadata = state.named_metadata_mut::<ValueBloomFeedbackMetadata>(&self.name)?;

        if metadata.bloom.contains(val) {
            Ok(true)
        } else {
            metadata.bloom.insert(val);
            Ok(false)
        }
    }
}
