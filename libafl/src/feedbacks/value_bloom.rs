//! The [`ValueBloomFeedback`] checks if a value has already been observed in a [`BloomFilter`] and returns `true` if the value is new, adding it to the bloom filter.
//!

use core::hash::Hash;
use std::borrow::Cow;

use fastbloom::BloomFilter;
use libafl_bolts::{
    impl_serdeany,
    tuples::{Handle, MatchNameRef},
    Error, Named,
};
use serde::{Deserialize, Serialize};

use crate::{
    executors::ExitKind,
    feedbacks::{Feedback, StateInitializer},
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
    #[cfg(feature = "track_hit_feedbacks")]
    last_result: Option<bool>,
}

impl<'a, T> ValueBloomFeedback<'a, T> {
    /// Create a new [`ValueBloomFeedback`]
    #[must_use]
    pub fn new(observer_hnd: &Handle<ValueObserver<'a, T>>) -> Self {
        Self::with_name(observer_hnd.name().clone(), observer_hnd)
    }

    /// Create a new [`ValueBloomFeedback`] with a given name
    #[must_use]
    pub fn with_name(name: Cow<'static, str>, observer_hnd: &Handle<ValueObserver<'a, T>>) -> Self {
        Self {
            name,
            observer_hnd: observer_hnd.clone(),
            #[cfg(feature = "track_hit_feedbacks")]
            last_result: None,
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

        let res = if metadata.bloom.contains(val) {
            false
        } else {
            metadata.bloom.insert(val);
            true
        };

        #[cfg(feature = "track_hit_feedbacks")]
        {
            self.last_result = Some(true);
        }

        Ok(res)
    }

    #[cfg(feature = "track_hit_feedbacks")]
    fn last_result(&self) -> Result<bool, Error> {
        self.last_result.ok_or_else(|| Error::illegal_state("No last result set in `ValueBloomFeedback`. Either `is_interesting` has never been called or the fuzzer restarted in the meantime."))
    }
}

#[cfg(test)]
mod test {
    use core::ptr::write_volatile;

    use libafl_bolts::{ownedref::OwnedRef, serdeany::NamedSerdeAnyMap, tuples::Handled};
    use tuple_list::tuple_list;

    use super::ValueBloomFeedback;
    use crate::{
        events::NopEventManager,
        executors::ExitKind,
        feedbacks::{Feedback, StateInitializer},
        inputs::NopInput,
        observers::ValueObserver,
        HasNamedMetadata,
    };

    static mut VALUE: u32 = 0;

    struct NamedMetadataState {
        map: NamedSerdeAnyMap,
    }

    impl HasNamedMetadata for NamedMetadataState {
        fn named_metadata_map(&self) -> &NamedSerdeAnyMap {
            &self.map
        }

        fn named_metadata_map_mut(&mut self) -> &mut NamedSerdeAnyMap {
            &mut self.map
        }
    }

    #[test]
    fn test_value_bloom_feedback() {
        let value_ptr = unsafe { OwnedRef::from_ptr(&raw mut VALUE) };

        let observer = ValueObserver::new("test_value", value_ptr);

        let mut vbf = ValueBloomFeedback::new(&observer.handle());

        let mut state = NamedMetadataState {
            map: NamedSerdeAnyMap::new(),
        };
        vbf.init_state(&mut state).unwrap();

        let observers = tuple_list!(observer);
        let mut mgr = NopEventManager::<NamedMetadataState>::new();
        let input = NopInput {};
        let exit_ok = ExitKind::Ok;

        let first_eval = vbf
            .is_interesting(&mut state, &mut mgr, &input, &observers, &exit_ok)
            .unwrap();
        assert_eq!(first_eval, true);

        let second_eval = vbf
            .is_interesting(&mut state, &mut mgr, &input, &observers, &exit_ok)
            .unwrap();

        assert_ne!(first_eval, second_eval);

        unsafe {
            write_volatile(&raw mut VALUE, 1234_u32);
        }

        let next_eval = vbf
            .is_interesting(&mut state, &mut mgr, &input, &observers, &exit_ok)
            .unwrap();
        assert_eq!(next_eval, true);
    }
}
