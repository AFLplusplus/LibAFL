//! The [`BoolValueFeedback`] is a [`Feedback`] returning `true` or `false` as the `is_interesting` value.

use alloc::borrow::Cow;

use libafl_bolts::{
    tuples::{Handle, MatchNameRef},
    Error, Named,
};

use crate::{
    feedbacks::{Feedback, StateInitializer},
    observers::{ObserversTuple, ValueObserver},
    HasNamedMetadata,
};

/// This feedback returns `true` or `false` as the `is_interesting` value.
#[derive(Debug)]
pub struct BoolValueFeedback<'a> {
    name: Cow<'static, str>,
    observer_hnd: Handle<ValueObserver<'a, bool>>,
    #[cfg(feature = "track_hit_feedbacks")]
    last_result: Option<bool>,
}

impl<'a> BoolValueFeedback<'a> {
    /// Create a new [`BoolValueFeedback`]
    #[must_use]
    pub fn new(observer_hnd: &Handle<ValueObserver<'a, bool>>) -> Self {
        Self::with_name(observer_hnd.name().clone(), observer_hnd)
    }

    /// Create a new [`BoolValueFeedback`] with a given name
    #[must_use]
    pub fn with_name(
        name: Cow<'static, str>,
        observer_hnd: &Handle<ValueObserver<'a, bool>>,
    ) -> Self {
        Self {
            name,
            observer_hnd: observer_hnd.clone(),
            #[cfg(feature = "track_hit_feedbacks")]
            last_result: None,
        }
    }
}

impl Named for BoolValueFeedback<'_> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<S> StateInitializer<S> for BoolValueFeedback<'_> {
    fn init_state(&mut self, _state: &mut S) -> Result<(), Error> {
        Ok(())
    }
}

impl<EM, I, OT, S> Feedback<EM, I, OT, S> for BoolValueFeedback<'_>
where
    OT: ObserversTuple<I, S>,
    S: HasNamedMetadata,
{
    fn is_interesting(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &I,
        observers: &OT,
        _exit_kind: &crate::executors::ExitKind,
    ) -> Result<bool, Error> {
        let Some(observer) = observers.get(&self.observer_hnd) else {
            return Err(Error::illegal_state(format!(
                "Observer {:?} not found",
                self.observer_hnd
            )));
        };

        let val = observer.value.as_ref();

        Ok(*val)
    }

    fn append_metadata(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _observers: &OT,
        _testcase: &mut crate::corpus::Testcase<I>,
    ) -> Result<(), Error> {
        Ok(())
    }

    fn discard_metadata(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        Ok(())
    }

    #[cfg(feature = "track_hit_feedbacks")]
    fn last_result(&self) -> Result<bool, Error> {
        self.last_result.ok_or_else(|| Error::illegal_state("No last result set in `ValueBloomFeedback`. Either `is_interesting` has never been called or the fuzzer restarted in the meantime."))
    }
}
