//! Concolic feedback for concolic fuzzing.
//! It is used to attach concolic tracing metadata to the testcase.
//! This feedback should be used in combination with another feedback as this feedback always considers testcases
//! to be not interesting.
//! Requires a [`ConcolicObserver`] to observe the concolic trace.
use alloc::borrow::Cow;
use core::{fmt::Debug, marker::PhantomData};

use libafl_bolts::{
    tuples::{Handle, Handled, MatchNameRef},
    Named,
};

use crate::{
    corpus::Testcase,
    events::EventFirer,
    executors::ExitKind,
    feedbacks::Feedback,
    inputs::UsesInput,
    observers::{concolic::ConcolicObserver, ObserversTuple},
    state::State,
    Error, HasMetadata,
};

/// The concolic feedback. It is used to attach concolic tracing metadata to the testcase.
/// This feedback should be used in combination with another feedback as this feedback always considers testcases
/// to be not interesting.
/// Requires a [`ConcolicObserver`] to observe the concolic trace.
#[derive(Debug)]
pub struct ConcolicFeedback<'map, S> {
    observer_handle: Handle<ConcolicObserver<'map>>,
    phantom: PhantomData<S>,
}

impl<'map, S> ConcolicFeedback<'map, S> {
    /// Creates a concolic feedback from an observer
    #[allow(unused)]
    #[must_use]
    pub fn from_observer(observer: &ConcolicObserver<'map>) -> Self {
        Self {
            observer_handle: observer.handle(),
            phantom: PhantomData,
        }
    }
}

impl<S> Named for ConcolicFeedback<'_, S> {
    fn name(&self) -> &Cow<'static, str> {
        self.observer_handle.name()
    }
}

impl<S> Feedback<S> for ConcolicFeedback<'_, S>
where
    S: State,
{
    #[allow(clippy::wrong_self_convention)]
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &<S as UsesInput>::Input,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        Ok(false)
    }

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
        if let Some(metadata) = observers
            .get(&self.observer_handle)
            .map(ConcolicObserver::create_metadata_from_current_map)
        {
            testcase.metadata_map_mut().insert(metadata);
        }
        Ok(())
    }

    fn discard_metadata(
        &mut self,
        _state: &mut S,
        _input: &<S as UsesInput>::Input,
    ) -> Result<(), Error> {
        Ok(())
    }
}
