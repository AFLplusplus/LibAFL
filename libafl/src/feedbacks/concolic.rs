//! Concolic feedback for concolic fuzzing.
//! It is used to attach concolic tracing metadata to the testcase.
//! This feedback should be used in combination with another feedback as this feedback always considers testcases
//! to be not interesting.
//! Requires a [`ConcolicObserver`] to observe the concolic trace.
use alloc::{borrow::ToOwned, string::String};
use core::{fmt::Debug, marker::PhantomData};

use crate::{
    bolts::tuples::Named,
    corpus::Testcase,
    events::EventFirer,
    executors::ExitKind,
    feedbacks::Feedback,
    inputs::UsesInput,
    observers::{
        concolic::{ConcolicMetadata, ConcolicObserver},
        ObserversTuple,
    },
    state::{HasClientPerfMonitor, HasMetadata},
    Error,
};

/// The concolic feedback. It is used to attach concolic tracing metadata to the testcase.
/// This feedback should be used in combination with another feedback as this feedback always considers testcases
/// to be not interesting.
/// Requires a [`ConcolicObserver`] to observe the concolic trace.
#[derive(Debug)]
pub struct ConcolicFeedback<S> {
    name: String,
    metadata: Option<ConcolicMetadata>,
    phantom: PhantomData<S>,
}

impl<S> ConcolicFeedback<S> {
    /// Creates a concolic feedback from an observer
    #[allow(unused)]
    #[must_use]
    pub fn from_observer(observer: &ConcolicObserver) -> Self {
        Self {
            name: observer.name().to_owned(),
            metadata: None,
            phantom: PhantomData,
        }
    }
}

impl<S> Named for ConcolicFeedback<S> {
    fn name(&self) -> &str {
        &self.name
    }
}

impl<S> Feedback<S> for ConcolicFeedback<S>
where
    S: UsesInput + Debug + HasClientPerfMonitor,
{
    #[allow(clippy::wrong_self_convention)]
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &<S as UsesInput>::Input,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        self.metadata = observers
            .match_name::<ConcolicObserver>(&self.name)
            .map(ConcolicObserver::create_metadata_from_current_map);
        Ok(false)
    }

    fn append_metadata(
        &mut self,
        _state: &mut S,
        _testcase: &mut Testcase<<S as UsesInput>::Input>,
    ) -> Result<(), Error> {
        if let Some(metadata) = self.metadata.take() {
            _testcase.metadata_mut().insert(metadata);
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
