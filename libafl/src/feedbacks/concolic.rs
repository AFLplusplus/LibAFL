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
    inputs::Input,
    observers::{
        concolic::{ConcolicMetadata, ConcolicObserver},
        ObserversTuple,
    },
    prelude::{HasClientPerfMonitor, State},
    state::HasMetadata,
    Error,
};

/// The concolic feedback. It is used to attach concolic tracing metadata to the testcase.
/// This feedback should be used in combination with another feedback as this feedback always considers testcases
/// to be not interesting.
/// Requires a [`ConcolicObserver`] to observe the concolic trace.
#[derive(Debug)]
pub struct ConcolicFeedback<I, S> {
    name: String,
    metadata: Option<ConcolicMetadata>,
    phantom: PhantomData<(I, S)>,
}

impl<I, S> ConcolicFeedback<I, S> {
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

impl<I, S> Named for ConcolicFeedback<I, S> {
    fn name(&self) -> &str {
        &self.name
    }
}

impl<I, S> Feedback for ConcolicFeedback<I, S>
where
    I: Input,
    S: State<Input = I> + Debug + HasClientPerfMonitor,
{
    type Input = I;

    type State = S;

    #[allow(clippy::wrong_self_convention)]
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut Self::State,
        _manager: &mut EM,
        _input: &Self::Input,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<Input = I, State = S>,
        OT: ObserversTuple<I, S>,
    {
        self.metadata = observers
            .match_name::<ConcolicObserver>(&self.name)
            .map(ConcolicObserver::create_metadata_from_current_map);
        Ok(false)
    }

    fn append_metadata(
        &mut self,
        _state: &mut Self::State,
        _testcase: &mut Testcase<Self::Input>,
    ) -> Result<(), Error> {
        if let Some(metadata) = self.metadata.take() {
            _testcase.metadata_mut().insert(metadata);
        }
        Ok(())
    }

    fn discard_metadata(
        &mut self,
        _state: &mut Self::State,
        _input: &Self::Input,
    ) -> Result<(), Error> {
        Ok(())
    }
}
