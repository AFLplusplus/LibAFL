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
    state::{HasClientPerfStats, HasMetadata},
    Error,
};

/// The concolic feedback. It is used to attach concolic tracing metadata to the testcase.
/// This feedback should be used in combination with another feedback as this feedback always considers testcases
/// to be not interesting.
/// Requires a [`ConcolicObserver`] to observe the concolic trace.
pub struct ConcolicFeedback {
    name: String,
    metadata: Option<ConcolicMetadata>,
}

impl ConcolicFeedback {
    #[allow(unused)]
    pub fn from_observer(observer: &ConcolicObserver) -> Self {
        Self {
            name: observer.name().to_owned(),
            metadata: None,
        }
    }
}

impl Named for ConcolicFeedback {
    fn name(&self) -> &str {
        &self.name
    }
}

impl<I, S> Feedback<I, S> for ConcolicFeedback
where
    I: Input,
    S: HasClientPerfStats,
{
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &I,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<I, S>,
        OT: ObserversTuple<I, S>,
    {
        self.metadata = observers
            .match_name::<ConcolicObserver>(&self.name)
            .map(ConcolicObserver::create_metadata_from_current_map);
        Ok(false)
    }

    fn append_metadata(
        &mut self,
        _state: &mut S,
        _testcase: &mut Testcase<I>,
    ) -> Result<(), Error> {
        if let Some(metadata) = self.metadata.take() {
            _testcase.metadata_mut().insert(metadata);
        }
        Ok(())
    }

    fn discard_metadata(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        Ok(())
    }
}
