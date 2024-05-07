//! Feedback and metatadata for stderr and stdout.

use alloc::{borrow::Cow, string::String};

use libafl_bolts::{
    impl_serdeany,
    tuples::{Handle, Handled, MatchNameRef},
    Named,
};
use serde::{Deserialize, Serialize};

use crate::{
    corpus::Testcase,
    events::EventFirer,
    executors::ExitKind,
    feedbacks::Feedback,
    observers::{ObserversTuple, StdErrObserver, StdOutObserver},
    state::State,
    Error, HasMetadata,
};

/// Metadata for [`StdOutToMetadataFeedback`].
#[derive(Debug, Serialize, Deserialize)]
pub struct StdOutMetadata {
    #[allow(missing_docs)]
    pub stdout: String,
}

impl_serdeany!(StdOutMetadata);

/// Nop feedback that annotates stdout in the new testcase. The testcase
/// is never interesting (use with an OR).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StdOutToMetadataFeedback {
    o_ref: Handle<StdOutObserver>,
}

impl<S> Feedback<S> for StdOutToMetadataFeedback
where
    S: State,
{
    #[allow(clippy::wrong_self_convention)]
    #[inline]
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &S::Input,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        Ok(false)
    }

    /// Append to the testcase the generated metadata in case of a new corpus item.
    #[inline]
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
        let observer = observers
            .get(&self.o_ref)
            .ok_or(Error::illegal_state("StdOutObserver is missing"))?;
        let buffer = observer
            .stdout
            .as_ref()
            .ok_or(Error::illegal_state("StdOutObserver has no stdout"))?;
        let stdout = String::from_utf8_lossy(buffer).into_owned();

        testcase
            .metadata_map_mut()
            .insert(StdOutMetadata { stdout });

        Ok(())
    }

    /// Discard the stored metadata in case that the testcase is not added to the corpus.
    #[inline]
    fn discard_metadata(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        Ok(())
    }
}

impl Named for StdOutToMetadataFeedback {
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        self.o_ref.name()
    }
}

impl StdOutToMetadataFeedback {
    /// Creates a new [`StdOutToMetadataFeedback`].
    #[must_use]
    pub fn new(observer: &StdOutObserver) -> Self {
        Self {
            o_ref: observer.handle(),
        }
    }
}

/// Metadata for [`StdErrToMetadataFeedback`].
#[derive(Debug, Serialize, Deserialize)]
pub struct StdErrMetadata {
    #[allow(missing_docs)]
    pub stderr: String,
}

impl_serdeany!(StdErrMetadata);

/// Nop feedback that annotates stderr in the new testcase. The testcase
/// is never interesting (use with an OR).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StdErrToMetadataFeedback {
    o_ref: Handle<StdErrObserver>,
}

impl<S> Feedback<S> for StdErrToMetadataFeedback
where
    S: State,
{
    #[allow(clippy::wrong_self_convention)]
    #[inline]
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &S::Input,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        Ok(false)
    }

    /// Append to the testcase the generated metadata in case of a new corpus item.
    #[inline]
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
        let observer = observers
            .get(&self.o_ref)
            .ok_or(Error::illegal_state("StdErrObserver is missing"))?;
        let buffer = observer
            .stderr
            .as_ref()
            .ok_or(Error::illegal_state("StdErrObserver has no stderr"))?;
        let stderr = String::from_utf8_lossy(buffer).into_owned();

        testcase
            .metadata_map_mut()
            .insert(StdErrMetadata { stderr });

        Ok(())
    }

    /// Discard the stored metadata in case that the testcase is not added to the corpus.
    #[inline]
    fn discard_metadata(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        Ok(())
    }
}

impl Named for StdErrToMetadataFeedback {
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        self.o_ref.name()
    }
}

impl StdErrToMetadataFeedback {
    /// Creates a new [`StdErrToMetadataFeedback`].
    #[must_use]
    pub fn new(observer: &StdErrObserver) -> Self {
        Self {
            o_ref: observer.handle(),
        }
    }
}
