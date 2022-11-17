use libafl::{
    prelude::{
        EventFirer, ExitKind, Feedback, HasClientPerfMonitor, Named, ObserversTuple, UsesInput,
    },
    Error,
};
use serde::{Deserialize, Serialize};

/// A [`ReturnValueFeedback`] reports as interesting if `LLVMTestOneInput == 42`
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ReturnValueFeedback {}

impl<S> Feedback<S> for ReturnValueFeedback
where
    S: HasClientPerfMonitor + UsesInput,
{
    #[allow(clippy::wrong_self_convention)]
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &S::Input,
        _observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer,
        OT: ObserversTuple<S>,
    {
        if let ExitKind::Oom = exit_kind {
            //HACK: we need to add a new ExitKind for XSS
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

impl Named for ReturnValueFeedback {
    #[inline]
    fn name(&self) -> &str {
        "ReturnValueFeedback"
    }
}

impl ReturnValueFeedback {
    /// Creates a new [`ReturnValueFeedback`]
    #[must_use]
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for ReturnValueFeedback {
    fn default() -> Self {
        Self::new()
    }
}
