//! Feedbacks and associated metadata for detecting whether a given testcase was transferred from
//! another node.

use libafl_bolts::{impl_serdeany, Error, Named};
use serde::{Deserialize, Serialize};

use crate::{
    events::EventFirer,
    executors::ExitKind,
    feedbacks::Feedback,
    observers::ObserversTuple,
    state::{HasMetadata, State},
};

/// Constant name of the [`TransferringMetadata`].
pub const TRANSFERRED_FEEDBACK_NAME: &str = "transferred_feedback_internal";

/// Metadata which denotes whether we are currently transferring an input. Implementors of
/// multi-node communication systems (like [`crate::events::LlmpEventManager`]) should wrap any
/// [`crate::EvaluatorObservers::evaluate_input_with_observers`] or
/// [`crate::ExecutionProcessor::process_execution`] calls with setting this metadata to true/false
/// before and after.
#[derive(Copy, Clone, Debug, Deserialize, Serialize)]
pub struct TransferringMetadata {
    transferring: bool,
}

impl_serdeany!(TransferringMetadata);

impl TransferringMetadata {
    /// Indicate to the metadata that we are currently transferring data.
    pub fn set_transferring(&mut self, transferring: bool) {
        self.transferring = transferring;
    }
}

/// Simple feedback which may be used to test whether the testcase was transferred from another node
/// in a multi-node fuzzing arrangement.
#[derive(Copy, Clone, Debug)]
pub struct TransferredFeedback;

impl Named for TransferredFeedback {
    fn name(&self) -> &str {
        TRANSFERRED_FEEDBACK_NAME
    }
}

impl<S> Feedback<S> for TransferredFeedback
where
    S: HasMetadata + State,
{
    fn init_state(&mut self, state: &mut S) -> Result<(), Error> {
        state.add_metadata(TransferringMetadata { transferring: true });
        Ok(())
    }

    fn is_interesting<EM, OT>(
        &mut self,
        state: &mut S,
        _manager: &mut EM,
        _input: &S::Input,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        Ok(state.metadata::<TransferringMetadata>()?.transferring)
    }
}
