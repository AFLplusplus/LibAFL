use libafl_bolts::{impl_serdeany, Error, Named};
use serde::{Deserialize, Serialize};

use crate::{
    events::EventFirer, executors::ExitKind, feedbacks::Feedback, observers::ObserversTuple,
    state::HasMetadata,
};

pub const TRANSFERRED_FEEDBACK_NAME: &str = "transferred_feedback_internal";

#[derive(Copy, Clone, Deserialize, Serialize)]
pub struct TransferringMetadata {
    transferring: bool,
}

impl_serdeany!(TransferringMetadata);

impl TransferringMetadata {
    pub fn set_transferring(&mut self, transferring: bool) {
        self.transferring = transferring;
    }
}

#[derive(Copy, Clone)]
pub struct TransferredFeedback;

impl Named for TransferredFeedback {
    fn name(&self) -> &str {
        TRANSFERRED_FEEDBACK_NAME
    }
}

impl<S> Feedback<S> for TransferredFeedback
where
    S: HasMetadata,
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
