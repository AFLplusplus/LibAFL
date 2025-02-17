use libafl::{
    events::{Event, EventManagerHook},
    state::Stoppable,
    Error,
};
use libafl_bolts::ClientId;

#[derive(Clone, Copy)]
pub struct LibAflFuzzEventHook {
    exit_on_solution: bool,
}

impl<I, S> EventManagerHook<I, S> for LibAflFuzzEventHook
where
    S: Stoppable,
{
    fn pre_receive(
        &mut self,
        state: &mut S,
        _client_id: ClientId,
        event: &Event<I>,
    ) -> Result<bool, Error> {
        if self.exit_on_solution && matches!(event, Event::Objective { .. }) {
            // TODO: dump state
            state.request_stop();
        }
        Ok(true)
    }
}
