use libafl::{
    events::{Event, EventManagerHook, EventWithStats},
    state::Stoppable,
    Error,
};
use libafl_bolts::ClientId;

#[derive(Copy, Clone)]
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
        event: &EventWithStats<I>,
    ) -> Result<bool, Error> {
        if self.exit_on_solution && matches!(event.event(), Event::Objective { .. }) {
            // TODO: dump state
            state.request_stop();
        }
        Ok(true)
    }
}
