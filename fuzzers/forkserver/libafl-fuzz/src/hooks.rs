use libafl::{
    events::{Event, EventManagerHook},
    state::{State, Stoppable},
    Error,
};
use libafl_bolts::ClientDescription;

#[derive(Clone, Copy)]
pub struct LibAflFuzzEventHook {
    exit_on_solution: bool,
}

impl<S> EventManagerHook<S> for LibAflFuzzEventHook
where
    S: State + Stoppable,
{
    fn pre_exec(
        &mut self,
        state: &mut S,
        _client_id: ClientDescription,
        event: &Event<S::Input>,
    ) -> Result<bool, Error> {
        if self.exit_on_solution && matches!(event, Event::Objective { .. }) {
            // TODO: dump state
            state.request_stop();
        }
        Ok(true)
    }
    fn post_exec(&mut self, _state: &mut S, _client_id: ClientDescription) -> Result<bool, Error> {
        Ok(true)
    }
}
