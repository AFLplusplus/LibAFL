use libafl::{
    corpus::Corpus,
    events::{Event, EventManagerHook},
    state::{HasCorpus, Stoppable},
    Error,
};
use libafl_bolts::ClientId;

#[derive(Clone, Copy)]
pub struct LibAflFuzzEventHook {
    exit_on_solution: bool,
}

impl<S> EventManagerHook<<S::Corpus as Corpus>::Input, S> for LibAflFuzzEventHook
where
    S: HasCorpus + Stoppable,
{
    fn pre_exec(
        &mut self,
        state: &mut S,
        _client_id: ClientId,
        event: &Event<<S::Corpus as Corpus>::Input>,
    ) -> Result<bool, Error> {
        if self.exit_on_solution && matches!(event, Event::Objective { .. }) {
            // TODO: dump state
            state.request_stop();
        }
        Ok(true)
    }
    fn post_exec(&mut self, _state: &mut S, _client_id: ClientId) -> Result<bool, Error> {
        Ok(true)
    }
}
