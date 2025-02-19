use crate::modules::PredicatesMap;
use libafl::stages::Stage;
pub static mut IS_RCA: bool = false;

#[derive(Debug)]
pub struct RCAStage {
    cache: PredicatesMap,
}

impl RCAStage {
    #[must_use]
    pub fn new() -> Self {
        Self {
            cache: PredicatesMap::default(),
        }
    }
}

impl<E, EM, S, Z> Stage<E, EM, S, Z> for RCAStage {
    fn should_restart(&mut self, state: &mut S) -> Result<bool, libafl::Error> {
        
    }

    fn clear_progress(&mut self, state: &mut S) -> Result<(), libafl::Error> {
        
    }

    fn perform(
            &mut self,
            fuzzer: &mut Z,
            executor: &mut E,
            state: &mut S,
            manager: &mut EM,
        ) -> Result<(), libafl::Error> {
        
    }
}