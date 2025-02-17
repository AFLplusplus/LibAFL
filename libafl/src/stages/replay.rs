/*
use alloc::{
    borrow::{Cow, ToOwned},
    string::ToString,
};

use libafl_bolts::Named;

use super::Stage;

/// The counter for giving this stage unique id
static mut REPLAY_STAGE_ID: usize = 0;
/// The name for tmin stage
pub static REPLAY_STAGE_NAME: &str = "tmin";

/// Scan all corpus, objectives and run them once
#[derive(Debug)]
pub struct ReplayStage {
    name: Cow<'static, str>,
}

impl ReplayStage {
    #[must_use]
    /// Construct this stage
    pub fn new() -> Self {
        // unsafe but impossible that you create two threads both instantiating this instance
        let stage_id = unsafe {
            let ret = REPLAY_STAGE_ID;
            REPLAY_STAGE_ID += 1;
            ret
        };

        Self {
            name: Cow::Owned(REPLAY_STAGE_NAME.to_owned() + ":" + stage_id.to_string().as_ref()),
        }
    }
}

impl Named for ReplayStage {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<E, EM, S, Z> Stage<E, EM, S, Z> for ReplayStage {
    fn should_restart(&mut self, state: &mut S) -> Result<bool, libafl_bolts::Error> {
        Ok(true)
    }

    fn clear_progress(&mut self, state: &mut S) -> Result<(), libafl_bolts::Error> {
        Ok(false)
    }

    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<(), libafl_bolts::Error> {
        Ok(())
    }
}
*/
