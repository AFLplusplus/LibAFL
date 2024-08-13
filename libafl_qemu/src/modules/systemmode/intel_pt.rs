use libafl::inputs::UsesInput;

use crate::modules::EmulatorModule;

#[derive(Debug)]
pub struct IntelPTModule {}

impl<S> EmulatorModule<S> for IntelPTModule where S: Unpin + UsesInput {}
