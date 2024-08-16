use libafl::inputs::UsesInput;

use crate::{
    modules::{EmulatorModule, ExitKind},
    qemu::intel_pt::IntelPT,
    EmulatorModules,
};

#[derive(Debug)]
pub struct IntelPTModule {
    pt: Option<IntelPT>,
}

impl IntelPTModule {
    pub fn new() -> Self {
        Self { pt: None }
    }
}

impl<S> EmulatorModule<S> for IntelPTModule
where
    S: Unpin + UsesInput,
{
    // should be thread creation instead
    fn pre_exec<ET>(
        &mut self,
        _emulator_modules: &mut EmulatorModules<ET, S>,
        _input: &<S as UsesInput>::Input,
    ) {
        let pid = 0xcaffe; // where do I get this from?
        self.pt = Some(IntelPT::try_new(pid).unwrap()); //TODO remove unwrap
        self.pt.as_mut().unwrap().enable_tracing().unwrap();
        // on error call IntelPT::availability() to give a more detailed error message
    }

    // should be thread teeardown instead
    fn post_exec<OT, ET>(
        &mut self,
        _emulator_modules: &mut EmulatorModules<ET, S>,
        _input: &<S as UsesInput>::Input,
        _observers: &mut OT,
        _exit_kind: &mut ExitKind,
    ) {
        self.pt = None;
    }
}
