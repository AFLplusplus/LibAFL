use libafl::{inputs::UsesInput, observers::ObserversTuple, HasMetadata};
use libafl_qemu_sys::{CPUArchStatePtr, GuestVirtAddr};
use libipt::Image;

use crate::{
    modules::{EmulatorModule, EmulatorModuleTuple, ExitKind},
    qemu::intel_pt::IntelPT,
    EmulatorModules, NewThreadHook,
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

pub fn intel_pt_new_thread<ET, S>(
    emulator_modules: &mut EmulatorModules<ET, S>,
    _state: Option<&mut S>,
    _env: CPUArchStatePtr,
    tid: u32,
) -> bool
where
    S: HasMetadata + Unpin + UsesInput,
    ET: EmulatorModuleTuple<S>,
{
    let intel_pt_module = emulator_modules
        .modules_mut()
        .match_first_type_mut::<IntelPTModule>()
        .unwrap();

    if intel_pt_module.pt.is_some() {
        panic!("Intel PT module already initialized, only single core VMs are supported ATM.");
    }

    intel_pt_module.pt = Some(IntelPT::try_new(tid as i32).unwrap());

    // What does this bool mean?
    true
}

impl<S> EmulatorModule<S> for IntelPTModule
where
    S: Unpin + UsesInput + HasMetadata,
{
    fn first_exec<ET>(&mut self, emulator_modules: &mut EmulatorModules<ET, S>)
    where
        ET: EmulatorModuleTuple<S>,
    {
        emulator_modules.thread_creation(NewThreadHook::Function(intel_pt_new_thread::<ET, S>));
        // TODO emulator_modules.thread_teradown
        // emulator_modules.cpu_runs(
        //     CpuPostRunHook::Function(...),
        // );
    }

    fn post_exec<OT, ET>(
        &mut self,
        _emulator_modules: &mut EmulatorModules<ET, S>,
        _input: &S::Input,
        _observers: &mut OT,
        _exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<S>,
        ET: EmulatorModuleTuple<S>,
    {
        if self.pt.is_none() {
            panic!("Intel PT module not initialized.");
        }

        // we need the memory map to decode the traces here
        // TODO handle self modifying code
        let mut image = Image::new(Some("empty_image")).expect("Failed to create image");

        let block_ips = self.pt.as_mut().unwrap().decode(&mut image, None);

        // 2. update map
        for ip in block_ips {
            // unsafe {
            //     EDGES_MAP[idx] += 1;
            // }
        }
    }
}
