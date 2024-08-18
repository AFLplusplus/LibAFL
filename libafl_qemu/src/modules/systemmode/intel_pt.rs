use libafl::{inputs::UsesInput, observers::ObserversTuple, HasMetadata};
use libafl_qemu_sys::{CPUArchStatePtr, GuestVirtAddr};

use crate::{
    modules::{EmulatorModule, EmulatorModuleTuple, ExitKind},
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

// pub fn intel_pt_new_thread<ET, S>(
//     emulator_modules: &mut EmulatorModules<ET, S>,
//     _state: Option<&mut S>,
//     _env: CPUArchStatePtr,
//     tid: u32
// ) -> bool
// where
//     S: HasMetadata + Unpin + UsesInput,
//     ET: EmulatorModuleTuple<S>,
// {
//     let intel_pt_module = emulator_modules.modules().match_first_type_mut::<IntelPTModule>().unwrap();

//     if let Some(pt) = &mut intel_pt_module.pt {
//         // update PT state
//     }

//     // Why a bool here?
//     true
// }

impl<S> EmulatorModule<S> for IntelPTModule
where
    S: Unpin + UsesInput + HasMetadata,
{
    fn first_exec<ET>(&mut self, emulator_modules: &mut EmulatorModules<ET, S>)
    where
        ET: EmulatorModuleTuple<S>,
    {
        // emulator_modules.thread_creation(
        //     NewThreadHook::Function(intel_pt_new_thread::<ET, S>)
        // );

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
        // 1. decode traces
        // Output: List of block's IPs we are going through during the fuzzer's run (after filtering)
        // let indexes: Vec<GuestVirtAddr> = {
        //     // result of decoding
        //     // use libxdc...
        // };

        // 2. update map
        // for idx in indexes {
        //     unsafe {
        //         EDGES_MAP[idx] += 1;
        //     }
        // }
    }
}
