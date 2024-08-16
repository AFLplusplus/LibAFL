use libafl_qemu_sys::GuestVirtAddr;
use libafl::inputs::UsesInput;
use libafl::observers::ObserversTuple;
use libafl_targets::EDGES_MAP;
use crate::{modules::{EmulatorModule, ExitKind}, qemu::intel_pt::IntelPT, CpuPreRunHook, EmulatorModules, NewThreadHook};
use crate::modules::EmulatorModuleTuple;

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
    state: Option<&mut S>,
    env: CPUArchStatePtr,
    tid: u32
) -> Option<u64>
where
    S: HasMetadata + Unpin + UsesInput,
    ET: EmulatorModuleTuple<S>,
{
    // do something each time a thread in created in QEMU
    let intel_pt_module: IntelPTModule = match emulator_modules.modules().match_first_type_mut::<IntelPTModule>();

    if let Some(pt) = intel_pt_module.pt {
        // update PT state
    }
}

pub fn intel_pt_pre_cpu_exec<ET, S>(
    emulator_modules: &mut EmulatorModules<ET, S>,
    state: Option<&mut S>,
    cpu: CPUStatePtr,
) -> Option<u64>
where
    S: HasMetadata + Unpin + UsesInput,
    ET: EmulatorModuleTuple<S>,
{
    // do something each time a thread in created in QEMU
    let intel_pt_module: IntelPTModule = match emulator_modules.modules().match_first_type_mut::<IntelPTModule>();

    if let Some(pt) = intel_pt_module.pt {
        // update PT state
    }
}

impl<S> EmulatorModule<S> for IntelPTModule
where
    S: Unpin + UsesInput,
{
    fn first_exec<ET>(&mut self, emulator_modules: &mut EmulatorModules<ET, S>)
    where
        ET: EmulatorModuleTuple<S>,
    {
        emulator_modules.thread_creation(
            NewThreadHook::Function(intel_pt_new_thread::<ET, S>)
        );

        emulator_modules.cpu_runs(
            CpuPreRunHook::Function(...),
            CpuPostRunHook::Function(...),
        );
    }

    fn post_exec<OT, ET>(&mut self, _emulator_modules: &mut EmulatorModules<ET, S>, _input: &S::Input, _observers: &mut OT, _exit_kind: &mut ExitKind)
    where
        OT: ObserversTuple<S>,
        ET: EmulatorModuleTuple<S>,
    {
        // 1. decode traces
        // Output: List of block's IPs we are going through during the fuzzer's run (after filtering)
        let indexes: Vec<GuestVirtAddr> = {
            // result of decoding
            // use libxdc...
        };

        // 2. update map
        // for idx in indexes {
        //     unsafe {
        //         EDGES_MAP[idx] += 1;
        //     }
        // }
    }
}
