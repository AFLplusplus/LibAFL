use std::{fmt::Debug, fs::OpenOptions, io::Write};

use libafl::{inputs::UsesInput, observers::ObserversTuple, HasMetadata};
use libafl_qemu_sys::CPUArchStatePtr;

use crate::{
    modules::{EmulatorModule, EmulatorModuleTuple, ExitKind},
    qemu::intel_pt::IntelPT,
    EmulatorModules, NewThreadHook,
};

//#[derive(Debug)]
pub struct IntelPTModule {
    pt: Option<IntelPT>,
}

impl Debug for IntelPTModule {
    // TODO image is not debug
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IntelPTModule")
            .field("pt", &self.pt)
            .finish()
    }
}

impl IntelPTModule {
    pub fn new() -> Self {
        Self { pt: None }
    }
}

impl Default for IntelPTModule {
    fn default() -> Self {
        Self::new()
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
    intel_pt_module
        .pt
        .as_mut()
        .unwrap()
        .enable_tracing()
        .unwrap();

    // What does this bool mean? ignore for the moment
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
    }

    fn pre_exec<ET>(
        &mut self,
        emulator_modules: &mut EmulatorModules<ET, S>,
        _input: &<S as UsesInput>::Input,
    ) where
        ET: EmulatorModuleTuple<S>,
    {
    }

    fn post_exec<OT, ET>(
        &mut self,
        emulator_modules: &mut EmulatorModules<ET, S>,
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

        // we need the memory map to decode the traces here take it in prexec. use QemuMemoryChunk
        // TODO handle self modifying code

        let qemu = emulator_modules.qemu();
        // qemu.read_mem()

        // TODO: raw traces buff just for debugging
        let mut buff = Vec::new();
        let block_ips = self.pt.as_mut().unwrap().decode_with_callback(
            |addr, out_buff| unsafe { qemu.read_mem(out_buff, addr.into()) },
            Some(&mut buff),
        );

        let trace_path = "trace.out";
        let mut file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(trace_path)
            .expect("Failed to open trace output file");

        file.write_all(&buff).unwrap();
        // println!("Block IPs: {:#x?}", block_ips);
    }
}
