//! Functionality implementing hooks for instrumented code
use std::{collections::HashMap, rc::Rc};

use frida_gum::{
    instruction_writer::X86Register,
    stalker::{Instruction, StalkerIterator},
    CpuContext, ModuleMap,
};
use frida_gum_sys::Insn;
use rangemap::RangeMap;
use yaxpeax_arch::LengthedInstruction;
use yaxpeax_x86::long_mode::{InstDecoder, Opcode};


use crate::{
    helper::FridaRuntime,
    utils::{frida_to_cs, writer_register, operand_details},
};

/// Frida hooks for instrumented code
pub struct HookRuntime {
    hooks: HashMap<usize, Box<dyn FnMut(usize, CpuContext) + 'static>>,
}

impl Default for HookRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for HookRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HookRuntime")
    }
}

impl FridaRuntime for HookRuntime {
    /// Initialize the coverage runtime
    /// The struct MUST NOT be moved after this function is called, as the generated assembly references it
    fn init(
        &mut self,
        _gum: &frida_gum::Gum,
        _ranges: &RangeMap<usize, (u16, String)>,
        _module_map: &Rc<ModuleMap>,
    ) {
    }

    fn pre_exec<I: libafl::inputs::Input + libafl::inputs::HasTargetBytes>(
        &mut self,
        _input: &I,
    ) -> Result<(), libafl::Error> {
        Ok(())
    }

    fn post_exec<I: libafl::inputs::Input + libafl::inputs::HasTargetBytes>(
        &mut self,
        _input: &I,
    ) -> Result<(), libafl::Error> {
        Ok(())
    }
}

impl HookRuntime {
    /// Create a new hook runtime
    #[must_use]
    pub fn new() -> Self {
        Self {
            hooks: HashMap::new(),
        }
    }

    /// Register a hook with the runtime
    #[inline]
    pub fn register_hook(
        &mut self,
        address: usize,
        callback: impl FnMut(usize, CpuContext) + 'static,
    ) {
        self.hooks.insert(address, Box::new(callback));
    }

    /// Determine if this instruction is interesting for the purposes of hooking
    #[inline]
    pub fn is_interesting(&self, 
        decoder: InstDecoder,
        instr: &Insn) -> Option<usize> {
        let instruction = frida_to_cs(decoder, instr);

        if instruction.opcode() == Opcode::CALL || instruction.opcode() == Opcode::CALLF {

            let operand = instruction.operand(0);
            if operand.is_memory() {
                if let Some((basereg, indexreg, scale, disp)) = operand_details(&operand) {
                    let target_address = unsafe {((instr.address() + instruction.len() + disp as u64) as *const usize).read() };
                    if self.hooks.contains_key(&target_address) {
                        return Some(target_address)
                    }

                }
            }
        }
        None
    }

    /// Emits a callout to the hook
    #[inline]
    pub fn emit_callout(&mut self, address: usize, insn: &Instruction) {
        log::trace!("emit_callout: {:x}", address);
        insn.put_callout(move |context| (self.hooks.get_mut(&address).unwrap())(address, context));
    }
}
