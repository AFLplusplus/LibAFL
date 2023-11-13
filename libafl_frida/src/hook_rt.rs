//! Functionality implementing hooks for instrumented code
use std::{collections::HashMap, rc::Rc};

use capstone::{arch::x86::X86OperandType, Capstone};
use frida_gum::{
    instruction_writer::X86Register,
    stalker::{Instruction, StalkerIterator},
    CpuContext, ModuleMap,
};
use frida_gum_sys::Insn;
use rangemap::RangeMap;

use crate::{
    helper::FridaRuntime,
    utils::{frida_to_cs, writer_register},
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
    pub fn is_interesting(&self, capstone: &Capstone, instr: &Insn) -> Option<usize> {
        let instructions = frida_to_cs(capstone, instr);
        let instruction = instructions.first().unwrap();

        let mnemonic = instruction.mnemonic().unwrap();
        if mnemonic == "call" || mnemonic == "jmp" {
            log::trace!("instruction: {:}", instruction.to_string());
            let operands = capstone
                .insn_detail(instruction)
                .unwrap()
                .arch_detail()
                .operands();

            if let capstone::arch::ArchOperand::X86Operand(operand) = operands.first().unwrap() {
                match operand.op_type {
                    X86OperandType::Mem(opmem) => {
                        if X86Register::Rip == writer_register(opmem.base()) {
                            let target_address = unsafe {((instruction.address() as usize + instruction.len() + opmem.disp() as usize) as *const usize).read()};
                            log::trace!("{:x} -> {:x}", (instruction.address() as usize  + instruction.len() + opmem.disp() as usize), target_address);
                            if self.hooks.contains_key(&target_address) {
                                log::trace!("!!!!!!\n");
                                return Some(target_address);
                            }
                        }
                    }
                    _ => (),
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
