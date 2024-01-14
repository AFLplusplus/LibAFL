//! Functionality implementing hooks for instrumented code
use std::{cell::RefCell, collections::HashMap, rc::Rc};

use frida_gum::{stalker::Instruction, CpuContext, ModuleMap, instruction_writer::X86Register};
use frida_gum_sys::Insn;
use rangemap::RangeMap;
use yaxpeax_arch::LengthedInstruction;
use yaxpeax_x86::{
    long_mode::{InstDecoder, Opcode},
};

use crate::{
    asan::asan_rt::AsanRuntime,
    helper::{FridaRuntime, FridaRuntimeTuple},
    utils::{frida_to_cs, immediate_value, operand_details},
};

/// Frida hooks for instrumented code
pub struct HookRuntime {
    hooks: HashMap<usize, Box<dyn FnMut(usize, CpuContext, Option<&mut AsanRuntime>) + 'static>>,
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
        callback: impl FnMut(usize, CpuContext, Option<&mut AsanRuntime>) + 'static,
    ) {
        self.hooks.insert(address, Box::new(callback));
    }

    fn resolve_jump_target(&self, decoder: InstDecoder, address: usize) -> Option<usize> {
        log::trace!("resolve_jump_target({:x})", address);
        let slice = unsafe { std::slice::from_raw_parts(address as *const u8, 32) };
        if let Ok(instruction) = decoder.decode_slice(slice) {
            if instruction.opcode() == Opcode::JMP || instruction.opcode() == Opcode::JMPF {
                let operand = instruction.operand(0);
                if operand.is_memory() {
                    if let Some((basereg, _indexreg, _scale, disp)) = operand_details(&operand) {
                        if basereg == X86Register::Rip {
                            let target_address = unsafe {
                                (((address as u64 + instruction.len()) as i64 + disp as i64)
                                    as *const usize)
                                    .read()
                            };

                            return if let Some(address) =
                                self.resolve_jump_target(decoder, target_address)
                            {
                                Some(address)
                            } else {
                                Some(target_address)
                            };
                        }
                    }
                } else {
                    log::trace!("instruction: {}", instruction);

                    let inner_address = (address as u64 + instruction.len()) as i64
                        + immediate_value(&instruction.operand(0)).unwrap();
                    return if let Some(inner_address) =
                        self.resolve_jump_target(decoder, inner_address as usize)
                    {
                        Some(inner_address)
                    } else {
                        Some(address)
                    };
                }
            }
        }
        None
    }

    /// Determine if this instruction is interesting for the purposes of hooking
    #[inline]
    pub fn is_interesting(&self, decoder: InstDecoder, instr: &Insn) -> Option<usize> {
        let instruction = frida_to_cs(decoder, instr);

        if instruction.opcode() == Opcode::CALL {
            if instruction.operand(0).is_memory() {
                if let Some((basereg, _indexreg, _scale, disp)) =
                    operand_details(&instruction.operand(0))
                {
                    if basereg == X86Register::Rip {
                        log::trace!("instruction: {}", instruction);
                        let target_address = unsafe {
                            (((instr.address() + instruction.len()) as i64 + disp as i64)
                                as *const usize)
                                .read()
                        };

                        let address = if let Some(address) =
                            self.resolve_jump_target(decoder, target_address)
                        {
                            address
                        } else {
                            target_address
                        };
                        if self.hooks.contains_key(&address) {
                            return Some(address)
                        };
                    }
                }
            } else {
                let inner_address = instr.address() as i64
                    + instr.bytes().len() as i64
                    + immediate_value(&instruction.operand(0)).unwrap();
                if let Some(target_address) =
                    self.resolve_jump_target(decoder, inner_address as usize)
                {
                    if self.hooks.contains_key(&target_address) {
                        return Some(target_address);
                    }
                }
            }
        }
        None
    }

    /// Emits a callout to the hook
    #[inline]
    pub fn emit_callout<RT: FridaRuntimeTuple>(
        &mut self,
        address: usize,
        insn: &Instruction,
        runtimes: Rc<RefCell<RT>>,
    ) {
        log::trace!("emit_callout: {:x}", address);
        insn.put_callout(move |context| {
            (self.hooks.get_mut(&address).unwrap())(
                address,
                context,
                runtimes.borrow_mut().match_first_type_mut::<AsanRuntime>(),
            )
        })
    }
}
