//! Functionality implementing hooks for instrumented code
use std::{cell::RefCell, collections::HashMap, rc::Rc};

use frida_gum::{
    stalker::Instruction,
    CpuContext, ModuleMap,
};
#[cfg(target_arch = "x86_64")]
use frida_gum::instruction_writer::X86Register;

use frida_gum_sys::Insn;
use rangemap::RangeMap;

#[cfg(target_arch = "x86_64")]
use yaxpeax_arch::LengthedInstruction;
#[cfg(target_arch = "x86_64")]
use yaxpeax_x86::long_mode::{InstDecoder, Opcode};


#[cfg(target_arch = "aarch64")]
use yaxpeax_arm::armv8::a64::{InstDecoder, Opcode, Operand};

#[cfg(target_arch = "aarch64")]
use frida_gum::instruction_writer::{Aarch64Register,Aarch64InstructionWriter,IndexMode,InstructionWriter};

#[cfg(target_arch = "aarch64")]
use std::ptr::addr_of;

use crate::{
    asan::asan_rt::AsanRuntime,
    helper::{FridaRuntime, FridaRuntimeTuple},
    utils::frida_to_cs,
};

#[cfg(target_arch = "x86_64")]
use crate::utils::{immediate_value, operand_details};

/// Frida hooks for instrumented code
#[cfg(target_arch = "x86_64")]
pub struct HookRuntime {
    hooks: HashMap<usize, Box<dyn FnMut(usize, CpuContext, Option<&mut AsanRuntime>) + 'static>>,
}

#[cfg(target_arch = "aarch64")]
pub struct HookRuntime {
    hooks: HashMap<usize, Box<dyn FnMut(usize, CpuContext, Option<&mut AsanRuntime>) + 'static>>,
    hooked: u64, //Runtimes are wrapped in a RefCell, so in theory we shouldn't need to pin this
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
            hooked: 0,
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


    #[cfg(target_arch = "x86_64")]
    fn resolve_jump_target(&self, decoder: InstDecoder, address: usize) -> Option<usize> {
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
                    if let Some(immediate) = immediate_value(&instruction.operand(0)) {
                        let inner_address = (address as u64 + instruction.len()) as i64 + immediate;
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
        }
        None
    }

    /// Determine if this instruction is interesting for the purposes of hooking
    #[inline]
    #[cfg(target_arch = "x86_64")]
    pub fn is_interesting(&self, decoder: InstDecoder, instr: &Insn) -> Option<(usize, bool)> {
        let instruction = frida_to_cs(decoder, instr);

        if instruction.opcode() == Opcode::CALL || instruction.opcode() == Opcode::JMP {
            if instruction.operand(0).is_memory() {
                log::trace!("{:x}: instruction: {}",instr.address(), instruction);
                if let Some((basereg, _indexreg, _scale, disp)) =
                    operand_details(&instruction.operand(0))
                {
                    if basereg == X86Register::Rip {
                        let target_address = unsafe {
                            (((instr.address() + instruction.len()) as i64 + disp as i64)
                                as *const usize)
                                .read()
                        };
                        log::trace!("- {:x} : {:x}", ((instr.address() + instruction.len()) as i64 + disp as i64), target_address);

                        let (address, needs_return) = if let Some(address) =
                            self.resolve_jump_target(decoder, target_address)
                        {
                            (address, false)
                        } else {
                            (target_address, true)
                        };
                        if self.hooks.contains_key(&address) {
                            return Some((
                                address,
                                needs_return && instruction.opcode() == Opcode::JMP,
                            ));
                        };
                    }
                }
            } else {
                if let Some(immediate) = immediate_value(&instruction.operand(0)) {
                    let inner_address =
                        (instr.address() as i64 + instr.bytes().len() as i64 + immediate) as usize;
                    if self.hooks.contains_key(&inner_address) {
                        return Some((inner_address, instruction.opcode() == Opcode::JMP));
                    }

                    if let Some(target_address) =
                        self.resolve_jump_target(decoder, inner_address)
                    {
                        if self.hooks.contains_key(&target_address) {
                            return Some((target_address, false));
                        }
                    }
                }
            }
        }
        None
    }




    #[inline]
    #[cfg(target_arch = "aarch64")]
    pub fn is_interesting(&self, decoder: InstDecoder, instr: &Insn) -> Option<(usize, bool)> {
        let instruction = frida_to_cs(decoder, instr);
        
        match instruction.opcode{
            Opcode::BR | Opcode::BLR => {
                let reg_op = instruction.operands[0];
                let reg_num = if let Operand::Register(_, num) = reg_op {
                    num
                } else {
                    panic!("Invalid instruction - opcode: {:?}, operands: {:?}", instruction.opcode, instruction.operands);
                };
                
                //we could probably introduce some kind of speculative backpatching as it is unlikely that if it is hooked the first time that it ever hooks again
                
                return Some((reg_num as usize, true)); //the reg should always be checked
            },
            Opcode::BL | Opcode::B => {
                
                let call_address = if let Operand::PCOffset(off) = instruction.operands[0] {
                    (instr.address() as i64 + off) as usize
                }else {
                    panic!("Invalid instruction - opcode: {:?}, operands: {:?}", instruction.opcode, instruction.operands); //impossible to have b/bl with a PCOffset
                };

                if !self.hooks.contains_key(&call_address){
                    return None;
                }

                return Some((call_address, false));
                
            },

            _ => {
                return None;
            }
        }

    }

    /// Emits a callout to the hook
    #[inline]
    #[cfg(target_arch = "x86_64")]
    pub fn emit_callout<RT: FridaRuntimeTuple>(
        &mut self,
        address: usize,
        insn: &Instruction,
        needs_return: bool,
        runtimes: Rc<RefCell<RT>>,
    ) {
        log::trace!("emit_callout: {:x}", address);
        insn.put_callout(move |context| {
            (self.hooks.get_mut(&address).unwrap())(
                address,
                context,
                runtimes.borrow_mut().match_first_type_mut::<AsanRuntime>(),
            )
        });

        if needs_return {
            log::trace!("needs return at {:x}", address);
            insn.put_chaining_return();
        }
    }

    #[inline]
    #[cfg(target_arch = "aarch64")]
    pub fn emit_callout<RT: FridaRuntimeTuple>(
        &mut self,
        address_or_reg: usize,
        insn: &Instruction,
        is_reg: bool,
        writer: Aarch64InstructionWriter,
        runtimes: Rc<RefCell<RT>>,
    ) {

        let hooked_address = addr_of!(self.hooked) as u64;
        log::trace!("emit_callout: {:x}", address_or_reg);
        insn.put_callout(move |context| {
            if !is_reg {
            //if we are not in a register, address_or_reg is the actual address
            //safe to unwrap because we check in is_interesting to see if we should hook
                (self.hooks.get_mut(&address_or_reg).unwrap())( 
                    address_or_reg,
                    context,
                    runtimes.borrow_mut().match_first_type_mut::<AsanRuntime>(),
                )
            }else{ //we are a register
                let address = match address_or_reg {
                    0..=28 => context.reg(address_or_reg),
                    29 => context.fp(),
                    30 => context.lr(),
                    _ => {
                        panic!("Invalid register: {:#x}", address_or_reg);
                    }
                } as usize;

                if let Some(f) = self.hooks.get_mut(&address) {
                    f(address, context, runtimes.borrow_mut().match_first_type_mut::<AsanRuntime>());
                    self.hooked = 1;
                } else {
                    self.hooked = 0;
                }
            }
        });

        if is_reg { //Opcode::BR/Opcode::BLR
            //write load from self.hooked, cbz to end, 
            let redzone_size = frida_gum_sys::GUM_RED_ZONE_SIZE as i32;
            let not_hooked_label_id = insn.instr().address() | 0xfaded; //this is label id for the hooked

            //stp x16, x17, [sp, #-0x90]!
            writer.put_stp_reg_reg_reg_offset(
                Aarch64Register::X16,
                Aarch64Register::X17,
                Aarch64Register::Sp,
                i64::from(-(16 + redzone_size)),
                IndexMode::PreAdjust,
            );
            //mov x16, &self->hooked
            writer.put_ldr_reg_u64(Aarch64Register::X16, hooked_address);
            //move self->hooked into x16
            writer.put_ldr_reg_reg(Aarch64Register::X16, Aarch64Register::X16);
            //if hooked is 0 then we want to continue as if nothing happened
            writer.put_cbz_reg_label(Aarch64Register::X16, not_hooked_label_id);
            //this branch we have a hook
            writer.put_ldp_reg_reg_reg_offset(
                Aarch64Register::X16,
                Aarch64Register::X17,
                Aarch64Register::Sp,
                16 + i64::from(redzone_size),
                IndexMode::PostAdjust,
            );
            //then we chaining return because we hooked
            insn.put_chaining_return();

            writer.put_label(not_hooked_label_id);

            writer.put_ldp_reg_reg_reg_offset(
                Aarch64Register::X16,
                Aarch64Register::X17,
                Aarch64Register::Sp,
                16 + i64::from(redzone_size),
                IndexMode::PostAdjust,
            );

            insn.keep(); //the keep will dispatch to the next block

        } else { //Opcode::B/Opcode::BL
            insn.put_chaining_return();
        }
            //instruction should be kept here
        
    }
    
}



