//! Functionality implementing hooks for instrumented code
use std::{
    cell::RefCell,
    collections::HashMap,
    ptr::addr_of,
    rc::Rc,
};

#[cfg(target_arch = "aarch64")]
use frida_gum::instruction_writer::{
    Aarch64InstructionWriter, Aarch64Register, IndexMode, InstructionWriter,
};
#[cfg(target_arch = "x86_64")]
use frida_gum::instruction_writer::{
    InstructionWriter, X86BranchCondition, X86InstructionWriter, X86Register,
};
use frida_gum::{stalker::Instruction, CpuContext, ModuleMap};
use frida_gum_sys::Insn;
use rangemap::RangeMap;
#[cfg(target_arch = "aarch64")]
use yaxpeax_arm::armv8::a64::{InstDecoder, Opcode, Operand};
#[cfg(target_arch = "x86_64")]
use yaxpeax_x86::long_mode::{InstDecoder, Opcode, Operand};

#[cfg(target_arch = "x86_64")]
use crate::utils::{get_register, operand_details, writer_register};
use crate::{
    asan::asan_rt::AsanRuntime,
    helper::{FridaRuntime, FridaRuntimeTuple},
    utils::{frida_to_cs, immediate_value},
};

#[cfg(target_arch = "x86_64")]
use std::ptr::read_unaligned;

/*
LibAFL hook_rt design:

The objective of this runtime is to move away from using Interceptor for hooking and move to
something that hooks during the stalk. The way this does this is different for direct and indirect
branches.

For direct branches, the hooking is easy. We simply check if the branch target is hooked. If it is,
run the hooked function. If it is not, then continue as per normal. If it is hooked, we chaining
return to return the caller.

For indirect branches (i.e., jmp rax/blr x16), it is harder as the branch target is difficult to
know at block-compile time. In the case of indirect branches, we check the register during runtime.
If the value of the register is a hooked function then run the hooked function in the callout and
set HookRuntime::hooked = 1. If it is not then set HookRuntime::hooked = 0.

From here, we either chaining return if HookRuntime::hooked == 1 or continue on to the next block
via a keeping the instruction if HookRuntime::hooked = 0

*/

/// Frida hooks for instrumented code
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

/// The type of a call instruction
#[derive(Debug)]
#[cfg(target_arch = "x86_64")]
pub enum CallType {
    /// Call an immediate address
    Imm(usize),
    /// Call through a register
    Reg(X86Register),
    /// Call through a memory dereference
    Mem((X86Register, X86Register, u8, i32)), //this is the return type from operand_details
}

impl HookRuntime {
    /// Create a new hook runtime
    #[must_use]
    pub fn new() -> Self {
        return Self {
            hooks: HashMap::new(),
            hooked: 0,
        };
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

    /// Determine if this instruction is interesting for the purposes of hooking
    #[inline]
    #[cfg(target_arch = "x86_64")]
    pub fn is_interesting(&self, decoder: InstDecoder, instr: &Insn) -> Option<(CallType, bool)> {

        let result = frida_to_cs(decoder, instr);

        if let Err(e) = result {
            log::error!("{}", e);
            return None;
        }

        let instruction = result.unwrap();

        // log::trace!("{instruction:}");
        //there are 3 seperate cases we need to handle: loads, immediates, and registers
        //we need to deal with all cases in case of dlsym
        if instruction.opcode() == Opcode::CALL || instruction.opcode() == Opcode::JMP {
            //if its a memory op, we can't resolve it yet as it may not be resolved yet
            if instruction.operand(0).is_memory() {
                // log::trace!("{:x}: instruction: {}", instr.address(), instruction);
                let mem_details = operand_details(&instruction.operand(0));

                if let Some((reg, index_reg, scale, disp)) = mem_details {
                    if reg == X86Register::Rip {
                        //rip relative loads are from the end of the instruction, so add the
                        //instruction length to the displacement
                        return Some((CallType::Mem((
                            reg,
                            index_reg,
                            scale,
                            disp + instr.len() as i32,
                        )), instruction.opcode() == Opcode::JMP));
                    }
                    return Some((CallType::Mem((reg, index_reg, scale, disp)), instruction.opcode() == Opcode::JMP));
                }
            } else {
                if let Some(imm) = immediate_value(&instruction.operand(0)) {
                        let target = (instr.address() as i64 + imm) as usize;
                        if !self.hooks.contains_key(&target) {
                            return None;
                        }
                        return Some((CallType::Imm(target), instruction.opcode() == Opcode::JMP));
                    
                } else {

                match instruction.operand(0) {
                    Operand::Register(reg_spec) => {
                        return Some((CallType::Reg(writer_register(reg_spec)), instruction.opcode() == Opcode::JMP));
                    }
                    _ => panic!("Invalid call/jmp instructions"),
                }
                }
            }
        }
        None
    }

    #[inline]
    #[cfg(target_arch = "aarch64")]
    pub fn is_interesting(&self, decoder: InstDecoder, instr: &Insn) -> Option<(usize, bool)> {
        let result = frida_to_cs(decoder, instr);

        if let Err(e) = result {
            log::error!("{}", e);
            return None;
        }

        let instruction = result.unwrap();

        match instruction.opcode {
            Opcode::BR | Opcode::BLR => {
                let reg_op = instruction.operands[0];
                let reg_num = if let Operand::Register(_, num) = reg_op {
                    num
                } else {
                    panic!(
                        "Invalid instruction - opcode: {:?}, operands: {:?}",
                        instruction.opcode, instruction.operands
                    );
                };

                //we could probably introduce some kind of speculative backpatching as it is unlikely that if it is hooked the first time that it ever hooks again

                return Some((reg_num as usize, true)); //the reg should always be checked
            }
            Opcode::BL | Opcode::B => {
                let call_address = if let Operand::PCOffset(off) = instruction.operands[0] {
                    (instr.address() as i64 + off) as usize
                } else {
                    panic!(
                        "Invalid instruction - opcode: {:?}, operands: {:?}",
                        instruction.opcode, instruction.operands
                    ); //impossible to have b/bl with a PCOffset
                };

                if !self.hooks.contains_key(&call_address) {
                    return None;
                }

                return Some((call_address, false));
            }

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
        call_type: CallType,
        is_jmp: bool,
        insn: &Instruction,
        writer: X86InstructionWriter,
        runtimes: Rc<RefCell<RT>>,
    ) {
        log::trace!("emit_callout: {:#x}", insn.instr().address());
        // log::trace!("call: {:?}", call_type);
        let hooked_address = addr_of!(self.hooked) as u64;
        let rip = insn.instr().address();
        let next_instruction_address = rip + insn.instr().len() as u64;
        let is_imm = if let CallType::Imm(_) = call_type {
            //log::trace!("needs return at {:x}", address);
            true
        } else {
            false
        };

               // writer.put_bytes(&[0xcc]); //put int3

        insn.put_callout(move |context| {
            let address = match call_type {
                CallType::Mem((reg, index_reg, scale, disp)) => {
                    let base = if let X86Register::Rip = reg {
                        rip
                    } else {
                        get_register(&context, reg)
                    };

                    let index = get_register(&context, index_reg);
                    let addr = (base.wrapping_add(index.wrapping_mul(scale as u64)) as i64
                        + disp as i64) as *const u64; //disp already has the offset applied if we are doing an rip relative load

                    // log::trace!("Call dereference address: {:#x}", addr as u64);

                    let value = unsafe { read_unaligned(addr) };
                    // log::trace!("call value: {:#x}", value);
                    value as usize
                }
                CallType::Imm(address) => address,
                CallType::Reg(reg) => get_register(&context, reg) as usize,
            };

            if let Some(f) = self.hooks.get_mut(&address) {
                f(
                    address,
                    context,
                    runtimes.borrow_mut().match_first_type_mut::<AsanRuntime>(),
                );
                self.hooked = 1;
            } else {
                self.hooked = 0;
            }
        });
        //

        if !is_imm {
            let not_hooked_label_id = insn.instr().address() | 0xfaded; //this is label id for the hooked
            // writer.put_bytes(&[0xcc]);
            writer.put_sub_reg_imm(X86Register::Rsp, frida_gum_sys::GUM_RED_ZONE_SIZE as isize);
            writer.put_push_reg(X86Register::Rdi);
            writer.put_mov_reg_u64(X86Register::Rdi, hooked_address); //hooked address is in RDI
            writer.put_mov_reg_reg_ptr(X86Register::Rdi, X86Register::Rdi); //mov rdi, [rdi]

            //sub is the same as cmp. rdi is 0 if we hooked
            writer.put_sub_reg_imm(X86Register::Rdi, 1);

            writer.put_jcc_near_label(X86BranchCondition::Jne, not_hooked_label_id, 0);

            writer.put_pop_reg(X86Register::Rdi);
            writer.put_add_reg_imm(X86Register::Rsp, frida_gum_sys::GUM_RED_ZONE_SIZE as isize);

            // we hooked the function, continue execution at the next block
            // if it is a jmp, then we just chaining return. If it is a call, we need to make the
            // chaining return return to the previous block. This is accomplished by temporarily
            // pushing a fake return address onto the stack, then continuing to the chaining
            // return.
            if !is_jmp {
                writer.put_mov_reg_address(X86Register::Rcx, next_instruction_address);
                writer.put_push_reg(X86Register::Rcx);

            }
            // insn.put_chaining_return();

            writer.put_label(not_hooked_label_id);

            writer.put_pop_reg(X86Register::Rdi);
            writer.put_add_reg_imm(X86Register::Rsp, frida_gum_sys::GUM_RED_ZONE_SIZE as isize);
            // we did not hook the function, execute the original call/jmp instruction
            insn.keep();

        } else {
            // insn.put_chaining_return();
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
            } else {
                //we are a register
                let address = match address_or_reg {
                    0..=28 => context.reg(address_or_reg),
                    29 => context.fp(),
                    30 => context.lr(),
                    _ => {
                        panic!("Invalid register: {:#x}", address_or_reg);
                    }
                } as usize;

                if let Some(f) = self.hooks.get_mut(&address) {
                    //the hook sets the return value for us, so we have nothing to do
                    f(
                        address,
                        context,
                        runtimes.borrow_mut().match_first_type_mut::<AsanRuntime>(),
                    );
                    self.hooked = 1;
                } else {
                    self.hooked = 0;
                }
            }
        });

        if is_reg {
            //Opcode::BR/Opcode::BLR
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
            //mov &self->hooked into x16
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
        } else {
            //Opcode::B/Opcode::BL
            insn.put_chaining_return();
        }
    }
}
