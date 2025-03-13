//! The [`FRIDA`](https://frida.re) `CmpLog` runtime
//!
//! Functionality for [`frida`](https://frida.re)-based binary-only `CmpLog`.
//! With it, a fuzzer can collect feedback about each compare that happened in the target
//! This allows the fuzzer to potentially solve the compares, if a compare value is directly
//! related to the input.
//! Read the [`RedQueen`](https://www.ndss-symposium.org/ndss-paper/redqueen-fuzzing-with-input-to-state-correspondence/) paper for the general concepts.

use alloc::rc::Rc;
#[cfg(target_arch = "aarch64")]
use core::ffi::c_void;

use dynasmrt::dynasm;
#[cfg(target_arch = "aarch64")]
use dynasmrt::{DynasmApi, DynasmLabelApi};
use frida_gum::ModuleMap;
#[cfg(target_arch = "x86_64")]
use frida_gum::{instruction_writer::InstructionWriter, stalker::StalkerOutput};
#[cfg(target_arch = "aarch64")]
use frida_gum::{
    instruction_writer::{Aarch64Register, IndexMode, InstructionWriter},
    stalker::StalkerOutput,
};
use frida_gum_sys::Insn;
#[cfg(all(feature = "cmplog", target_arch = "x86_64"))]
use hashbrown::HashMap;
#[cfg(all(feature = "cmplog", target_arch = "x86_64"))]
use iced_x86::{
    BlockEncoder, Code, DecoderOptions, Instruction, InstructionBlock, MemoryOperand, MemorySize,
    OpKind, Register,
};
use libafl::Error;
use libafl_targets::{CMPLOG_MAP_W, cmps::__libafl_targets_cmplog_instructions};
use rangemap::RangeMap;

use crate::helper::FridaRuntime;
#[cfg(all(feature = "cmplog", target_arch = "aarch64"))]
use crate::utils::{disas_count, writer_register};

#[cfg(all(feature = "cmplog", target_arch = "aarch64"))]
/// Speciial `CmpLog` Cases for `aarch64`
#[derive(Debug)]
pub enum SpecialCmpLogCase {
    /// Test bit and branch if zero
    Tbz,
    /// Test bit and branch if not zero
    Tbnz,
}

#[cfg(all(feature = "cmplog", target_arch = "x86_64"))]
/// Speciial `CmpLog` Cases for `aarch64`
#[derive(Debug)]
pub enum SpecialCmpLogCase {}

#[cfg(target_arch = "aarch64")]
use yaxpeax_arm::armv8::a64::{InstDecoder, Opcode, Operand, ShiftStyle};
#[cfg(target_arch = "x86_64")]
use yaxpeax_x86::long_mode::InstDecoder;

/// The [`frida_gum_sys::GUM_RED_ZONE_SIZE`] casted to [`i32`]
///
/// # Panic
/// In debug mode, will panic on wraparound (which should never happen in practice)
#[cfg(all(feature = "cmplog", target_arch = "aarch64"))]
#[expect(clippy::cast_possible_wrap)]
fn gum_red_zone_size_i32() -> i32 {
    debug_assert!(
        i32::try_from(frida_gum_sys::GUM_RED_ZONE_SIZE).is_ok(),
        "GUM_RED_ZONE_SIZE is bigger than i32::max"
    );
    frida_gum_sys::GUM_RED_ZONE_SIZE as i32
}

/// The type of an operand loggged during `CmpLog`
#[derive(Debug, Clone, Copy)]
#[cfg(all(feature = "cmplog", target_arch = "aarch64"))]
pub enum CmplogOperandType {
    /// A Register
    Regid(Aarch64Register),
    /// An immediate value
    Imm(u64),
    /// A constant immediate value
    Cimm(u64),
    // We don't need a memory type because you cannot directly compare with memory
}

/// The type of an operand loggged during `CmpLog`
#[derive(Debug, Clone, Copy)]
#[cfg(all(feature = "cmplog", target_arch = "x86_64"))]
pub enum CmplogOperandType {
    /// A Register
    Reg(Register),
    /// An immediate value
    Imm(u64),
    /// A memory operand
    Mem(Register, Register, i64, u32, MemorySize), // base, index, disp, scale, mem_size
}

/// `Frida`-based binary-only innstrumentation that logs compares to the fuzzer
/// `LibAFL` can use this knowledge for powerful mutations.
#[derive(Debug)]
#[cfg(target_arch = "aarch64")]
pub struct CmpLogRuntime {
    ops_save_register_and_blr_to_populate: Option<Box<[u8]>>,
    ops_handle_tbz_masking: Option<Box<[u8]>>,
    ops_handle_tbnz_masking: Option<Box<[u8]>>,
}

/// `Frida`-based binary-only innstrumentation that logs compares to the fuzzer
/// `LibAFL` can use this knowledge for powerful mutations.
#[derive(Debug)]
#[cfg(target_arch = "x86_64")]
pub struct CmpLogRuntime {
    save_registers: Option<Box<[u8]>>,
    restore_registers: Option<Box<[u8]>>,
}

impl FridaRuntime for CmpLogRuntime {
    /// Initialize this `CmpLog` runtime.
    /// This will generate the instrumentation blobs for the current arch.
    fn init(
        &mut self,
        _gum: &frida_gum::Gum,
        _ranges: &RangeMap<u64, (u16, String)>,
        _module_map: &Rc<ModuleMap>,
    ) {
        self.generate_instrumentation_blobs();
    }

    fn deinit(&mut self, _gum: &frida_gum::Gum) {}

    fn pre_exec(&mut self, _input_bytes: &[u8]) -> Result<(), Error> {
        Ok(())
    }

    fn post_exec(&mut self, _input_bytes: &[u8]) -> Result<(), Error> {
        Ok(())
    }
}

impl CmpLogRuntime {
    /// Create a new [`CmpLogRuntime`]
    #[must_use]
    #[cfg(target_arch = "aarch64")]
    pub fn new() -> CmpLogRuntime {
        Self {
            ops_save_register_and_blr_to_populate: None,
            ops_handle_tbz_masking: None,
            ops_handle_tbnz_masking: None,
        }
    }

    /// Create a new [`CmpLogRuntime`]
    #[must_use]
    #[cfg(target_arch = "x86_64")]
    pub fn new() -> CmpLogRuntime {
        Self {
            save_registers: None,
            restore_registers: None,
        }
    }

    /// Call the external function that populates the `cmplog_map` with the relevant values
    #[expect(clippy::unused_self)]
    #[cfg(target_arch = "aarch64")]
    extern "C" fn populate_lists(&mut self, op1: u64, op2: u64, retaddr: u64) {
        // log::trace!(
        //     "entered populate_lists with: {:#02x}, {:#02x}, {:#02x}",
        //     op1, op2, retaddr
        // );
        let mut k = (retaddr >> 4) ^ (retaddr << 8);

        k &= (CMPLOG_MAP_W as u64) - 1;

        unsafe {
            __libafl_targets_cmplog_instructions(k as usize, 8, op1, op2);
        }
    }

    #[cfg(target_arch = "x86_64")]
    extern "C" fn populate_lists(size: u8, op1: u64, op2: u64, retaddr: u64) {
        // log::trace!(
        //     "entered populate_lists with: {:#02x}, {:#02x}, {:#02x}",
        //     op1, op2, retaddr
        // );
        let mut k = (retaddr >> 4) ^ (retaddr << 8);

        k &= (CMPLOG_MAP_W as u64) - 1;

        unsafe {
            __libafl_targets_cmplog_instructions(k as usize, size, op1, op2);
        }
    }

    /// Generate the instrumentation blobs for the current arch.
    #[expect(clippy::similar_names)]
    #[cfg(target_arch = "aarch64")]
    fn generate_instrumentation_blobs(&mut self) {
        macro_rules! blr_to_populate {
            ($ops:ident) => {dynasm!($ops
                ; .arch aarch64
                ; stp x2, x3, [sp, #-0x10]!
                ; stp x4, x5, [sp, #-0x10]!
                ; stp x6, x7, [sp, #-0x10]!
                ; stp x8, x9, [sp, #-0x10]!
                ; stp x10, x11, [sp, #-0x10]!
                ; stp x12, x13, [sp, #-0x10]!
                ; stp x14, x15, [sp, #-0x10]!
                ; stp x16, x17, [sp, #-0x10]!
                ; stp x18, x19, [sp, #-0x10]!
                ; stp x20, x21, [sp, #-0x10]!
                ; stp x22, x23, [sp, #-0x10]!
                ; stp x24, x25, [sp, #-0x10]!
                ; stp x26, x27, [sp, #-0x10]!
                ; stp x28, x29, [sp, #-0x10]!
                ; stp x30, xzr, [sp, #-0x10]!
                ; .u32 0xd53b4218_u32 // mrs x24, nzcv
                // jump to rust based population of the lists
                ; mov x2, x0
                ; adr x3, >done
                ; ldr x4, >populate_lists
                ; ldr x0, >self_addr
                ; blr x4
                // restore the reg state before returning to the caller
                ; .u32 0xd51b4218_u32 // msr nzcv, x24
                ; ldp x30, xzr, [sp], #0x10
                ; ldp x28, x29, [sp], #0x10
                ; ldp x26, x27, [sp], #0x10
                ; ldp x24, x25, [sp], #0x10
                ; ldp x22, x23, [sp], #0x10
                ; ldp x20, x21, [sp], #0x10
                ; ldp x18, x19, [sp], #0x10
                ; ldp x16, x17, [sp], #0x10
                ; ldp x14, x15, [sp], #0x10
                ; ldp x12, x13, [sp], #0x10
                ; ldp x10, x11, [sp], #0x10
                ; ldp x8, x9, [sp], #0x10
                ; ldp x6, x7, [sp], #0x10
                ; ldp x4, x5, [sp], #0x10
                ; ldp x2, x3, [sp], #0x10
                ; b >done
                ; self_addr:
                ; .u64 core::ptr::from_mut(self) as *mut c_void as u64
                ; populate_lists:
                ; .u64 CmpLogRuntime::populate_lists as *mut c_void as u64
                ; done:
            );};
        }

        // ldp/stp is more efficient than str/ldr so we use them instead.
        macro_rules! tbz_masking {
            ($ops:ident) => {dynasm!($ops
                ; .arch aarch64
                ; stp x5, xzr, [sp, #-0x10]!
                ; mov x5, #1
                ; lsl x5, x5, x1
                ; eor x5, x5, #255
                ; orr x1, x0, x5
                ; ldp x5, xzr, [sp], #0x10
            );};
        }

        macro_rules! tbnz_masking {
            ($ops:ident) => {dynasm!($ops
                ; .arch aarch64
                ; stp x5, xzr, [sp, #-0x10]!
                ; mov x5, #1
                ; lsl x5, x5, x1
                ; orr x1, x0, x5
                ; ldp x5, xzr, [sp], #0x10
            );};

        }

        let mut ops_handle_tbz_masking =
            dynasmrt::VecAssembler::<dynasmrt::aarch64::Aarch64Relocation>::new(0);
        tbz_masking!(ops_handle_tbz_masking);

        let mut ops_handle_tbnz_masking =
            dynasmrt::VecAssembler::<dynasmrt::aarch64::Aarch64Relocation>::new(0);
        tbnz_masking!(ops_handle_tbnz_masking);

        let mut ops_save_register_and_blr_to_populate =
            dynasmrt::VecAssembler::<dynasmrt::aarch64::Aarch64Relocation>::new(0);
        blr_to_populate!(ops_save_register_and_blr_to_populate);

        self.ops_handle_tbz_masking = Some(
            ops_handle_tbz_masking
                .finalize()
                .unwrap()
                .into_boxed_slice(),
        );

        self.ops_handle_tbnz_masking = Some(
            ops_handle_tbnz_masking
                .finalize()
                .unwrap()
                .into_boxed_slice(),
        );

        self.ops_save_register_and_blr_to_populate = Some(
            ops_save_register_and_blr_to_populate
                .finalize()
                .unwrap()
                .into_boxed_slice(),
        );
    }

    #[expect(clippy::similar_names)]
    #[cfg(all(windows, target_arch = "x86_64"))]
    fn generate_instrumentation_blobs(&mut self) {
        macro_rules! save_registers {
            ($ops:ident) => {dynasm!($ops
                ; .arch x64
                ; push rcx
                ; push rdx
                ; push r8
                ; push r9
                ; push r10
                ; push r11
                ; push rax
            );};
        }
        let mut save_registers = dynasmrt::VecAssembler::<dynasmrt::x64::X64Relocation>::new(0);
        save_registers!(save_registers);
        self.save_registers = Some(save_registers.finalize().unwrap().into_boxed_slice());

        macro_rules! restore_registers {
            ($ops:ident) => {dynasm!($ops
                ; .arch x64
                ; pop rax
                ; pop r11
                ; pop r10
                ; pop r9
                ; pop r8
                ; pop rdx
                ; pop rcx
            );};
        }
        let mut restore_registers = dynasmrt::VecAssembler::<dynasmrt::x64::X64Relocation>::new(0);
        restore_registers!(restore_registers);
        self.restore_registers = Some(restore_registers.finalize().unwrap().into_boxed_slice());
    }

    #[cfg(all(unix, target_arch = "x86_64"))]
    fn generate_instrumentation_blobs(&mut self) {
        macro_rules! save_registers {
            ($ops:ident) => {dynasm!($ops
                ; .arch x64
                ; push rax
                ; push rdi
                ; push rsi
                ; push rdx
                ; push rcx
                ; push r8
                ; push r9
            );};
        }
        let mut save_registers = dynasmrt::VecAssembler::<dynasmrt::x64::X64Relocation>::new(0);
        save_registers!(save_registers);
        self.save_registers = Some(save_registers.finalize().unwrap().into_boxed_slice());

        macro_rules! restore_registers {
            ($ops:ident) => {dynasm!($ops
                ; .arch x64
                ; pop r9
                ; pop r8
                ; pop rcx
                ; pop rdx
                ; pop rsi
                ; pop rdi
                ; pop rax
            );};
        }
        let mut restore_registers = dynasmrt::VecAssembler::<dynasmrt::x64::X64Relocation>::new(0);
        restore_registers!(restore_registers);
        self.restore_registers = Some(restore_registers.finalize().unwrap().into_boxed_slice());
    }

    /// Get the blob which saves the context, jumps to the populate function and restores the context
    #[inline]
    #[must_use]
    #[cfg(target_arch = "aarch64")]
    pub fn ops_save_register_and_blr_to_populate(&self) -> &[u8] {
        self.ops_save_register_and_blr_to_populate.as_ref().unwrap()
    }

    /// Get the blob which handles the tbz opcode masking
    #[inline]
    #[must_use]
    #[cfg(target_arch = "aarch64")]
    pub fn ops_handle_tbz_masking(&self) -> &[u8] {
        self.ops_handle_tbz_masking.as_ref().unwrap()
    }

    /// Get the blob which handles the tbnz opcode masking
    #[inline]
    #[must_use]
    #[cfg(target_arch = "aarch64")]
    pub fn ops_handle_tbnz_masking(&self) -> &[u8] {
        self.ops_handle_tbnz_masking.as_ref().unwrap()
    }

    /// Emit the instrumentation code which is responsible for operands value extraction and cmplog map population
    #[cfg(all(feature = "cmplog", target_arch = "x86_64"))]
    #[expect(clippy::too_many_lines)]
    #[inline]
    pub fn emit_comparison_handling(
        &self,
        address: u64,
        output: &StalkerOutput,
        op1: &CmplogOperandType, //first operand of the comparsion
        op2: &CmplogOperandType, //second operand of the comparsion
        _shift: &Option<SpecialCmpLogCase>,
        _special_case: &Option<SpecialCmpLogCase>,
    ) {
        let writer = output.writer();

        writer.put_bytes(&self.save_registers.clone().unwrap());

        // let int3 = [0xcc];
        // writer.put_bytes(&int3);

        let mut insts = vec![];
        // self ptr is not used so far
        let mut size_op = 0;

        let arg_reg_1;
        let arg_reg_2;
        let arg_reg_3;
        let arg_reg_4;
        let mut tmp_reg = HashMap::new();
        tmp_reg.insert(8, Register::RAX);
        tmp_reg.insert(4, Register::EAX);
        tmp_reg.insert(2, Register::AX);

        #[cfg(windows)]
        {
            arg_reg_1 = Register::CL;
            arg_reg_2 = Register::RDX;
            arg_reg_3 = Register::R8;
            arg_reg_4 = Register::R9;
        }
        #[cfg(unix)]
        {
            arg_reg_1 = Register::DL;
            arg_reg_2 = Register::RSI;
            arg_reg_3 = Register::RDX;
            arg_reg_4 = Register::RCX;
        }
        let mut set_size = |s: usize| {
            if size_op == 0 {
                size_op = s;
            } else {
                assert_eq!(size_op, s);
            }
        };
        // we put the operand value into rax and than push it on stack, so the
        // only clobbered register is rax, and if actual operand value uses it,
        // we simply restore it from stack
        for (op_num, op) in [op1, op2].iter().enumerate() {
            let op_num: i64 = op_num.try_into().unwrap();
            match op {
                CmplogOperandType::Reg(reg) => {
                    let info = reg.info();
                    set_size(info.size());
                    let reg_largest = reg.full_register();
                    if reg_largest == Register::RAX {
                        insts.push(
                            // we rely on the fact that latest saved register on stack is rax
                            Instruction::with1(
                                Code::Push_rm64,
                                MemoryOperand::with_base_displ(Register::RSP, op_num * 8),
                            )
                            .unwrap(),
                        );
                    } else {
                        insts.push(Instruction::with1(Code::Push_rm64, reg_largest).unwrap());
                    }
                }
                CmplogOperandType::Mem(reg_base, reg_index, disp, scale, mem_size) => {
                    let size;
                    let inst;
                    match *mem_size {
                        MemorySize::UInt64 | MemorySize::Int64 => {
                            size = 8;
                            inst = Code::Mov_r64_rm64;
                        }
                        MemorySize::UInt32 | MemorySize::Int32 => {
                            size = 4;
                            inst = Code::Mov_r32_rm32;
                        }
                        MemorySize::UInt16 | MemorySize::Int16 => {
                            size = 2;
                            inst = Code::Mov_r16_rm16;
                        }
                        _ => {
                            println!("Invalid memory size");
                            size = 4;
                            inst = Code::Push_rm32;
                        }
                    }
                    set_size(size);
                    let mut disp_adjusted = *disp;
                    let mut reg_base = *reg_base;
                    if reg_base == Register::RSP {
                        // 0x38 is an amount of bytes used by save_registers()
                        disp_adjusted = disp_adjusted + 0x38 + 8_i64 * op_num;
                    }
                    let tmp_reg_adjusted = *tmp_reg.get(&size).unwrap();
                    // in case of RIP, disp is an absolute address already calculated
                    // by iced, we can simply load it to rax (but in this case index register must
                    // be not rax)
                    if reg_base == Register::RIP {
                        insts.push(
                            Instruction::with2(Code::Mov_r64_imm64, Register::RAX, disp_adjusted)
                                .unwrap(),
                        );
                        reg_base = Register::RAX;
                        disp_adjusted = 0;
                    }
                    insts.push(
                        Instruction::with2(
                            inst,
                            tmp_reg_adjusted,
                            MemoryOperand::with_base_index_scale_displ_size(
                                reg_base,
                                *reg_index,
                                *scale,
                                disp_adjusted,
                                1,
                            ),
                        )
                        .unwrap(),
                    );
                    insts.push(Instruction::with1(Code::Push_rm64, Register::RAX).unwrap());
                }
                CmplogOperandType::Imm(imm) => {
                    insts.push(Instruction::with1(Code::Pushq_imm32, *imm as i32).unwrap());
                }
            }
        }

        insts.push(Instruction::with2(Code::Mov_r8_imm8, arg_reg_1, size_op as u64).unwrap());
        insts.push(Instruction::with1(Code::Pop_r64, arg_reg_2).unwrap());
        insts.push(Instruction::with1(Code::Pop_r64, arg_reg_3).unwrap());
        insts.push(Instruction::with2(Code::Mov_r64_imm64, arg_reg_4, address).unwrap());
        let block = InstructionBlock::new(&insts, 0);
        let block = BlockEncoder::encode(64, block, DecoderOptions::NONE).unwrap();
        writer.put_bytes(block.code_buffer.as_slice());
        writer.put_call_address((CmpLogRuntime::populate_lists as usize).try_into().unwrap());

        writer.put_bytes(&self.restore_registers.clone().unwrap());
    }

    /// Emit the instrumentation code which is responsible for operands value extraction and cmplog map population
    #[cfg(all(feature = "cmplog", target_arch = "aarch64"))]
    #[expect(clippy::too_many_lines)]
    #[inline]
    pub fn emit_comparison_handling(
        &self,
        _address: u64,
        output: &StalkerOutput,
        op1: &CmplogOperandType, //first operand of the comparsion
        op2: &CmplogOperandType, //second operand of the comparsion
        _shift: &Option<(ShiftStyle, u8)>,
        special_case: &Option<SpecialCmpLogCase>,
    ) {
        let writer = output.writer();

        // Preserve x0, x1:
        writer.put_stp_reg_reg_reg_offset(
            Aarch64Register::X0,
            Aarch64Register::X1,
            Aarch64Register::Sp,
            i64::from(-(16 + gum_red_zone_size_i32())),
            IndexMode::PreAdjust,
        );

        // make sure operand1 value is saved into x0
        match op1 {
            CmplogOperandType::Imm(value) | CmplogOperandType::Cimm(value) => {
                writer.put_ldr_reg_u64(Aarch64Register::X0, *value);
            }
            CmplogOperandType::Regid(reg) => match *reg {
                Aarch64Register::X0 | Aarch64Register::W0 => {}
                Aarch64Register::X1 | Aarch64Register::W1 => {
                    writer.put_mov_reg_reg(Aarch64Register::X0, Aarch64Register::X1);
                }
                _ => {
                    if !writer.put_mov_reg_reg(Aarch64Register::X0, *reg) {
                        writer.put_mov_reg_reg(Aarch64Register::W0, *reg);
                    }
                }
            },
        }

        // make sure operand2 value is saved into x1
        match op2 {
            CmplogOperandType::Imm(value) | CmplogOperandType::Cimm(value) => {
                writer.put_ldr_reg_u64(Aarch64Register::X1, *value);
                if let Some(inst) = special_case {
                    match inst {
                        SpecialCmpLogCase::Tbz => {
                            writer.put_bytes(self.ops_handle_tbz_masking());
                        }
                        SpecialCmpLogCase::Tbnz => {
                            writer.put_bytes(self.ops_handle_tbnz_masking());
                        }
                    }
                }
            }
            CmplogOperandType::Regid(reg) => match *reg {
                Aarch64Register::X1 | Aarch64Register::W1 => {}
                Aarch64Register::X0 | Aarch64Register::W0 => {
                    writer.put_ldr_reg_reg_offset(Aarch64Register::X1, Aarch64Register::Sp, 0u64);
                }
                _ => {
                    if !writer.put_mov_reg_reg(Aarch64Register::X1, *reg) {
                        writer.put_mov_reg_reg(Aarch64Register::W1, *reg);
                    }
                }
            },
        }

        //call cmplog runtime to populate the values map
        writer.put_bytes(self.ops_save_register_and_blr_to_populate());

        // Restore x0, x1
        assert!(writer.put_ldp_reg_reg_reg_offset(
            Aarch64Register::X0,
            Aarch64Register::X1,
            Aarch64Register::Sp,
            16 + i64::from(frida_gum_sys::GUM_RED_ZONE_SIZE),
            IndexMode::PostAdjust,
        ));
    }

    #[cfg(all(feature = "cmplog", target_arch = "x86_64"))]
    #[inline]
    /// Check if the current instruction is cmplog relevant one(any opcode which sets the flags)
    #[must_use]
    pub fn cmplog_is_interesting_instruction(
        _decoder: InstDecoder,
        _address: u64,
        instr: &Insn,
    ) -> Option<(
        CmplogOperandType,
        CmplogOperandType,
        Option<SpecialCmpLogCase>,
        Option<SpecialCmpLogCase>,
    )> {
        let bytes = instr.bytes();
        let mut decoder =
            iced_x86::Decoder::with_ip(64, bytes, instr.address(), DecoderOptions::NONE);
        if !decoder.can_decode() {
            return None;
        }
        let mut instruction = Instruction::default();
        decoder.decode_out(&mut instruction);
        match instruction.mnemonic() {
            iced_x86::Mnemonic::Cmp | iced_x86::Mnemonic::Sub => {} // continue
            _ => return None,
        }

        if instruction.op_count() != 2 {
            return None;
        }

        // we don't support rip related reference with index register yet
        if instruction.memory_base() == Register::RIP
            && instruction.memory_index() != Register::None
        {
            return None;
        }

        if instruction.memory_size() == MemorySize::UInt8
            || instruction.memory_size() == MemorySize::Int8
        {
            return None;
        }

        let op1 = match instruction.op0_kind() {
            OpKind::Register => CmplogOperandType::Reg(instruction.op0_register()),
            OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate32to64 => CmplogOperandType::Imm(instruction.immediate(0)),
            OpKind::Memory => {
                // can't use try_into here, since we need to cast u64 to i64
                // which is fine in this case
                #[expect(clippy::cast_possible_wrap)]
                CmplogOperandType::Mem(
                    instruction.memory_base(),
                    instruction.memory_index(),
                    instruction.memory_displacement64() as i64,
                    instruction.memory_index_scale(),
                    instruction.memory_size(),
                )
            }
            _ => {
                return None;
            }
        };

        let op2 = match instruction.op1_kind() {
            OpKind::Register => CmplogOperandType::Reg(instruction.op1_register()),
            OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate32to64 => CmplogOperandType::Imm(instruction.immediate(1)),
            OpKind::Memory =>
            {
                #[expect(clippy::cast_possible_wrap)]
                CmplogOperandType::Mem(
                    instruction.memory_base(),
                    instruction.memory_index(),
                    instruction.memory_displacement64() as i64,
                    instruction.memory_index_scale(),
                    instruction.memory_size(),
                )
            }
            _ => {
                return None;
            }
        };

        // debug print, shows all the cmp instrumented instructions
        if log::log_enabled!(log::Level::Debug) {
            use iced_x86::{Formatter, NasmFormatter};
            let mut formatter = NasmFormatter::new();
            let mut output = String::new();
            formatter.format(&instruction, &mut output);
            log::debug!(
                "inst: {:x} {:?}, {:?} {:?}",
                instruction.ip(),
                output,
                op1,
                op2
            );
        }

        Some((op1, op2, None, None))
    }

    #[cfg(all(feature = "cmplog", target_arch = "aarch64"))]
    #[expect(clippy::similar_names, clippy::type_complexity)]
    #[inline]
    /// Check if the current instruction is cmplog relevant one(any opcode which sets the flags)
    #[must_use]
    pub fn cmplog_is_interesting_instruction(
        decoder: InstDecoder,
        _address: u64,
        instr: &Insn,
    ) -> Option<(
        CmplogOperandType,
        CmplogOperandType,
        Option<(ShiftStyle, u8)>, //possible shifts: everything except MSL
        Option<SpecialCmpLogCase>,
    )> {
        let mut instr = disas_count(&decoder, instr.bytes(), 1)[0];
        let operands_len = instr
            .operands
            .iter()
            .position(|item| *item == Operand::Nothing)
            .unwrap_or(4);
        // "cmp" | "ands" | "subs" | "adds" | "negs" | "ngcs" | "sbcs" | "bics" | "cbz"
        //    | "cbnz" | "tbz" | "tbnz" | "adcs" - yaxpeax aliases insns (i.e., cmp -> subs)
        // We only care for compare instructions - aka instructions which set the flags
        match instr.opcode {
            Opcode::SUBS
            | Opcode::ANDS
            | Opcode::ADDS
            | Opcode::SBCS
            | Opcode::BICS
            | Opcode::CBZ
            | Opcode::CBNZ
            | Opcode::TBZ
            | Opcode::TBNZ
            | Opcode::ADC => (),
            _ => return None,
        }

        // cbz - 1 operand, everything else - 3 operands
        let special_case = [
            Opcode::CBZ,
            Opcode::CBNZ,
            Opcode::TBZ,
            Opcode::TBNZ,
            Opcode::SUBS,
            Opcode::ADDS,
            Opcode::ANDS,
            Opcode::SBCS,
            Opcode::BICS,
            Opcode::ADCS,
        ]
        .contains(&instr.opcode);
        //this check is to ensure that there are the right number of operands
        if operands_len != 2 && !special_case {
            return None;
        }

        // handle special opcodes case which have 3 operands, but the 1st(dest) is not important to us
        ////subs", "adds", "ands", "sbcs", "bics", "adcs"
        if [
            Opcode::SUBS,
            Opcode::ADDS,
            Opcode::ANDS,
            Opcode::SBCS,
            Opcode::BICS,
            Opcode::ADCS,
        ]
        .contains(&instr.opcode)
        {
            //remove the dest operand from the list
            instr.operands.rotate_left(1);
            instr.operands[3] = Operand::Nothing;
        }

        // cbz marked as special since there is only 1 operand
        #[expect(clippy::cast_sign_loss)]
        let special_case = matches!(instr.opcode, Opcode::CBZ | Opcode::CBNZ);

        #[expect(clippy::cast_sign_loss, clippy::similar_names)]
        let operand1 = match instr.operands[0] {
            //the only possibilities are registers for the first operand
            //precompute the aarch64 frida register because it is ambiguous if register=31 means xzr or sp in yaxpeax
            Operand::Register(sizecode, reg) => Some(CmplogOperandType::Regid(writer_register(
                reg, sizecode, true,
            ))),
            Operand::RegisterOrSP(sizecode, reg) => Some(CmplogOperandType::Regid(
                writer_register(reg, sizecode, false),
            )),
            _ => panic!("First argument is not a register"), //this should never be possible in arm64
        };

        #[expect(clippy::cast_sign_loss)]
        let operand2 = if special_case {
            Some((CmplogOperandType::Imm(0), None))
        } else {
            match instr.operands[1] {
                Operand::Register(sizecode, reg) => Some((
                    CmplogOperandType::Regid(writer_register(reg, sizecode, true)),
                    None,
                )),
                Operand::ImmShift(imm, shift) => {
                    Some((CmplogOperandType::Imm(u64::from(imm) << shift), None))
                } //precalculate the shift
                Operand::RegShift(shiftstyle, amount, regsize, reg) => {
                    let reg = CmplogOperandType::Regid(writer_register(reg, regsize, true));
                    let shift = (shiftstyle, amount);
                    Some((reg, Some(shift)))
                }
                Operand::Immediate(imm) => Some((CmplogOperandType::Imm(u64::from(imm)), None)),
                _ => panic!("Second argument could not be decoded"),
            }
        };

        // tbz will need to have special handling at emit time(masking operand1 value with operand2)
        let special_case = match instr.opcode {
            Opcode::TBZ => Some(SpecialCmpLogCase::Tbz),
            Opcode::TBNZ => Some(SpecialCmpLogCase::Tbnz),
            _ => None,
        };

        if let Some(op1) = operand1 {
            operand2.map(|op2| (op1, op2.0, op2.1, special_case))
        } else {
            None
        }
    }
}

impl Default for CmpLogRuntime {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}
