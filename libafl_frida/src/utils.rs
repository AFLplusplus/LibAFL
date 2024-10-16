#[cfg(target_arch = "aarch64")]
use frida_gum::instruction_writer::Aarch64Register;
#[cfg(target_arch = "x86_64")]
use frida_gum::{instruction_writer::X86Register, CpuContext};
#[cfg(target_arch = "x86_64")]
use libafl::Error;
#[cfg(target_arch = "aarch64")]
use num_traits::cast::FromPrimitive;
#[cfg(target_arch = "x86_64")]
use yaxpeax_arch::LengthedInstruction;
#[cfg(target_arch = "aarch64")]
use yaxpeax_arch::{Decoder, ReaderBuilder};
#[cfg(target_arch = "aarch64")]
use yaxpeax_arm::armv8::a64::{InstDecoder, Instruction, Opcode, Operand, SIMDSizeCode, SizeCode};
#[cfg(target_arch = "x86_64")]
use yaxpeax_x86::amd64::Operand;
#[cfg(target_arch = "x86_64")]
use yaxpeax_x86::amd64::{InstDecoder, Instruction, RegSpec};

/// Determine the size of an SIMD register
#[cfg(target_arch = "aarch64")]
#[inline]
#[must_use]
pub fn get_simd_size(sizecode: SIMDSizeCode) -> u32 {
    match sizecode {
        SIMDSizeCode::B => 1,
        SIMDSizeCode::H => 2,
        SIMDSizeCode::S => 4,
        SIMDSizeCode::D => 8,
        SIMDSizeCode::Q => 16,
    }
}

/// Determine the size of a normal register
#[cfg(target_arch = "aarch64")]
#[inline]
#[must_use]
pub fn get_reg_size(sizecode: SizeCode) -> u32 {
    match sizecode {
        SizeCode::W => {
            //this is guaranteed to be 4 because we deal with the strb/ldrb and strh/ldrh should be dealt with in instruction_width
            4
        }
        SizeCode::X => 8,
    }
}

/// Determine the width of the specified instruction
#[cfg(target_arch = "aarch64")]
#[inline]
#[must_use]
pub fn instruction_width(instr: &Instruction) -> u32 {
    let num_registers = match instr.opcode {
        Opcode::STP
        | Opcode::STXP
        | Opcode::STNP
        | Opcode::STLXP
        | Opcode::LDP
        | Opcode::LDXP
        | Opcode::LDNP => 2,
        _ => 1,
    };

    // let mnemonic = instr.opcode.to_string().as_bytes();
    match instr.opcode.to_string().as_bytes().last().unwrap() {
        b'b' => return 1,
        b'h' => return 2,
        b'w' => return 4 * num_registers,
        _ => (),
    }

    let size = match instr.operands.first().unwrap() {
        Operand::Register(sizecode, _) => {
            //this is used for standard loads/stores including ldr, ldp, etc.
            get_reg_size(*sizecode)
        }
        Operand::RegisterPair(sizecode, _) => {
            //not sure where this is used, but it is possible in yaxpeax
            get_reg_size(*sizecode)
        }
        Operand::SIMDRegister(sizecode, _) => {
            //this is used in cases like ldr q0, [sp]
            get_simd_size(*sizecode)
        }
        Operand::SIMDRegisterGroup(sizecode, _, _, num) => {
            ////This is used for cases such as ld4 {v1.2s, v2.2s, v3.2s, v4.2s}, [x0].
            //the sizecode is the size of each simd structure (This can only be D or Q), num is the number of them (i.e. ld4 would be 4)
            get_simd_size(*sizecode) * u32::from(*num)
        }
        Operand::SIMDRegisterGroupLane(_, sizecode, num, _) => {
            //This is used for cases such as ld4 {v0.s, v1.s, v2.s, v3.s}[0], [x0]. In this case sizecode is the size of each lane, num is the number of them
            get_simd_size(*sizecode) * u32::from(*num)
        }
        _ => {
            return 0;
        }
    };
    num_registers * size
}

/// Convert from a yaxpeax register to frida gum's register state
#[cfg(target_arch = "aarch64")]
#[must_use]
#[inline]
pub fn writer_register(reg: u16, sizecode: SizeCode, zr: bool) -> Aarch64Register {
    //yaxpeax and arm both make it so that depending on the opcode reg=31 can be EITHER SP or XZR.
    match (reg, sizecode, zr) {
        (0..=28, SizeCode::X, _) => {
            Aarch64Register::from_u32(Aarch64Register::X0 as u32 + u32::from(reg)).unwrap()
        }
        (0..=30, SizeCode::W, _) => {
            Aarch64Register::from_u32(Aarch64Register::W0 as u32 + u32::from(reg)).unwrap()
        }
        (29, SizeCode::X, _) => Aarch64Register::Fp,
        (30, SizeCode::X, _) => Aarch64Register::Lr,
        (31, SizeCode::X, false) => Aarch64Register::Sp,
        (31, SizeCode::W, false) => Aarch64Register::Wsp,
        (31, SizeCode::X, true) => Aarch64Register::Xzr,
        (31, SizeCode::W, true) => Aarch64Register::Wzr,
        _ => panic!("Failed to get writer register"),
    }
}

/// Translate from `RegSpec` to `X86Register`
#[cfg(target_arch = "x86_64")]
const X86_64_REGS: [(RegSpec, X86Register); 34] = [
    (RegSpec::eax(), X86Register::Eax),
    (RegSpec::ecx(), X86Register::Ecx),
    (RegSpec::edx(), X86Register::Edx),
    (RegSpec::ebx(), X86Register::Ebx),
    (RegSpec::esp(), X86Register::Esp),
    (RegSpec::ebp(), X86Register::Ebp),
    (RegSpec::esi(), X86Register::Esi),
    (RegSpec::edi(), X86Register::Edi),
    (RegSpec::r8d(), X86Register::R8d),
    (RegSpec::r9d(), X86Register::R9d),
    (RegSpec::r10d(), X86Register::R10d),
    (RegSpec::r11d(), X86Register::R11d),
    (RegSpec::r12d(), X86Register::R12d),
    (RegSpec::r13d(), X86Register::R13d),
    (RegSpec::r14d(), X86Register::R14d),
    (RegSpec::r15d(), X86Register::R15d),
    (RegSpec::eip(), X86Register::Eip),
    (RegSpec::rax(), X86Register::Rax),
    (RegSpec::rcx(), X86Register::Rcx),
    (RegSpec::rdx(), X86Register::Rdx),
    (RegSpec::rbx(), X86Register::Rbx),
    (RegSpec::rsp(), X86Register::Rsp),
    (RegSpec::rbp(), X86Register::Rbp),
    (RegSpec::rsi(), X86Register::Rsi),
    (RegSpec::rdi(), X86Register::Rdi),
    (RegSpec::r8(), X86Register::R8),
    (RegSpec::r9(), X86Register::R9),
    (RegSpec::r10(), X86Register::R10),
    (RegSpec::r11(), X86Register::R11),
    (RegSpec::r12(), X86Register::R12),
    (RegSpec::r13(), X86Register::R13),
    (RegSpec::r14(), X86Register::R14),
    (RegSpec::r15(), X86Register::R15),
    (RegSpec::rip(), X86Register::Rip),
];

/// Get the value of a register given a context
#[cfg(target_arch = "x86_64")]
#[must_use]
pub fn get_register(context: &CpuContext, reg: X86Register) -> u64 {
    match reg {
        X86Register::Rax => context.rax(),
        X86Register::Rbx => context.rbx(),
        X86Register::Rcx => context.rcx(),
        X86Register::Rdx => context.rdx(),
        X86Register::Rdi => context.rdi(),
        X86Register::Rsi => context.rsi(),
        X86Register::Rsp => context.rsp(),
        X86Register::Rbp => context.rbp(),
        X86Register::R8 => context.r8(),
        X86Register::R9 => context.r9(),
        X86Register::R10 => context.r10(),
        X86Register::R11 => context.r11(),
        X86Register::R12 => context.r12(),
        X86Register::R13 => context.r13(),
        X86Register::R14 => context.r14(),
        X86Register::R15 => context.r15(),
        _ => 0,
    }
}

/// The writer registers.
///
///  `FRIDA` registers: <https://docs.rs/frida-gum/latest/frida_gum/instruction_writer/enum.X86Register.html>
/// `capstone` registers: <https://docs.rs/capstone-sys/latest/capstone_sys/x86_reg/index.html>
#[cfg(target_arch = "x86_64")]
#[must_use]
#[inline]
#[allow(clippy::unused_self)]
pub fn writer_register(reg: RegSpec) -> X86Register {
    for (reg1, reg2) in &X86_64_REGS {
        // println!("reg1:{:#?} reg2:{:#?}", reg1, reg);
        if *reg1 == reg {
            return *reg2;
        }
    }
    X86Register::None
}

/// Translates a `FRIDA` instruction to a disassembled instruction.
#[cfg(target_arch = "x86_64")]
pub(crate) fn frida_to_cs(
    decoder: InstDecoder,
    frida_insn: &frida_gum_sys::Insn,
) -> Result<Instruction, Error> {
    match decoder.decode_slice(frida_insn.bytes()) {
        Ok(result) => Ok(result),
        Err(error) => {
            log::error!(
                "{:?}: {:x}: {:?}",
                error,
                frida_insn.address(),
                frida_insn.bytes()
            );
            Err(Error::illegal_state(
                "Instruction did not disassemble properly",
            ))
        }
    }
}

/// Get the `base`, `idx`, `scale`, `disp` for each operand
#[cfg(target_arch = "x86_64")]
#[must_use]
pub fn operand_details(operand: &Operand) -> Option<(X86Register, X86Register, u8, i32)> {
    match operand {
        Operand::MemDeref { base } => {
            let base = writer_register(*base);
            Some((base, X86Register::None, 0, 0))
        }
        Operand::Disp { base, disp } => {
            let base = writer_register(*base);
            Some((base, X86Register::None, 0, *disp))
        }
        Operand::MemIndexScale { index, scale } => {
            let index = writer_register(*index);
            Some((X86Register::None, index, *scale, 0))
        }
        Operand::MemIndexScaleDisp { index, scale, disp } => {
            let index = writer_register(*index);
            Some((X86Register::None, index, *scale, *disp))
        }
        Operand::MemBaseIndexScale { base, index, scale } => {
            let base = writer_register(*base);
            let index = writer_register(*index);
            Some((base, index, *scale, 0))
        }
        Operand::MemBaseIndexScaleDisp {
            base,
            index,
            scale,
            disp,
        } => {
            let base = writer_register(*base);
            let index = writer_register(*index);
            Some((base, index, *scale, *disp))
        }
        _ => None,
    }
}

/// Get the immediate value of the operand
#[cfg(target_arch = "x86_64")]
#[must_use]
pub fn immediate_value(operand: &Operand) -> Option<i64> {
    match operand {
        Operand::ImmediateI8 { imm } => Some(i64::from(*imm)),
        Operand::ImmediateU8 { imm } => Some(i64::from(*imm)),
        Operand::ImmediateI16 { imm } => Some(i64::from(*imm)),
        Operand::ImmediateU16 { imm } => Some(i64::from(*imm)),
        Operand::ImmediateI32 { imm } => Some(i64::from(*imm)),
        Operand::ImmediateU32 { imm } => Some(i64::from(*imm)),
        Operand::ImmediateI64 { imm } => Some(*imm),
        #[allow(clippy::cast_possible_wrap)]
        Operand::ImmediateU64 { imm } => Some(*imm as i64),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy)]
#[cfg(target_arch = "x86_64")]
/// What kind of memory access this instruction has
pub enum AccessType {
    /// Read-access
    Read,
    /// Write-access
    Write,
}

/// Disassemble "count" number of instructions
#[cfg(target_arch = "x86_64")]
#[must_use]
pub fn disas_count(decoder: &InstDecoder, data: &[u8], count: usize) -> Vec<Instruction> {
    let mut counter = count;
    let mut ret = vec![];
    let mut start = 0;
    loop {
        if counter == 0 {
            break ret;
        }
        let Ok(inst) = decoder.decode_slice(&data[start..]) else {
            break ret;
        };
        start += inst.len().to_const() as usize;

        ret.push(inst);
        counter -= 1;
    }
}

#[cfg(target_arch = "aarch64")]
/// Disassemble "count" number of instructions
#[must_use]
pub fn disas_count(decoder: &InstDecoder, data: &[u8], _count: usize) -> Vec<Instruction> {
    let mut ret = vec![];

    let mut reader = ReaderBuilder::<u64, u8>::read_from(data);

    while let Ok(insn) = decoder.decode(&mut reader) {
        ret.push(insn);
    }

    ret
}
