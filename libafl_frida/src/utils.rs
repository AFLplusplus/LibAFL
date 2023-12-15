#[cfg(target_arch = "aarch64")]
use capstone::Capstone;
#[cfg(target_arch = "aarch64")]
use capstone::{
    arch::{self, arm64::Arm64OperandType, ArchOperand::Arm64Operand},
    Insn,
};
#[cfg(target_arch = "aarch64")]
use frida_gum::instruction_writer::Aarch64Register;
#[cfg(target_arch = "x86_64")]
use frida_gum::instruction_writer::X86Register;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use frida_gum_sys;
#[cfg(target_arch = "aarch64")]
use num_traits::cast::FromPrimitive;
#[cfg(target_arch = "x86_64")]
use yaxpeax_arch::LengthedInstruction;
use yaxpeax_x86::amd64::Operand;
#[cfg(target_arch = "x86_64")]
use yaxpeax_x86::amd64::{InstDecoder, Instruction, RegSpec};

/// Determine the width of the specified instruction
#[cfg(target_arch = "aarch64")]
#[inline]
#[must_use]
pub fn instruction_width(instr: &Insn, operands: &[arch::ArchOperand]) -> u32 {
    use capstone::arch::arm64::{Arm64Insn as I, Arm64Reg as R, Arm64Vas as V};

    let num_registers = match instr.id().0.into() {
        I::ARM64_INS_STP
        | I::ARM64_INS_STXP
        | I::ARM64_INS_STNP
        | I::ARM64_INS_STLXP
        | I::ARM64_INS_LDP
        | I::ARM64_INS_LDXP
        | I::ARM64_INS_LDNP => 2,
        _ => 1,
    };

    let mnemonic = instr.mnemonic().unwrap();
    match mnemonic.as_bytes().last().unwrap() {
        b'b' => return 1,
        b'h' => return 2,
        b'w' => return 4 * num_registers,
        _ => (),
    }

    if let Arm64Operand(operand) = operands.first().unwrap() {
        if operand.vas != V::ARM64_VAS_INVALID {
            let count_byte: u32 = if mnemonic.starts_with("st") || mnemonic.starts_with("ld") {
                mnemonic.chars().nth(2).unwrap().to_digit(10).unwrap()
            } else {
                1
            };

            return match operand.vas {
                V::ARM64_VAS_1B => count_byte,
                V::ARM64_VAS_1H => 2 * count_byte,
                V::ARM64_VAS_4B | V::ARM64_VAS_1S | V::ARM64_VAS_1D | V::ARM64_VAS_2H => {
                    4 * count_byte
                }
                V::ARM64_VAS_8B
                | V::ARM64_VAS_4H
                | V::ARM64_VAS_2S
                | V::ARM64_VAS_2D
                | V::ARM64_VAS_1Q => 8 * count_byte,
                V::ARM64_VAS_8H | V::ARM64_VAS_4S | V::ARM64_VAS_16B => 16 * count_byte,
                V::ARM64_VAS_INVALID => {
                    panic!("should not be reached");
                }
            };
        } else if let Arm64OperandType::Reg(operand) = operand.op_type {
            match u32::from(operand.0) {
                R::ARM64_REG_W0..=R::ARM64_REG_W30
                | R::ARM64_REG_WZR
                | R::ARM64_REG_WSP
                | R::ARM64_REG_S0..=R::ARM64_REG_S31 => return 4 * num_registers,
                R::ARM64_REG_D0..=R::ARM64_REG_D31 => return 8 * num_registers,
                R::ARM64_REG_Q0..=R::ARM64_REG_Q31 => return 16,
                _ => (),
            }
        };
    };

    8 * num_registers
}

/// Convert from a capstone register id to a frida `InstructionWriter` register index
#[cfg(target_arch = "aarch64")]
#[must_use]
#[inline]
pub fn writer_register(reg: capstone::RegId) -> Aarch64Register {
    let regint: u16 = reg.0;
    Aarch64Register::from_u32(u32::from(regint)).unwrap()
}

/// Translate from `RegSpec` to `X86Register`
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

/// The writer registers
/// frida registers: <https://docs.rs/frida-gum/0.4.0/frida_gum/instruction_writer/enum.X86Register.html>
/// capstone registers: <https://docs.rs/capstone-sys/0.14.0/capstone_sys/x86_reg/index.html>
#[cfg(all(target_arch = "x86_64", unix))]
#[must_use]
#[inline]
#[allow(clippy::unused_self)]
pub fn writer_register(reg: RegSpec) -> X86Register {
    for (reg1, reg2) in X86_64_REGS.iter() {
        if *reg1 == reg {
            return reg2.clone();
        }
    }
    return X86Register::None;
}

/// Translates a frida instruction to a capstone instruction.
/// Returns a [`capstone::Instructions`] with a single [`capstone::Insn`] inside.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub(crate) fn frida_to_cs<'a>(
    decoder: &'a InstDecoder,
    frida_insn: &frida_gum_sys::Insn,
) -> Instruction {
    decoder.decode_slice(frida_insn.bytes()).unwrap()
}

#[cfg(any(target_arch = "x86_64"))]
/// Get the base, idx, scale, disp for each operand
pub fn operand_details(operand: Operand) -> Option<(X86Register, X86Register, u8, i32)> {
    match operand {
        Operand::RegDeref(base) => {
            let base = writer_register(base);
            Some((base, X86Register::None, 0, 0))
        }
        Operand::RegDisp(base, disp) => {
            let base = writer_register(base);
            Some((base, X86Register::None, 0, disp))
        }
        Operand::RegScale(base, scale) => {
            let base = writer_register(base);
            Some((base, X86Register::None, scale, 0))
        }
        Operand::RegIndexBase(base, index) => {
            let base = writer_register(base);
            let index = writer_register(index);
            Some((base, index, 0, 0))
        }
        Operand::RegIndexBaseDisp(base, index, disp) => {
            let base = writer_register(base);
            let index = writer_register(index);
            Some((base, index, 0, disp))
        }
        Operand::RegScaleDisp(base, scale, disp) => {
            let base = writer_register(base);
            Some((base, X86Register::None, scale, disp))
        }
        Operand::RegIndexBaseScale(base, index, scale) => {
            let base = writer_register(base);
            let index = writer_register(index);
            Some((base, index, scale, 0))
        }
        Operand::RegIndexBaseScaleDisp(base, index, scale, disp) => {
            let base = writer_register(base);
            let index = writer_register(index);
            Some((base, index, scale, disp))
        }
        _ => None,
    }
}

#[derive(Debug, Clone, Copy)]
#[cfg(any(target_arch = "x86_64"))]
/// What kind of memory access this instruction has
pub enum AccessType {
    /// Read-access
    Read,
    /// Write-access
    Write,
}

#[cfg(target_arch = "x86_64")]
/// Disassemble "count" number of instructions
pub fn disas_count(decoder: &InstDecoder, data: &[u8], count: usize) -> Vec<Instruction> {
    let mut counter = count;
    let mut ret = vec![];
    let mut start = 0;
    loop {
        if counter <= 0 {
            break ret;
        }
        let inst = match decoder.decode_slice(&data[start..]) {
            Ok(i) => i,
            Err(_) => break ret, // am i right here?
        };
        start += inst.len().to_const() as usize;

        ret.push(inst);
        counter -= 1;
    }
}
