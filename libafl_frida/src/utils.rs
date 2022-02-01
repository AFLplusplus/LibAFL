#[cfg(target_arch = "aarch64")]
use frida_gum::instruction_writer::Aarch64Register;
#[cfg(target_arch = "x86_64")]
use frida_gum::instruction_writer::X86Register;

#[cfg(target_arch = "aarch64")]
use capstone::{
    arch::{self, arm64::Arm64OperandType, ArchOperand::Arm64Operand},
    Insn,
};

#[cfg(target_arch = "aarch64")]
use num_traits::cast::FromPrimitive;

/// Determine the width of the specified instruction
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn instruction_width(instr: &Insn, operands: &Vec<arch::ArchOperand>) -> u32 {
    use capstone::arch::arm64::Arm64Insn as I;
    use capstone::arch::arm64::Arm64Reg as R;
    use capstone::arch::arm64::Arm64Vas as V;

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
                V::ARM64_VAS_1B => 1 * count_byte,
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
            match operand.0 as u32 {
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

/// Convert from a capstone register id to a frida InstructionWriter register index
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn writer_register(reg: capstone::RegId) -> Aarch64Register {
    let regint: u16 = reg.0;
    Aarch64Register::from_u32(regint as u32).unwrap()
}

/// The writer registers
/// frida registers: <https://docs.rs/frida-gum/0.4.0/frida_gum/instruction_writer/enum.X86Register.html>
/// capstone registers: <https://docs.rs/capstone-sys/0.14.0/capstone_sys/x86_reg/index.html>
#[cfg(all(target_arch = "x86_64", unix))]
#[must_use]
#[inline]
#[allow(clippy::unused_self)]
pub fn writer_register(reg: capstone::RegId) -> X86Register {
    let regint: u16 = reg.0;
    match regint {
        19 => X86Register::Eax,
        22 => X86Register::Ecx,
        24 => X86Register::Edx,
        21 => X86Register::Ebx,
        30 => X86Register::Esp,
        20 => X86Register::Ebp,
        29 => X86Register::Esi,
        23 => X86Register::Edi,
        226 => X86Register::R8d,
        227 => X86Register::R9d,
        228 => X86Register::R10d,
        229 => X86Register::R11d,
        230 => X86Register::R12d,
        231 => X86Register::R13d,
        232 => X86Register::R14d,
        233 => X86Register::R15d,
        26 => X86Register::Eip,
        35 => X86Register::Rax,
        38 => X86Register::Rcx,
        40 => X86Register::Rdx,
        37 => X86Register::Rbx,
        44 => X86Register::Rsp,
        36 => X86Register::Rbp,
        43 => X86Register::Rsi,
        39 => X86Register::Rdi,
        106 => X86Register::R8,
        107 => X86Register::R9,
        108 => X86Register::R10,
        109 => X86Register::R11,
        110 => X86Register::R12,
        111 => X86Register::R13,
        112 => X86Register::R14,
        113 => X86Register::R15,
        41 => X86Register::Rip,
        _ => X86Register::None, // Ignore Xax..Xip
    }
}
