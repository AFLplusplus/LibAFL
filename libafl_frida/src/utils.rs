#[cfg(any(target_arch = "x86_64"))]
use capstone::Capstone;
#[cfg(target_arch = "aarch64")]
use frida_gum::instruction_writer::Aarch64Register;
#[cfg(target_arch = "aarch64")]
use yaxpeax_arm::armv8::a64::{Instruction, Operand, Opcode, SIMDSizeCode, SizeCode};
#[cfg(target_arch = "x86_64")]
use frida_gum::instruction_writer::X86Register;
#[cfg(any(target_arch = "x86_64"))]
use frida_gum_sys;
#[cfg(target_arch = "aarch64")]
use num_traits::cast::FromPrimitive;

/// Determine the size of an SIMD register
#[cfg(target_arch = "aarch64")]
#[inline]
#[must_use]
pub fn get_simd_size(sizecode: SIMDSizeCode) -> u32 {
    match sizecode{
        SIMDSizeCode::B => {
            1
        },
        SIMDSizeCode::H => {
            2
        },
        SIMDSizeCode::S => {
            4
        },
        SIMDSizeCode::D => {
            8
        },
        SIMDSizeCode::Q => {
            16
        }
    }
}

/// Determine the size of a normal register
#[cfg(target_arch = "aarch64")]
#[inline]
#[must_use]
pub fn get_reg_size(sizecode: SizeCode) -> u32 {
    match sizecode{ 
        SizeCode::W => { //this is guaranteed to be 4 because we deal with the strb/ldrb and strh/ldrh should be dealt with in instruction_width
            4
        },
        SizeCode::X => {
            8
        },
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
        Operand::Register(sizecode, _) => { //this is used for standard loads/stores including ldr, ldp, etc.
            get_reg_size(*sizecode)
        },
        Operand::RegisterPair(sizecode, _) => { //not sure where this is used, but it is possible in yaxpeax
            get_reg_size(*sizecode)
        }
        Operand::SIMDRegister(sizecode, _) => { //this is used in cases like ldr q0, [sp]
            get_simd_size(*sizecode)
        },
        Operand::SIMDRegisterGroup(sizecode, _, _, num) => { 
            ////This is used for cases such as ld4 {v1.2s, v2.2s, v3.2s, v4.2s}, [x0]. 
            //the sizecode is the size of each simd structure (This can only be D or Q), num is the number of them (i.e. ld4 would be 4)
            get_simd_size(*sizecode) * *num as u32
        },
        Operand::SIMDRegisterGroupLane(_, sizecode, num, _) => {
            //This is used for cases such as ld4 {v0.s, v1.s, v2.s, v3.s}[0], [x0]. In this case sizecode is the size of each lane, num is the number of them
            get_simd_size(*sizecode) * *num as u32
        },
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
        (0..=28, SizeCode::X, _) => Aarch64Register::from_u32(Aarch64Register::X0 as u32 + reg as u32).unwrap(),
        (0..=30, SizeCode::W, _) => Aarch64Register::from_u32(Aarch64Register::W0 as u32 + reg as u32).unwrap(),
        (29, SizeCode::X, _) => Aarch64Register::Fp,
        (30, SizeCode::X, _) => Aarch64Register::Lr,
        (31, SizeCode::X, false) => Aarch64Register::Sp,
        (31, SizeCode::W, false) => Aarch64Register::Wsp,
        (31, SizeCode::X, true) => Aarch64Register::Xzr,
        (31, SizeCode::W, true) => Aarch64Register::Wzr,
        _ => panic!("Failed to get writer register")
    }
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

/// Translates a frida instruction to a capstone instruction.
/// Returns a [`capstone::Instructions`] with a single [`capstone::Insn`] inside.
#[cfg(any(target_arch = "x86_64"))]
pub(crate) fn frida_to_cs<'a>(
    capstone: &'a Capstone,
    frida_insn: &frida_gum_sys::Insn,
) -> capstone::Instructions<'a> {
    capstone
        .disasm_count(frida_insn.bytes(), frida_insn.address(), 1)
        .unwrap()
}
