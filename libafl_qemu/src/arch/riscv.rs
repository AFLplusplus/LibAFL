use core::ffi::c_long;
use std::sync::OnceLock;

use capstone::arch::BuildsCapstone;
use enum_map::{EnumMap, enum_map};
use num_enum::{IntoPrimitive, TryFromPrimitive};
#[cfg(feature = "python")]
use pyo3::prelude::*;
pub use strum_macros::EnumIter;
#[cfg(feature = "riscv32")]
pub use syscall_numbers::riscv32::*;
#[cfg(feature = "riscv64")]
pub use syscall_numbers::riscv64::*;

// QEMU specific
#[expect(non_upper_case_globals)]
pub const SYS_syscalls: c_long = 447;
#[expect(non_upper_case_globals)]
pub const SYS_riscv_flush_icache: c_long = SYS_arch_specific_syscall + 15;
#[expect(non_upper_case_globals)]
pub const SYS_riscv_hwprobe: c_long = SYS_arch_specific_syscall + 14;

use crate::{CallingConvention, QemuRWError, QemuRWErrorKind, sync_exit::ExitArgs};

#[expect(non_upper_case_globals)]
impl CallingConvention {
    pub const Default: CallingConvention = CallingConvention::RiscVilp32;
}

#[derive(IntoPrimitive, TryFromPrimitive, Debug, Clone, Copy, EnumIter)]
#[repr(i32)]
pub enum Regs {
    Zero = 0, // x0: Hardwired zero
    Ra = 1,   // x1: Return address
    Sp = 2,   // x2: Stack pointer
    Gp = 3,   // x3: Global pointer
    Tp = 4,   // x4: Thread pointer
    T0 = 5,   // x5: Temporary register
    T1 = 6,   // x6: Temporary register
    T2 = 7,   // x7: Temporary register
    FP = 8,   // x8: Saved register / frame pointer
    S1 = 9,   // x9: Saved register
    A0 = 10,  // x10: Function argument / return value
    A1 = 11,  // x11: Function argument / return value
    A2 = 12,  // x12: Function argument
    A3 = 13,  // x13: Function argument
    A4 = 14,  // x14: Function argument
    A5 = 15,  // x15: Function argument
    A6 = 16,  // x16: Function argument
    A7 = 17,  // x17: Function argument
    S2 = 18,  // x18: Saved register
    S3 = 19,  // x19: Saved register
    S4 = 20,  // x20: Saved register
    S5 = 21,  // x21: Saved register
    S6 = 22,  // x22: Saved register
    S7 = 23,  // x23: Saved register
    S8 = 24,  // x24: Saved register
    S9 = 25,  // x25: Saved register
    S10 = 26, // x26: Saved register
    S11 = 27, // x27: Saved register
    T3 = 28,  // x28: Temporary register
    T4 = 29,  // x29: Temporary register
    T5 = 30,  // x30: Temporary register
    T6 = 31,  // x31: Temporary register
    Pc = 32,  // Program Counter (code pointer not actual register)
}

static EXIT_ARCH_REGS: OnceLock<EnumMap<ExitArgs, Regs>> = OnceLock::new();

pub fn get_exit_arch_regs() -> &'static EnumMap<ExitArgs, Regs> {
    EXIT_ARCH_REGS.get_or_init(|| {
        enum_map! {
            ExitArgs::Ret  => Regs::A0,
            ExitArgs::Cmd  => Regs::A0,
            ExitArgs::Arg1 => Regs::A1,
            ExitArgs::Arg2 => Regs::A2,
            ExitArgs::Arg3 => Regs::A3,
            ExitArgs::Arg4 => Regs::A4,
            ExitArgs::Arg5 => Regs::A5,
            ExitArgs::Arg6 => Regs::A6,
        }
    })
}

#[cfg(not(feature = "riscv64"))]
pub type GuestReg = u32;
#[cfg(feature = "riscv64")]
pub type GuestReg = u64;

/// Return a RISCV ArchCapstoneBuilder
pub fn capstone() -> capstone::arch::riscv::ArchCapstoneBuilder {
    #[cfg(not(feature = "riscv64"))]
    return capstone::Capstone::new()
        .riscv()
        .mode(capstone::arch::riscv::ArchMode::RiscV32);
    #[cfg(feature = "riscv64")]
    return capstone::Capstone::new()
        .riscv()
        .mode(capstone::arch::riscv::ArchMode::RiscV64);
}

impl crate::ArchExtras for crate::CPU {
    fn read_return_address(&self) -> Result<GuestReg, QemuRWError> {
        self.read_reg(Regs::Ra)
    }

    fn write_return_address<T>(&self, val: T) -> Result<(), QemuRWError>
    where
        T: Into<GuestReg>,
    {
        self.write_reg(Regs::Ra, val)
    }

    fn read_function_argument_with_cc(
        &self,
        idx: u8,
        conv: CallingConvention,
    ) -> Result<GuestReg, QemuRWError> {
        QemuRWError::check_conv(QemuRWErrorKind::Read, CallingConvention::RiscVilp32, conv)?;

        // Note that 64 bit values may be passed in two registers (and are even-odd eg. A0, A2 and A3 where A1 is empty), then this mapping is off.
        // Note: This does not consider the floating point registers.
        // See https://riscv.org/wp-content/uploads/2015/01/riscv-calling.pdf
        let reg_id = match idx {
            0 => Regs::A0, // argument / return value
            1 => Regs::A1, // argument / return value
            2 => Regs::A2, // argument value
            3 => Regs::A3, // argument value
            4 => Regs::A4, // argument value
            5 => Regs::A5, // argument value
            6 => Regs::A6, // argument value
            7 => Regs::A7, // argument value
            r => return Err(QemuRWError::new_argument_error(QemuRWErrorKind::Read, r)),
        };

        self.read_reg(reg_id)
    }

    fn write_function_argument_with_cc<T>(
        &self,
        idx: u8,
        val: T,
        conv: CallingConvention,
    ) -> Result<(), QemuRWError>
    where
        T: Into<GuestReg>,
    {
        QemuRWError::check_conv(QemuRWErrorKind::Write, CallingConvention::RiscVilp32, conv)?;

        let val: GuestReg = val.into();
        match idx {
            0 => self.write_reg(Regs::A0, val), // argument / return value
            1 => self.write_reg(Regs::A1, val), // argument / return value
            r => Err(QemuRWError::new_argument_error(QemuRWErrorKind::Write, r)),
        }
    }
}
