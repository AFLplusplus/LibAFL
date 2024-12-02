use std::sync::OnceLock;

use capstone::arch::BuildsCapstone;
use enum_map::{enum_map, EnumMap};
use num_enum::{IntoPrimitive, TryFromPrimitive};
#[cfg(feature = "python")]
use pyo3::prelude::*;
pub use strum_macros::EnumIter;
pub use syscall_numbers::arm::*;

use crate::{sync_exit::ExitArgs, CallingConvention, QemuRWError, QemuRWErrorKind};

/// Registers for the ARM instruction set.
#[derive(IntoPrimitive, TryFromPrimitive, Debug, Clone, Copy, EnumIter)]
#[repr(i32)]
pub enum Regs {
    R0 = 0,
    R1 = 1,
    R2 = 2,
    R3 = 3,
    R4 = 4,
    R5 = 5,
    R6 = 6,
    R7 = 7,
    R8 = 8,
    R9 = 9,
    R10 = 10,
    R11 = 11,
    R12 = 12,
    R13 = 13,
    R14 = 14,
    R15 = 15,
    R25 = 25,
}

static EXIT_ARCH_REGS: OnceLock<EnumMap<ExitArgs, Regs>> = OnceLock::new();

pub fn get_exit_arch_regs() -> &'static EnumMap<ExitArgs, Regs> {
    EXIT_ARCH_REGS.get_or_init(|| {
        enum_map! {
            ExitArgs::Ret  => Regs::R0,
            ExitArgs::Cmd  => Regs::R0,
            ExitArgs::Arg1 => Regs::R1,
            ExitArgs::Arg2 => Regs::R2,
            ExitArgs::Arg3 => Regs::R3,
            ExitArgs::Arg4 => Regs::R4,
            ExitArgs::Arg5 => Regs::R5,
            ExitArgs::Arg6 => Regs::R6,
        }
    })
}

/// alias registers
#[allow(non_upper_case_globals)]
impl Regs {
    pub const Sp: Regs = Regs::R13;
    pub const Lr: Regs = Regs::R14;
    pub const Pc: Regs = Regs::R15;
    pub const Sb: Regs = Regs::R9;
    pub const Sl: Regs = Regs::R10;
    pub const Fp: Regs = Regs::R11;
    pub const Ip: Regs = Regs::R12;
    pub const Cpsr: Regs = Regs::R25;
}

/// Return an ARM ArchCapstoneBuilder
pub fn capstone() -> capstone::arch::arm::ArchCapstoneBuilder {
    capstone::Capstone::new()
        .arm()
        .mode(capstone::arch::arm::ArchMode::Arm)
}

/// Return an ARM Thumb ArchCapstoneBuilder
pub fn capstone_thumb() -> capstone::arch::arm::ArchCapstoneBuilder {
    capstone::Capstone::new()
        .arm()
        .mode(capstone::arch::arm::ArchMode::Thumb)
}

pub type GuestReg = u32;

impl crate::ArchExtras for crate::CPU {
    fn read_return_address(&self) -> Result<GuestReg, QemuRWError> {
        self.read_reg(Regs::Lr)
    }

    fn write_return_address<T>(&self, val: T) -> Result<(), QemuRWError>
    where
        T: Into<GuestReg>,
    {
        self.write_reg(Regs::Lr, val)
    }

    fn read_function_argument(
        &self,
        conv: CallingConvention,
        idx: u8,
    ) -> Result<GuestReg, QemuRWError> {
        QemuRWError::check_conv(QemuRWErrorKind::Read, CallingConvention::Cdecl, conv)?;

        let reg_id = match idx {
            0 => Regs::R0,
            1 => Regs::R1,
            2 => Regs::R2,
            3 => Regs::R3,
            // 4.. would be on the stack, let's not do this for now
            r => {
                return Err(QemuRWError::new_argument_error(
                    QemuRWErrorKind::Read,
                    i32::from(r),
                ))
            }
        };

        self.read_reg(reg_id)
    }

    fn write_function_argument<T>(
        &self,
        conv: CallingConvention,
        idx: i32,
        val: T,
    ) -> Result<(), QemuRWError>
    where
        T: Into<GuestReg>,
    {
        QemuRWError::check_conv(QemuRWErrorKind::Write, CallingConvention::Cdecl, conv)?;

        let val: GuestReg = val.into();
        match idx {
            0 => self.write_reg(Regs::R0, val),
            1 => self.write_reg(Regs::R1, val),
            r => Err(QemuRWError::new_argument_error(QemuRWErrorKind::Write, r)),
        }
    }
}
