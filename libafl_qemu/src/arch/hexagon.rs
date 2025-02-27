use std::sync::OnceLock;

use enum_map::{EnumMap, enum_map};
use num_enum::{IntoPrimitive, TryFromPrimitive};
#[cfg(feature = "python")]
use pyo3::prelude::*;
pub use strum_macros::EnumIter;

use crate::{CallingConvention, QemuRWError, QemuRWErrorKind, sync_exit::ExitArgs};

#[expect(non_upper_case_globals)]
impl CallingConvention {
    pub const Default: CallingConvention = CallingConvention::Hexagon;
}

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
    R16 = 16,
    R17 = 17,
    R18 = 18,
    R19 = 19,
    R20 = 20,
    R21 = 21,
    R22 = 22,
    R23 = 23,
    R24 = 24,
    R25 = 25,
    R26 = 26,
    R27 = 27,
    R28 = 28,
    R29 = 29,
    R30 = 30,
    R31 = 31,
    Sa0 = 32,
    Lc0 = 33,
    Sa1 = 34,
    Lc1 = 35,
    P3_0 = 36,
    M0 = 38,
    M1 = 39,
    Usr = 40,
    Pc = 41,
    Ugp = 42,
    Gp = 43,
    Cs0 = 44,
    Cs1 = 45,
    UpcycleLo = 46,
    UpcycleHi = 47,
    Framelimit = 48,
    Framekey = 49,
    Pktcntlo = 50,
    Pktcnthi = 51,
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
#[expect(non_upper_case_globals)]
impl Regs {
    pub const Sp: Regs = Regs::R29;
    pub const Fp: Regs = Regs::R30;
    pub const Lr: Regs = Regs::R31;
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

    fn read_function_argument_with_cc(
        &self,
        idx: u8,
        conv: CallingConvention,
    ) -> Result<GuestReg, QemuRWError> {
        QemuRWError::check_conv(QemuRWErrorKind::Read, CallingConvention::Hexagon, conv)?;

        // Note that 64 bit values may be passed in two registers (and may have padding), then this mapping is off.
        let reg_id = match idx {
            0 => Regs::R0,
            1 => Regs::R1,
            2 => Regs::R2,
            3 => Regs::R3,
            4 => Regs::R4,
            5 => Regs::R5,
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
        QemuRWError::check_conv(QemuRWErrorKind::Write, CallingConvention::Hexagon, conv)?;

        // Note that 64 bit values may be passed in two registers (and may have padding), then this mapping is off.
        let val: GuestReg = val.into();
        match idx {
            0 => self.write_reg(Regs::R0, val),
            1 => self.write_reg(Regs::R1, val),
            2 => self.write_reg(Regs::R2, val),
            3 => self.write_reg(Regs::R3, val),
            4 => self.write_reg(Regs::R4, val),
            5 => self.write_reg(Regs::R5, val),
            r => Err(QemuRWError::new_argument_error(QemuRWErrorKind::Write, r)),
        }
    }
}
