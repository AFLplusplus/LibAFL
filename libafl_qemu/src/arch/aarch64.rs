use std::sync::OnceLock;

use capstone::arch::BuildsCapstone;
use enum_map::{enum_map, EnumMap};
use num_enum::{IntoPrimitive, TryFromPrimitive};
#[cfg(feature = "python")]
use pyo3::prelude::*;
pub use strum_macros::EnumIter;
pub use syscall_numbers::aarch64::*;

use crate::{sync_exit::ExitArgs, CallingConvention};

#[derive(IntoPrimitive, TryFromPrimitive, Debug, Clone, Copy, EnumIter)]
#[repr(i32)]
pub enum Regs {
    X0 = 0,
    X1 = 1,
    X2 = 2,
    X3 = 3,
    X4 = 4,
    X5 = 5,
    X6 = 6,
    X7 = 7,
    X8 = 8,
    X9 = 9,
    X10 = 10,
    X11 = 11,
    X12 = 12,
    X13 = 13,
    X14 = 14,
    X15 = 15,
    X16 = 16,
    X17 = 17,
    X18 = 18,
    X19 = 19,
    X20 = 20,
    X21 = 21,
    X22 = 22,
    X23 = 23,
    X24 = 24,
    X25 = 25,
    X26 = 26,
    X27 = 27,
    X28 = 28,
    X29 = 29,
    X30 = 30,
    Sp = 31,
    Pc = 32,
    Pstate = 33,
}

static EXIT_ARCH_REGS: OnceLock<EnumMap<ExitArgs, Regs>> = OnceLock::new();

pub fn get_exit_arch_regs() -> &'static EnumMap<ExitArgs, Regs> {
    EXIT_ARCH_REGS.get_or_init(|| {
        enum_map! {
            ExitArgs::Ret  => Regs::X0,
            ExitArgs::Cmd  => Regs::X0,
            ExitArgs::Arg1 => Regs::X1,
            ExitArgs::Arg2 => Regs::X2,
            ExitArgs::Arg3 => Regs::X3,
            ExitArgs::Arg4 => Regs::X4,
            ExitArgs::Arg5 => Regs::X5,
            ExitArgs::Arg6 => Regs::X6,
        }
    })
}

/// alias registers
#[allow(non_upper_case_globals)]
impl Regs {
    pub const Fp: Regs = Regs::X29;
    pub const Lr: Regs = Regs::X30;
}

#[cfg(feature = "python")]
impl IntoPy<PyObject> for Regs {
    fn into_py(self, py: Python) -> PyObject {
        let n: i32 = self.into();
        n.into_py(py)
    }
}

/// Return an ARM64 ArchCapstoneBuilder
pub fn capstone() -> capstone::arch::arm64::ArchCapstoneBuilder {
    capstone::Capstone::new()
        .arm64()
        .mode(capstone::arch::arm64::ArchMode::Arm)
}

pub type GuestReg = u64;

impl crate::ArchExtras for crate::CPU {
    fn read_return_address<T>(&self) -> Result<T, String>
    where
        T: From<GuestReg>,
    {
        self.read_reg(Regs::Lr)
    }

    fn write_return_address<T>(&self, val: T) -> Result<(), String>
    where
        T: Into<GuestReg>,
    {
        self.write_reg(Regs::Lr, val)
    }

    fn read_function_argument<T>(&self, conv: CallingConvention, idx: u8) -> Result<T, String>
    where
        T: From<GuestReg>,
    {
        if conv != CallingConvention::Cdecl {
            return Err(format!("Unsupported calling convention: {conv:#?}"));
        }

        let reg_id = match idx {
            0 => Regs::X0,
            1 => Regs::X1,
            2 => Regs::X2,
            3 => Regs::X3,
            4 => Regs::X4,
            5 => Regs::X5,
            r => return Err(format!("Unsupported argument: {r:}")),
        };

        self.read_reg(reg_id)
    }

    fn write_function_argument<T>(
        &self,
        conv: CallingConvention,
        idx: i32,
        val: T,
    ) -> Result<(), String>
    where
        T: Into<GuestReg>,
    {
        if conv != CallingConvention::Cdecl {
            return Err(format!("Unsupported calling convention: {conv:#?}"));
        }

        let val: GuestReg = val.into();
        match idx {
            0 => self.write_reg(Regs::X0, val),
            1 => self.write_reg(Regs::X1, val),
            _ => Err(format!("Unsupported argument: {idx:}")),
        }
    }
}
