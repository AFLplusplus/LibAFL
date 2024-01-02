use std::sync::OnceLock;

use enum_map::{enum_map, EnumMap};
use num_enum::{IntoPrimitive, TryFromPrimitive};
#[cfg(feature = "python")]
use pyo3::prelude::*;
pub use strum_macros::EnumIter;
pub use syscall_numbers::mips::*;

use crate::{sync_backdoor::SyncBackdoorArgs, CallingConvention};

/// Registers for the MIPS instruction set.
#[derive(IntoPrimitive, TryFromPrimitive, Debug, Clone, Copy, EnumIter)]
#[repr(i32)]
pub enum Regs {
    R0 = 0,
    At = 1,
    V0 = 2,
    V1 = 3,
    A0 = 4,
    A1 = 5,
    A2 = 6,
    A3 = 7,
    T0 = 8,
    T1 = 9,
    T2 = 10,
    T3 = 11,
    T4 = 12,
    T5 = 13,
    T6 = 14,
    T7 = 15,
    S0 = 16,
    S1 = 17,
    S2 = 18,
    S3 = 19,
    S4 = 20,
    S5 = 21,
    S6 = 22,
    S7 = 23,
    T8 = 24,
    T9 = 25,
    K0 = 26,
    K1 = 27,
    Gp = 28,
    Sp = 29,
    Fp = 30,
    Ra = 31,

    Pc = 37,
}

static SYNC_BACKDOOR_ARCH_REGS: OnceLock<EnumMap<SyncBackdoorArgs, Regs>> = OnceLock::new();

pub fn get_sync_backdoor_arch_regs() -> &'static EnumMap<SyncBackdoorArgs, Regs> {
    SYNC_BACKDOOR_ARCH_REGS.get_or_init(|| {
        enum_map! {
            SyncBackdoorArgs::Ret  => Regs::V0,
            SyncBackdoorArgs::Cmd  => Regs::V0,
            SyncBackdoorArgs::Arg1 => Regs::A0,
            SyncBackdoorArgs::Arg2 => Regs::A1,
            SyncBackdoorArgs::Arg3 => Regs::A2,
            SyncBackdoorArgs::Arg4 => Regs::A3,
            SyncBackdoorArgs::Arg5 => Regs::T0,
            SyncBackdoorArgs::Arg6 => Regs::T1,
        }
    })
}

/// alias registers
#[allow(non_upper_case_globals)]
impl Regs {
    pub const Zero: Regs = Regs::R0;
}

#[cfg(feature = "python")]
impl IntoPy<PyObject> for Regs {
    fn into_py(self, py: Python) -> PyObject {
        let n: i32 = self.into();
        n.into_py(py)
    }
}

/// Return an MIPS ArchCapstoneBuilder
pub fn capstone() -> capstone::arch::mips::ArchCapstoneBuilder {
    capstone::Capstone::new().mips()
}

pub type GuestReg = u32;

impl crate::ArchExtras for crate::CPU {
    fn read_return_address<T>(&self) -> Result<T, String>
    where
        T: From<GuestReg>,
    {
        self.read_reg(Regs::Ra)
    }

    fn write_return_address<T>(&self, val: T) -> Result<(), String>
    where
        T: Into<GuestReg>,
    {
        self.write_reg(Regs::Ra, val)
    }

    fn read_function_argument<T>(&self, conv: CallingConvention, idx: i32) -> Result<T, String>
    where
        T: From<GuestReg>,
    {
        if conv != CallingConvention::Cdecl {
            return Err(format!("Unsupported calling convention: {conv:#?}"));
        }

        match idx {
            0 => self.read_reg(Regs::A0),
            1 => self.read_reg(Regs::A1),
            _ => Err(format!("Unsupported argument: {idx:}")),
        }
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
            0 => self.write_reg(Regs::A0, val),
            1 => self.write_reg(Regs::A1, val),
            _ => Err(format!("Unsupported argument: {idx:}")),
        }
    }
}
