use std::sync::OnceLock;

use enum_map::{enum_map, EnumMap};
use num_enum::{IntoPrimitive, TryFromPrimitive};
#[cfg(feature = "python")]
use pyo3::prelude::*;
pub use strum_macros::EnumIter;
pub use syscall_numbers::powerpc::*;

use crate::{sync_backdoor::BackdoorArgs, CallingConvention};

/// Registers for the MIPS instruction set.
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

    F0 = 32,
    F1 = 33,
    F2 = 34,
    F3 = 35,
    F4 = 36,
    F5 = 37,
    F6 = 38,
    F7 = 39,
    F8 = 40,
    F9 = 41,
    F10 = 42,
    F11 = 43,
    F12 = 44,
    F13 = 45,
    F14 = 46,
    F15 = 47,
    F16 = 48,
    F17 = 49,
    F18 = 50,
    F19 = 51,
    F20 = 52,
    F21 = 53,
    F22 = 54,
    F23 = 55,
    F24 = 56,
    F25 = 57,
    F26 = 58,
    F27 = 59,
    F28 = 60,
    F29 = 61,
    F30 = 62,
    F31 = 63,

    Nip = 64,
    Msr = 65,
    Cr = 66,
    Lr = 67,
    Ctr = 68,
    Xer = 69,
    Fpscr = 70,
}

static BACKDOOR_ARCH_REGS: OnceLock<EnumMap<BackdoorArgs, Regs>> = OnceLock::new();

pub fn get_backdoor_arch_regs() -> &'static EnumMap<BackdoorArgs, Regs> {
    BACKDOOR_ARCH_REGS.get_or_init(|| {
        enum_map! {
            BackdoorArgs::Ret  => Regs::R3,
            BackdoorArgs::Cmd  => Regs::R0,
            BackdoorArgs::Arg1 => Regs::R3,
            BackdoorArgs::Arg2 => Regs::R4,
            BackdoorArgs::Arg3 => Regs::R5,
            BackdoorArgs::Arg4 => Regs::R6,
            BackdoorArgs::Arg5 => Regs::R7,
            BackdoorArgs::Arg6 => Regs::R8,
        }
    })
}

/// alias registers
#[allow(non_upper_case_globals)]
impl Regs {
    pub const Pc: Regs = Regs::Nip;
    pub const Sp: Regs = Regs::R1;
}

#[cfg(feature = "python")]
impl IntoPy<PyObject> for Regs {
    fn into_py(self, py: Python) -> PyObject {
        let n: i32 = self.into();
        n.into_py(py)
    }
}

/// Return an MIPS ArchCapstoneBuilder
pub fn capstone() -> capstone::arch::ppc::ArchCapstoneBuilder {
    capstone::Capstone::new().ppc()
}

pub type GuestReg = u32;

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
            0 => Regs::R3,
            1 => Regs::R4,
            2 => Regs::R5,
            3 => Regs::R6,
            4 => Regs::R7,
            5 => Regs::R8,
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
            0 => self.write_reg(Regs::R3, val),
            1 => self.write_reg(Regs::R4, val),
            _ => Err(format!("Unsupported argument: {idx:}")),
        }
    }
}
