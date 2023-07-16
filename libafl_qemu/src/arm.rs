use capstone::arch::BuildsCapstone;
use num_enum::{IntoPrimitive, TryFromPrimitive};
#[cfg(feature = "python")]
use pyo3::prelude::*;
pub use strum_macros::EnumIter;
pub use syscall_numbers::arm::*;

use crate::CallingConvention;

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

#[cfg(feature = "python")]
impl IntoPy<PyObject> for Regs {
    fn into_py(self, py: Python) -> PyObject {
        let n: i32 = self.into();
        n.into_py(py)
    }
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
            0 => self.write_reg(Regs::R0, val),
            1 => self.write_reg(Regs::R1, val),
            _ => Err(format!("Unsupported argument: {idx:}")),
        }
    }
}
