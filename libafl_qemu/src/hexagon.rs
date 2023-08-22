use num_enum::{IntoPrimitive, TryFromPrimitive};
#[cfg(feature = "python")]
use pyo3::prelude::*;
pub use strum_macros::EnumIter;

use crate::CallingConvention;

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

/// alias registers
#[allow(non_upper_case_globals)]
impl Regs {
    pub const Sp: Regs = Regs::R29;
    pub const Fp: Regs = Regs::R30;
    pub const Lr: Regs = Regs::R31;
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
        _val: T,
    ) -> Result<(), String>
    where
        T: Into<GuestReg>,
    {
        if conv != CallingConvention::Cdecl {
            return Err(format!("Unsupported calling convention: {conv:#?}"));
        }

        Err(format!("Unsupported argument: {idx:}"))
    }
}
