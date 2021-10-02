use num_enum::{IntoPrimitive, TryFromPrimitive};
use strum_macros::EnumIter;

#[cfg(feature = "python")]
use pyo3::prelude::*;

/// Registers for the ARM instruction set.
#[derive(IntoPrimitive, TryFromPrimitive, Debug, Clone, Copy, EnumIter)]
#[repr(i32)]
pub enum Aarch64Regs {
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
}

/// alias registers
impl Aarch64Regs {
    pub const SP: Aarch64Regs = Aarch64Regs::R13;
    pub const LR: Aarch64Regs = Aarch64Regs::R14;
    pub const PC: Aarch64Regs = Aarch64Regs::R15;
    pub const SB: Aarch64Regs = Aarch64Regs::R9;
    pub const SL: Aarch64Regs = Aarch64Regs::R10;
    pub const FP: Aarch64Regs = Aarch64Regs::R11;
    pub const IP: Aarch64Regs = Aarch64Regs::R12;
}

#[cfg(feature = "python")]
impl IntoPy<PyObject> for Aarch64Regs {
    fn into_py(self, py: Python) -> PyObject {
        let n: i32 = self.into();
        n.into_py(py)
    }
}
