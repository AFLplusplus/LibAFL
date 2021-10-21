use num_enum::{IntoPrimitive, TryFromPrimitive};
use strum_macros::EnumIter;

#[cfg(feature = "python")]
use pyo3::prelude::*;

#[derive(IntoPrimitive, TryFromPrimitive, Debug, Clone, Copy, EnumIter)]
#[repr(i32)]
pub enum Aarch64Regs {
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
}

/// alias registers
#[allow(non_upper_case_globals)]
impl Aarch64Regs {
    pub const Fp: Aarch64Regs = Aarch64Regs::X29;
    pub const Lr: Aarch64Regs = Aarch64Regs::X30;
}

#[cfg(feature = "python")]
impl IntoPy<PyObject> for Aarch64Regs {
    fn into_py(self, py: Python) -> PyObject {
        let n: i32 = self.into();
        n.into_py(py)
    }
}
