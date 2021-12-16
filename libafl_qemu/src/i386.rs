use num_enum::{IntoPrimitive, TryFromPrimitive};
use strum_macros::EnumIter;

#[cfg(feature = "python")]
use pyo3::prelude::*;

pub use syscall_numbers::x86::*;

#[derive(IntoPrimitive, TryFromPrimitive, Debug, Clone, Copy, EnumIter)]
#[repr(i32)]
pub enum Regs {
    Eax = 0,
    Ebx = 1,
    Ecx = 2,
    Edx = 3,
    Esi = 4,
    Edi = 5,
    Ebp = 6,
    Esp = 7,
    Eip = 8,
    Eflags = 9,
}

/// alias registers
#[allow(non_upper_case_globals)]
impl Regs {
    pub const Sp: Regs = Regs::Esp;
    pub const Pc: Regs = Regs::Eip;
}

#[cfg(feature = "python")]
impl IntoPy<PyObject> for Regs {
    fn into_py(self, py: Python) -> PyObject {
        let n: i32 = self.into();
        n.into_py(py)
    }
}
