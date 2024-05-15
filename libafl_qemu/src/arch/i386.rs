use std::{mem::size_of, sync::OnceLock};

use capstone::arch::BuildsCapstone;
use enum_map::{enum_map, EnumMap};
use num_enum::{IntoPrimitive, TryFromPrimitive};
#[cfg(feature = "python")]
use pyo3::prelude::*;
pub use strum_macros::EnumIter;
pub use syscall_numbers::x86::*;

use crate::{sync_exit::ExitArgs, CallingConvention, GuestAddr};

#[derive(IntoPrimitive, TryFromPrimitive, Debug, Clone, Copy, EnumIter)]
#[repr(i32)]
pub enum Regs {
    Eax = 0,
    Ecx = 1,
    Edx = 2,
    Ebx = 3,
    Esp = 4,
    Ebp = 5,
    Esi = 6,
    Edi = 7,
    Eip = 8,
    Eflags = 9,
}

static EXIT_ARCH_REGS: OnceLock<EnumMap<ExitArgs, Regs>> = OnceLock::new();

pub fn get_exit_arch_regs() -> &'static EnumMap<ExitArgs, Regs> {
    EXIT_ARCH_REGS.get_or_init(|| {
        enum_map! {
            ExitArgs::Ret  => Regs::Eax,
            ExitArgs::Cmd  => Regs::Eax,
            ExitArgs::Arg1 => Regs::Edi,
            ExitArgs::Arg2 => Regs::Esi,
            ExitArgs::Arg3 => Regs::Edx,
            ExitArgs::Arg4 => Regs::Ebx,
            ExitArgs::Arg5 => Regs::Ecx,
            ExitArgs::Arg6 => Regs::Ebp,
        }
    })
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

/// Return an X86 ArchCapstoneBuilder
pub fn capstone() -> capstone::arch::x86::ArchCapstoneBuilder {
    capstone::Capstone::new()
        .x86()
        .mode(capstone::arch::x86::ArchMode::Mode32)
}

pub type GuestReg = u32;

impl crate::ArchExtras for crate::CPU {
    fn read_return_address<T>(&self) -> Result<T, String>
    where
        T: From<GuestReg>,
    {
        let stack_ptr: GuestReg = self.read_reg(Regs::Esp)?;
        let mut ret_addr = [0; size_of::<GuestReg>()];
        unsafe { self.read_mem(stack_ptr, &mut ret_addr) };
        Ok(GuestReg::from_le_bytes(ret_addr).into())
    }

    fn write_return_address<T>(&self, val: T) -> Result<(), String>
    where
        T: Into<GuestReg>,
    {
        let stack_ptr: GuestReg = self.read_reg(Regs::Esp)?;
        let val: GuestReg = val.into();
        let ret_addr = val.to_le_bytes();
        unsafe { self.write_mem(stack_ptr, &ret_addr) };
        Ok(())
    }

    fn read_function_argument<T>(&self, conv: CallingConvention, idx: u8) -> Result<T, String>
    where
        T: From<GuestReg>,
    {
        if conv != CallingConvention::Cdecl {
            return Err(format!("Unsupported calling convention: {conv:#?}"));
        }

        match idx {
            0..=1 => {
                let stack_ptr: GuestAddr = self.read_reg(Regs::Sp)?;
                /*
                 * Stack is full and descending. SP points to return address, arguments
                 * are in reverse order above that.
                 */
                let size: GuestAddr = size_of::<GuestReg>() as GuestAddr;
                let offset = size * (idx as GuestAddr + 1);

                let mut val = [0u8; size_of::<GuestReg>()];
                unsafe {
                    self.read_mem(stack_ptr + offset, &mut val);
                }
                Ok(GuestReg::from_le_bytes(val).into())
            }
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

        match idx {
            0..=1 => {
                let val: GuestReg = val.into();
                let stack_ptr: GuestAddr = self.read_reg(Regs::Sp)?;
                /*
                 * Stack is full and descending. SP points to return address, arguments
                 * are in reverse order above that.
                 */
                let size: GuestAddr = size_of::<GuestReg>() as GuestAddr;
                let offset = size * (idx as GuestAddr + 1);

                let arg = val.to_le_bytes();
                unsafe {
                    self.write_mem(stack_ptr + offset, &arg);
                }
                Ok(())
            }
            _ => Err(format!("Unsupported argument: {idx:}")),
        }
    }
}
