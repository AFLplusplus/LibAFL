use std::{mem::size_of, sync::OnceLock};

use capstone::arch::BuildsCapstone;
use enum_map::{EnumMap, enum_map};
use num_enum::{IntoPrimitive, TryFromPrimitive};
pub use strum_macros::EnumIter;
pub use syscall_numbers::x86_64::*;

use crate::{CallingConvention, GuestAddr, QemuRWError, QemuRWErrorKind, sync_exit::ExitArgs};

#[expect(non_upper_case_globals)]
impl CallingConvention {
    pub const Default: CallingConvention = CallingConvention::SystemV;
}

#[derive(IntoPrimitive, TryFromPrimitive, Debug, Clone, Copy, EnumIter)]
#[repr(i32)]
pub enum Regs {
    Rax = 0,
    Rbx = 1,
    Rcx = 2,
    Rdx = 3,
    Rsi = 4,
    Rdi = 5,
    Rbp = 6,
    Rsp = 7,
    R8 = 8,
    R9 = 9,
    R10 = 10,
    R11 = 11,
    R12 = 12,
    R13 = 13,
    R14 = 14,
    R15 = 15,
    Rip = 16,
    Rflags = 17,
}

static EXIT_ARCH_REGS: OnceLock<EnumMap<ExitArgs, Regs>> = OnceLock::new();

pub fn get_exit_arch_regs() -> &'static EnumMap<ExitArgs, Regs> {
    EXIT_ARCH_REGS.get_or_init(|| {
        enum_map! {
            ExitArgs::Ret  => Regs::Rax,
            ExitArgs::Cmd  => Regs::Rax,
            ExitArgs::Arg1 => Regs::Rdi,
            ExitArgs::Arg2 => Regs::Rsi,
            ExitArgs::Arg3 => Regs::Rdx,
            ExitArgs::Arg4 => Regs::R10,
            ExitArgs::Arg5 => Regs::R8,
            ExitArgs::Arg6 => Regs::R9,
        }
    })
}

/// alias registers
#[expect(non_upper_case_globals)]
impl Regs {
    pub const Sp: Regs = Regs::Rsp;
    pub const Pc: Regs = Regs::Rip;
}

/// Return an X86 `ArchCapstoneBuilder`
#[must_use]
pub fn capstone() -> capstone::arch::x86::ArchCapstoneBuilder {
    capstone::Capstone::new()
        .x86()
        .mode(capstone::arch::x86::ArchMode::Mode64)
}

pub type GuestReg = u64;

impl crate::ArchExtras for crate::CPU {
    fn read_return_address(&self) -> Result<GuestReg, QemuRWError> {
        let stack_ptr: GuestReg = self.read_reg(Regs::Rsp)?;
        let mut ret_addr = [0; size_of::<GuestReg>()];
        unsafe { self.read_mem_unchecked(stack_ptr, &mut ret_addr) };
        Ok(GuestReg::from_le_bytes(ret_addr))
    }

    fn write_return_address<T>(&self, val: T) -> Result<(), QemuRWError>
    where
        T: Into<GuestReg>,
    {
        let stack_ptr: GuestReg = self.read_reg(Regs::Rsp)?;
        let val: GuestReg = val.into();
        let ret_addr = val.to_le_bytes();
        unsafe { self.write_mem_unchecked(stack_ptr, &ret_addr) };
        Ok(())
    }

    fn read_function_argument_with_cc(
        &self,
        idx: u8,
        conv: CallingConvention,
    ) -> Result<GuestReg, QemuRWError> {
        QemuRWError::check_conv(QemuRWErrorKind::Read, CallingConvention::SystemV, conv)?;

        match idx {
            0 => self.read_reg(Regs::Rdi),
            1 => self.read_reg(Regs::Rsi),
            2 => self.read_reg(Regs::Rdx),
            3 => self.read_reg(Regs::Rcx),
            4 => self.read_reg(Regs::R8),
            5 => self.read_reg(Regs::R9),
            _ => {
                const SIZE: usize = size_of::<GuestReg>();
                let stack_ptr: GuestAddr = self.read_reg(Regs::Sp)?;
                /*
                 * Stack is full and descending. SP points to return address, arguments
                 * are in reverse order above that. 6th argument is at SP + 8.
                 */

                let offset = (SIZE as GuestAddr) * (GuestAddr::from(idx) - 5);
                let mut buf = [0; SIZE];
                self.read_mem(stack_ptr + offset, &mut buf)?;

                Ok(GuestAddr::from_le_bytes(buf))
            }
        }
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
        QemuRWError::check_conv(QemuRWErrorKind::Write, CallingConvention::SystemV, conv)?;

        let val: GuestReg = val.into();
        match idx {
            0 => self.write_reg(Regs::Rdi, val),
            1 => self.write_reg(Regs::Rsi, val),
            2 => self.write_reg(Regs::Rdx, val),
            3 => self.write_reg(Regs::Rcx, val),
            4 => self.write_reg(Regs::R8, val),
            5 => self.write_reg(Regs::R9, val),
            _ => {
                let val: GuestReg = val.into();
                let stack_ptr: GuestAddr = self.read_reg(Regs::Rsp)?;
                /*
                 * Stack is full and descending. SP points to return address, arguments
                 * are in reverse order above that. 6th argument is at SP + 8.
                 */
                let size: GuestAddr = size_of::<GuestReg>() as GuestAddr;
                let offset = size * (GuestAddr::from(idx) - 5);
                let arg = val.to_le_bytes();
                self.write_mem(stack_ptr + offset, &arg)
            }
        }
    }
}
