use std::{mem::size_of, ops::Range, sync::OnceLock};

use capstone::arch::BuildsCapstone;
use enum_map::{enum_map, EnumMap};
use num_enum::{IntoPrimitive, TryFromPrimitive};
pub use strum_macros::EnumIter;
pub use syscall_numbers::x86_64::*;

use crate::{sync_exit::ExitArgs, CallingConvention, QemuRWError, QemuRWErrorKind};

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
#[allow(non_upper_case_globals)]
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

pub const PROCESS_ADDRESS_RANGE: Range<u64> = 0..0x0000_7fff_ffff_ffff;

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

    fn read_function_argument(
        &self,
        conv: CallingConvention,
        idx: u8,
    ) -> Result<GuestReg, QemuRWError> {
        QemuRWError::check_conv(QemuRWErrorKind::Read, CallingConvention::Cdecl, conv)?;

        let reg_id = match idx {
            0 => Regs::Rdi,
            1 => Regs::Rsi,
            2 => Regs::Rdx,
            3 => Regs::Rcx,
            4 => Regs::R8,
            5 => Regs::R9,
            r => {
                return Err(QemuRWError::new_argument_error(
                    QemuRWErrorKind::Read,
                    i32::from(r),
                ))
            }
        };

        self.read_reg(reg_id)
    }

    fn write_function_argument<T>(
        &self,
        conv: CallingConvention,
        idx: i32,
        val: T,
    ) -> Result<(), QemuRWError>
    where
        T: Into<GuestReg>,
    {
        QemuRWError::check_conv(QemuRWErrorKind::Write, CallingConvention::Cdecl, conv)?;

        let val: GuestReg = val.into();
        match idx {
            0 => self.write_reg(Regs::Rdi, val),
            1 => self.write_reg(Regs::Rsi, val),
            r => Err(QemuRWError::new_argument_error(QemuRWErrorKind::Write, r)),
        }
    }
}
